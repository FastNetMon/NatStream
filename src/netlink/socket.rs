use std::io;
use std::os::unix::io::RawFd;

use anyhow::{Context, Result};
use log::{debug, warn};

// A module of nothing but protocol constants, named after the RFC field
// they encode. Listing them individually would be a maintenance burden
// with nothing to show for it.
#[allow(clippy::wildcard_imports)]
use super::constants::*;

pub struct NetlinkSocket {
    fd: RawFd,
}

/// One datagram read from the netlink socket.
// `len` and `datagram_len` are deliberately close: the pair is the point, and
// the doc comments say which is which.
#[allow(clippy::struct_field_names)]
pub struct Datagram {
    /// Bytes actually available in the caller's buffer.
    pub len: usize,
    /// The datagram's full length as reported by the kernel. Greater than
    /// `len` when the buffer was too small and the remainder was discarded.
    pub datagram_len: usize,
    /// Netlink port ID of the sender. Kernel-originated messages use 0.
    pub sender_portid: u32,
}

impl NetlinkSocket {
    pub fn open(recv_buf_size: usize) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("Failed to create netlink socket");
        }

        let sock = NetlinkSocket { fd };

        // Set receive buffer size — try SO_RCVBUFFORCE first (requires CAP_NET_ADMIN),
        // fall back to SO_RCVBUF
        let buf_size = buffer_size(recv_buf_size);
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                (&raw const buf_size).cast::<libc::c_void>(),
                socklen::<libc::c_int>(),
            )
        };
        if ret < 0 {
            debug!("SO_RCVBUFFORCE failed, falling back to SO_RCVBUF");
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&raw const buf_size).cast::<libc::c_void>(),
                    socklen::<libc::c_int>(),
                )
            };
            if ret < 0 {
                warn!("Failed to set SO_RCVBUF: {}", io::Error::last_os_error());
            }
        }

        // Bind the socket
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK_FAMILY;
        addr.nl_pid = 0; // let kernel assign
        addr.nl_groups = 0; // join groups via setsockopt instead

        let ret = unsafe {
            libc::bind(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                socklen::<libc::sockaddr_nl>(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error()).context("Failed to bind netlink socket");
        }

        // Join NFNLGRP_CONNTRACK_NEW
        sock.add_membership(NFNLGRP_CONNTRACK_NEW)
            .context("Failed to join NFNLGRP_CONNTRACK_NEW")?;

        // Join NFNLGRP_CONNTRACK_DESTROY
        sock.add_membership(NFNLGRP_CONNTRACK_DESTROY)
            .context("Failed to join NFNLGRP_CONNTRACK_DESTROY")?;

        // Set NETLINK_NO_ENOBUFS to silently drop under overload
        let one: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                NETLINK_NO_ENOBUFS,
                (&raw const one).cast::<libc::c_void>(),
                socklen::<libc::c_int>(),
            )
        };
        if ret < 0 {
            warn!(
                "Failed to set NETLINK_NO_ENOBUFS: {}",
                io::Error::last_os_error()
            );
        }

        debug!("Netlink socket opened (fd={fd})");
        Ok(sock)
    }

    fn add_membership(&self, group: libc::c_int) -> Result<()> {
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                NETLINK_ADD_MEMBERSHIP,
                (&raw const group).cast::<libc::c_void>(),
                socklen::<libc::c_int>(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error())
                .context(format!("NETLINK_ADD_MEMBERSHIP group {group}"));
        }
        Ok(())
    }

    /// Receive one netlink datagram into the provided buffer.
    pub fn recv(&self, buf: &mut [u8]) -> Result<Datagram, io::Error> {
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut addr_len = socklen::<libc::sockaddr_nl>();

        // MSG_TRUNC makes the return value the datagram's real length even when
        // it did not fit, so an oversized message can be reported rather than
        // silently losing its tail.
        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                libc::MSG_TRUNC,
                (&raw mut addr).cast::<libc::sockaddr>(),
                &raw mut addr_len,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let datagram_len = usize::try_from(n).expect("checked non-negative above");
        Ok(Datagram {
            len: datagram_len.min(buf.len()),
            datagram_len,
            sender_portid: addr.nl_pid,
        })
    }

    /// Get the cumulative number of drops on this socket via `SO_MEMINFO`.
    pub fn get_drops(&self) -> u64 {
        const SO_MEMINFO: libc::c_int = 55;
        const SK_MEMINFO_VARS: usize = 9;
        const SK_MEMINFO_DROPS: usize = 8;

        let mut meminfo = [0u32; SK_MEMINFO_VARS];
        let mut optlen = socklen::<[u32; SK_MEMINFO_VARS]>();
        let ret = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_SOCKET,
                SO_MEMINFO,
                meminfo.as_mut_ptr().cast::<libc::c_void>(),
                &raw mut optlen,
            )
        };
        if ret < 0 {
            return 0;
        }
        u64::from(meminfo[SK_MEMINFO_DROPS])
    }

    /// Poll this socket together with an auxiliary descriptor (the signalfd),
    /// with a timeout in milliseconds; a negative timeout blocks.
    /// Returns readiness for `(netlink, aux)`.
    pub fn poll_with(&self, aux_fd: RawFd, timeout_ms: i32) -> Result<(bool, bool), io::Error> {
        let mut fds = [
            libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: aux_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            (fds[0].revents & libc::POLLIN) != 0,
            (fds[1].revents & libc::POLLIN) != 0,
        ))
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
        debug!("Netlink socket closed (fd={})", self.fd);
    }
}
