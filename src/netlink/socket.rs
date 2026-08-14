use std::io;
use std::os::unix::io::RawFd;

use anyhow::{Context, Result};
use log::{debug, warn};

use super::constants::*;

pub struct NetlinkSocket {
    fd: RawFd,
}

/// One datagram read from the netlink socket.
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
        let buf_size = recv_buf_size as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            debug!("SO_RCVBUFFORCE failed, falling back to SO_RCVBUF");
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &buf_size as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                warn!("Failed to set SO_RCVBUF: {}", io::Error::last_os_error());
            }
        }

        // Bind the socket
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0; // let kernel assign
        addr.nl_groups = 0; // join groups via setsockopt instead

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
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
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            warn!(
                "Failed to set NETLINK_NO_ENOBUFS: {}",
                io::Error::last_os_error()
            );
        }

        debug!("Netlink socket opened (fd={})", fd);
        Ok(sock)
    }

    fn add_membership(&self, group: libc::c_int) -> Result<()> {
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                NETLINK_ADD_MEMBERSHIP,
                &group as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error())
                .context(format!("NETLINK_ADD_MEMBERSHIP group {}", group));
        }
        Ok(())
    }

    /// Receive one netlink datagram into the provided buffer.
    pub fn recv(&self, buf: &mut [u8]) -> Result<Datagram, io::Error> {
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;

        // MSG_TRUNC makes the return value the datagram's real length even when
        // it did not fit, so an oversized message can be reported rather than
        // silently losing its tail.
        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_TRUNC,
                &mut addr as *mut libc::sockaddr_nl as *mut libc::sockaddr,
                &mut addr_len,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let datagram_len = n as usize;
        Ok(Datagram {
            len: datagram_len.min(buf.len()),
            datagram_len,
            sender_portid: addr.nl_pid,
        })
    }

    /// Get the cumulative number of drops on this socket via SO_MEMINFO.
    pub fn get_drops(&self) -> u64 {
        const SO_MEMINFO: libc::c_int = 55;
        const SK_MEMINFO_VARS: usize = 9;
        const SK_MEMINFO_DROPS: usize = 8;

        let mut meminfo = [0u32; SK_MEMINFO_VARS];
        let mut optlen = std::mem::size_of_val(&meminfo) as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_SOCKET,
                SO_MEMINFO,
                meminfo.as_mut_ptr() as *mut libc::c_void,
                &mut optlen,
            )
        };
        if ret < 0 {
            return 0;
        }
        meminfo[SK_MEMINFO_DROPS] as u64
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
