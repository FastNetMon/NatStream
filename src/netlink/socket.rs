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

/// Buffers and headers for one batched receive.
///
/// `recvmmsg` wants an array of `mmsghdr`, each pointing at its own buffer and
/// its own address slot. That wiring is done once here and reused for every
/// receive, so the hot path only resets the few fields the kernel writes back.
pub struct ReceiveBatch {
    /// One receive buffer per slot, laid out end to end.
    storage: Vec<u8>,
    slot_len: usize,
    /// Where the kernel writes each datagram's sender.
    addresses: Vec<libc::sockaddr_nl>,
    /// One per slot, each pointing into `storage`.
    iovecs: Vec<libc::iovec>,
    headers: Vec<libc::mmsghdr>,
    /// Slots the last receive filled.
    filled: usize,
}

impl ReceiveBatch {
    /// A batch of `slots` datagrams, each up to `slot_len` bytes.
    ///
    /// # Panics
    ///
    /// If either dimension is zero, which would make the batch useless.
    #[must_use]
    pub fn new(slots: usize, slot_len: usize) -> Self {
        assert!(slots > 0, "a batch needs at least one slot");
        assert!(slot_len > 0, "a slot needs room for a datagram");

        let mut batch = ReceiveBatch {
            storage: vec![0u8; slots * slot_len],
            slot_len,
            addresses: vec![unsafe { std::mem::zeroed() }; slots],
            iovecs: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                };
                slots
            ],
            headers: vec![unsafe { std::mem::zeroed() }; slots],
            filled: 0,
        };
        batch.wire_up();
        batch
    }

    /// Slots in the batch, which is the most one receive can return.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.headers.len()
    }

    fn capacity_as_c_uint(&self) -> libc::c_uint {
        libc::c_uint::try_from(self.capacity()).expect("a batch is a handful of slots")
    }

    /// Point every header at its own buffer and address.
    ///
    /// The vectors are allocated once in `new` and never resized, so the
    /// pointers taken here stay valid for the life of the batch. Nothing but
    /// this type can reach them, and it hands out only slices.
    fn wire_up(&mut self) {
        let storage = self.storage.as_mut_ptr();
        let addresses = self.addresses.as_mut_ptr();
        let iovecs = self.iovecs.as_mut_ptr();
        let slot_len = self.slot_len;

        for index in 0..self.headers.len() {
            // SAFETY: `index` is below the length of every vector, and each
            // slot's buffer is `slot_len` bytes at `index * slot_len`.
            unsafe {
                *iovecs.add(index) = libc::iovec {
                    iov_base: storage.add(index * slot_len).cast::<libc::c_void>(),
                    iov_len: slot_len,
                };

                let header = &mut *self.headers.as_mut_ptr().add(index);
                header.msg_hdr.msg_name = addresses.add(index).cast::<libc::c_void>();
                header.msg_hdr.msg_namelen = socklen::<libc::sockaddr_nl>();
                header.msg_hdr.msg_iov = iovecs.add(index);
                header.msg_hdr.msg_iovlen = 1;
                header.msg_hdr.msg_control = std::ptr::null_mut();
                header.msg_hdr.msg_controllen = 0;
                header.msg_hdr.msg_flags = 0;
                header.msg_len = 0;
            }
        }
    }

    /// Restore the fields the kernel writes back, before reusing the batch.
    fn reset(&mut self) {
        self.filled = 0;
        for header in &mut self.headers {
            header.msg_hdr.msg_namelen = socklen::<libc::sockaddr_nl>();
            header.msg_hdr.msg_flags = 0;
            header.msg_len = 0;
        }
    }

    /// The datagram in slot `index`, and the bytes it holds.
    ///
    /// # Panics
    ///
    /// If `index` is beyond what the last receive filled.
    #[must_use]
    pub fn datagram(&self, index: usize) -> (Datagram, &[u8]) {
        assert!(index < self.filled, "slot {index} was not filled");

        // With MSG_TRUNC this is the datagram's real length, which can exceed
        // the slot it was read into.
        let datagram_len = self.headers[index].msg_len as usize;
        let len = datagram_len.min(self.slot_len);
        let start = index * self.slot_len;

        (
            Datagram {
                len,
                datagram_len,
                sender_portid: self.addresses[index].nl_pid,
            },
            &self.storage[start..start + len],
        )
    }
}

impl NetlinkSocket {
    /// Open the conntrack event socket and subscribe to NAT session events.
    ///
    /// # Errors
    ///
    /// If the socket cannot be created or bound, or if joining either
    /// conntrack multicast group fails — which is what happens without
    /// `CAP_NET_ADMIN`.
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

    /// Receive as many datagrams as are queued, up to the size of `batch`.
    ///
    /// One `recvmmsg` in place of a `recvfrom` per datagram. The kernel already
    /// packs several conntrack messages into each datagram; this collects
    /// several datagrams per syscall on top of that, which is what the ingest
    /// path spends most of its time on under load.
    ///
    /// Returns how many slots were filled. The socket is non-blocking here, so
    /// an empty socket reports `WouldBlock` rather than waiting — the caller
    /// drains until that happens and then goes back to `poll`.
    ///
    /// # Errors
    ///
    /// If `recvmmsg` fails. `EAGAIN` (as `WouldBlock`) means the socket is
    /// drained, and `EINTR` is reported rather than retried so the caller can
    /// check for a pending shutdown.
    ///
    /// # Panics
    ///
    /// Never: the count is checked to be non-negative before it is converted.
    pub fn recv_batch(&self, batch: &mut ReceiveBatch) -> Result<usize, io::Error> {
        batch.reset();

        let received = unsafe {
            libc::recvmmsg(
                self.fd,
                batch.headers.as_mut_ptr(),
                batch.capacity_as_c_uint(),
                // MSG_TRUNC reports each datagram's real length even when it
                // did not fit, so an oversized one is counted rather than
                // silently losing its tail.
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                std::ptr::null_mut(),
            )
        };
        if received < 0 {
            batch.filled = 0;
            return Err(io::Error::last_os_error());
        }

        batch.filled = usize::try_from(received).expect("checked non-negative above");
        Ok(batch.filled)
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
    /// # Errors
    ///
    /// If `poll` fails, including with `EINTR`.
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
