// Netlink protocol family
pub const NETLINK_NETFILTER: libc::c_int = 12;

// AF_NETLINK at the width sockaddr_nl.nl_family carries. Taken from libc rather
// than written out, so it stays tied to the platform's own definition.
#[allow(clippy::cast_possible_truncation)] // AF_NETLINK is 16
pub const AF_NETLINK_FAMILY: u16 = libc::AF_NETLINK as u16;

// The nfgenmsg family byte. These are the NFPROTO_* values, which coincide with
// the AF_* ones, and the header carries them in a single byte.
#[allow(clippy::cast_possible_truncation)] // AF_INET is 2
pub const NFPROTO_IPV4: u8 = libc::AF_INET as u8;
#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // AF_INET6 is 10
pub const NFPROTO_IPV6: u8 = libc::AF_INET6 as u8;

// Netlink socket options
pub const NETLINK_ADD_MEMBERSHIP: libc::c_int = 1;
pub const NETLINK_NO_ENOBUFS: libc::c_int = 5;

// Netfilter netlink multicast groups
pub const NFNLGRP_CONNTRACK_NEW: libc::c_int = 1;
pub const NFNLGRP_CONNTRACK_DESTROY: libc::c_int = 3;

// nfnetlink subsystem ID, carried in the high byte of nlmsg_type
pub const NFNL_SUBSYS_CTNETLINK: u16 = 1;

// Netlink control message types occupy everything below NLMSG_MIN_TYPE
pub const NLMSG_MIN_TYPE: u16 = 0x10;

// Conntrack event types (from nlmsg_type & 0xFF)
pub const IPCTNL_MSG_CT_NEW: u8 = 0;
pub const IPCTNL_MSG_CT_DELETE: u8 = 2;

// Conntrack attribute types (top-level)
pub const CTA_TUPLE_ORIG: u16 = 1;
pub const CTA_TUPLE_REPLY: u16 = 2;
pub const CTA_STATUS: u16 = 3;
pub const CTA_COUNTERS_ORIG: u16 = 9;
pub const CTA_COUNTERS_REPLY: u16 = 10;

// Conntrack tuple attribute types
pub const CTA_TUPLE_IP: u16 = 1;
pub const CTA_TUPLE_PROTO: u16 = 2;

// Conntrack IP attribute types
pub const CTA_IP_V4_SRC: u16 = 1;
pub const CTA_IP_V4_DST: u16 = 2;

// Conntrack proto attribute types
pub const CTA_PROTO_NUM: u16 = 1;
pub const CTA_PROTO_SRC_PORT: u16 = 2;
pub const CTA_PROTO_DST_PORT: u16 = 3;

// Conntrack counter attribute types
pub const CTA_COUNTERS_PACKETS: u16 = 1;
pub const CTA_COUNTERS_BYTES: u16 = 2;

// Conntrack status flags
pub const IPS_SRC_NAT: u32 = 1 << 4; // 0x10
pub const IPS_DST_NAT: u32 = 1 << 5; // 0x20
pub const IPS_NAT_MASK: u32 = IPS_SRC_NAT | IPS_DST_NAT;

// NLA alignment
pub const NLA_ALIGNTO: usize = 4;

// NLA type mask (strip nested/byte-order flags)
pub const NLA_TYPE_MASK: u16 = 0x3FFF;

// Netlink message header size
pub const NLMSG_HDRLEN: usize = 16;

// nfgenmsg size (1 byte family + 1 byte version + 2 bytes res_id)
pub const NFGENMSG_LEN: usize = 4;

// NLA header size (2 bytes len + 2 bytes type)
pub const NLA_HDRLEN: usize = 4;

// Default recv buffer size
pub const DEFAULT_RECV_BUF_SIZE: usize = 4 * 1024 * 1024; // 4 MB
pub const DEFAULT_SEND_BUF_SIZE: usize = 4 * 1024 * 1024; // 4 MB

/// How many datagrams one `recvmmsg` asks the kernel for.
///
/// The kernel packs several conntrack messages into each datagram, and this
/// collects several datagrams per syscall on top of that. Sixteen is enough to
/// amortise the call without holding a large idle buffer: the slots are only as
/// full as the traffic makes them.
pub const RECV_BATCH_SIZE: usize = 16;

/// The buffer behind each slot of a batch, and so the largest netlink datagram
/// that can be taken whole. Anything longer is reported as truncated.
pub const RECV_SLOT_SIZE: usize = 64 * 1024;

/// The size of an FFI option value, at the width the sockets API asks for.
///
/// Every use is `size_of` of a small fixed struct, so the value is a
/// compile-time constant of a few bytes and the conversion cannot lose
/// anything.
#[allow(clippy::cast_possible_truncation)]
pub const fn socklen<T>() -> libc::socklen_t {
    size_of::<T>() as libc::socklen_t
}

/// A socket buffer size at the width `setsockopt` takes it.
///
/// The sizes come from the command line as a `usize`, so one larger than an
/// `int` can hold has to become the largest one that fits rather than wrapping
/// to a negative number. Linux happens to reinterpret the value as a `u32` and
/// clamp it, which makes a wrapped size behave the same by luck; this does not
/// rely on that.
pub fn buffer_size(size: usize) -> libc::c_int {
    libc::c_int::try_from(size).unwrap_or(libc::c_int::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_buffer_size_too_large_for_an_int_becomes_the_largest_one_that_fits() {
        assert_eq!(buffer_size(usize::MAX), libc::c_int::MAX);
        assert!(buffer_size(usize::MAX) > 0, "must not wrap negative");
        assert_eq!(buffer_size(libc::c_int::MAX as usize + 1), libc::c_int::MAX);
    }

    #[test]
    fn an_ordinary_buffer_size_is_passed_through() {
        assert_eq!(buffer_size(DEFAULT_RECV_BUF_SIZE), 4 * 1024 * 1024);
        assert_eq!(buffer_size(0), 0);
        assert_eq!(buffer_size(libc::c_int::MAX as usize), libc::c_int::MAX);
    }
}
