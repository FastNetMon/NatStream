// Netlink protocol family
pub const NETLINK_NETFILTER: libc::c_int = 12;

// Netlink socket options
pub const NETLINK_ADD_MEMBERSHIP: libc::c_int = 1;
pub const NETLINK_NO_ENOBUFS: libc::c_int = 5;

// Netfilter netlink multicast groups
pub const NFNLGRP_CONNTRACK_NEW: libc::c_int = 1;
pub const NFNLGRP_CONNTRACK_DESTROY: libc::c_int = 3;

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
pub const IPS_SRC_NAT: u32 = 1 << 4;  // 0x10
pub const IPS_DST_NAT: u32 = 1 << 5;  // 0x20
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
