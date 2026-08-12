//! Protocol constants and Information Element identifiers.

// ---- IPFIX (RFC 7011) ----

pub const IPFIX_VERSION: u16 = 10;
pub const IPFIX_HEADER_LEN: usize = 16;

/// Template set ID (RFC 7011 section 3.3.2)
pub const IPFIX_TEMPLATE_SET_ID: u16 = 2;

// ---- NetFlow v9 (RFC 3954) ----

pub const NETFLOW9_VERSION: u16 = 9;
pub const NETFLOW9_HEADER_LEN: usize = 20;

/// Template FlowSet ID (RFC 3954 section 5.2)
pub const NETFLOW9_TEMPLATE_FLOWSET_ID: u16 = 0;

/// "The Exporter SHOULD insert some padding bytes so that the subsequent
/// FlowSet starts at a 4-byte aligned boundary… the Length field includes the
/// padding bytes." (RFC 3954 section 5.3)
pub const NETFLOW9_ALIGNMENT: usize = 4;

/// The two field types where NetFlow v9 diverges from the IPFIX registry.
///
/// v9 has no enterprise mechanism, so RFC 5103 reverse elements cannot be
/// expressed; it has dedicated types for a flow's reverse direction instead.
pub const V9_OUT_BYTES: u16 = 23;
pub const V9_OUT_PKTS: u16 = 24;

// ---- Shared between protocols ----

/// Set / FlowSet header size (set ID + length)
pub const SET_HEADER_LEN: usize = 4;

/// Field specifier size in a template record (RFC 7011 section 3.2)
pub const FIELD_SPECIFIER_LEN: usize = 4;

/// Private Enterprise Number field width in a template field specifier
pub const ENTERPRISE_NUMBER_LEN: usize = 4;

/// Enterprise bit in a field specifier's Information Element ID
pub const ENTERPRISE_BIT: u16 = 0x8000;

/// Max message size (MTU-safe for UDP)
pub const MAX_MSG_SIZE: usize = 1472;

/// Template IDs below this are reserved for set/FlowSet identifiers
pub const MIN_TEMPLATE_ID: u16 = 256;

pub const DEFAULT_TEMPLATE_ID: u16 = 256;

/// Template retransmit interval (seconds)
pub const DEFAULT_TEMPLATE_INTERVAL_SECS: u64 = 30;

/// Reverse Information Elements (RFC 5103): the forward-direction IE carried
/// with the enterprise bit set and the IANA reverse-PEN, which is how a
/// bidirectional flow reports its reply direction under IPFIX. Note this is
/// *not* the same as postOctetDeltaCount/postPacketDeltaCount (IEs 23/24),
/// which report the forward direction as modified by a middlebox.
pub const REVERSE_INFORMATION_ELEMENT_PEN: u32 = 29305;

// ---- IANA IPFIX Information Element IDs ----

pub const IE_OCTET_DELTA_COUNT: u16 = 1; // 8 bytes
pub const IE_PACKET_DELTA_COUNT: u16 = 2; // 8 bytes
pub const IE_PROTOCOL_IDENTIFIER: u16 = 4; // 1 byte
pub const IE_SOURCE_TRANSPORT_PORT: u16 = 7; // 2 bytes
pub const IE_SOURCE_IPV4_ADDRESS: u16 = 8; // 4 bytes
pub const IE_DESTINATION_TRANSPORT_PORT: u16 = 11; // 2 bytes
pub const IE_DESTINATION_IPV4_ADDRESS: u16 = 12; // 4 bytes
pub const IE_POST_NAT_SOURCE_IPV4_ADDRESS: u16 = 225; // 4 bytes
pub const IE_POST_NAT_DESTINATION_IPV4_ADDRESS: u16 = 226; // 4 bytes
pub const IE_POST_NAPT_SOURCE_TRANSPORT_PORT: u16 = 227; // 2 bytes
pub const IE_POST_NAPT_DESTINATION_TRANSPORT_PORT: u16 = 228; // 2 bytes
pub const IE_NAT_EVENT: u16 = 230; // 1 byte

// ---- NAT event types (RFC 8158) ----

pub const NAT44_SESSION_CREATE: u8 = 4;
pub const NAT44_SESSION_DELETE: u8 = 5;
