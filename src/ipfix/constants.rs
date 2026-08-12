// IPFIX protocol version (RFC 7011)
pub const IPFIX_VERSION: u16 = 10;

// IPFIX message header size
pub const IPFIX_HEADER_LEN: usize = 16;

// Set header size (set ID + length)
pub const SET_HEADER_LEN: usize = 4;

// Template set ID (RFC 7011 section 3.3.2)
pub const TEMPLATE_SET_ID: u16 = 2;

// Our template ID (must be >= 256)
pub const NAT_TEMPLATE_ID: u16 = 256;

// Template retransmit interval (seconds)
pub const TEMPLATE_RETRANSMIT_INTERVAL: u64 = 30;

// Max IPFIX message size (MTU-safe for UDP)
pub const MAX_IPFIX_MSG_SIZE: usize = 1472;

// IANA Information Element IDs
pub const IE_OCTET_DELTA_COUNT: u16 = 1;        // 8 bytes
pub const IE_PACKET_DELTA_COUNT: u16 = 2;        // 8 bytes
pub const IE_PROTOCOL_IDENTIFIER: u16 = 4;       // 1 byte
pub const IE_SOURCE_TRANSPORT_PORT: u16 = 7;      // 2 bytes
pub const IE_SOURCE_IPV4_ADDRESS: u16 = 8;        // 4 bytes
pub const IE_DESTINATION_TRANSPORT_PORT: u16 = 11; // 2 bytes
pub const IE_DESTINATION_IPV4_ADDRESS: u16 = 12;   // 4 bytes
pub const IE_POST_NAT_SOURCE_IPV4_ADDRESS: u16 = 225; // 4 bytes
pub const IE_POST_NAPT_SOURCE_TRANSPORT_PORT: u16 = 227; // 2 bytes
pub const IE_NAT_EVENT: u16 = 230;                // 1 byte

// Reverse Information Elements (RFC 5103): the forward-direction IE carried
// with the enterprise bit set and the IANA reverse-PEN, which is how a
// bidirectional flow reports its reply direction. Note this is *not* the same
// as postOctetDeltaCount/postPacketDeltaCount (IEs 23/24), which report the
// forward direction as modified by a middlebox.
pub const REVERSE_INFORMATION_ELEMENT_PEN: u32 = 29305;

// Enterprise bit in a field specifier's Information Element ID (RFC 7011 3.2)
pub const ENTERPRISE_BIT: u16 = 0x8000;

// Private Enterprise Number field width in a template field specifier
pub const ENTERPRISE_NUMBER_LEN: usize = 4;

// Field specifier size in a template record (RFC 7011 3.2)
pub const FIELD_SPECIFIER_LEN: usize = 4;

// Data record size (sum of all field sizes)
// natEvent(1) + protocol(1) + srcIP(4) + dstIP(4) + srcPort(2) + dstPort(2)
// + postNatSrcIP(4) + postNaptSrcPort(2) + octetDelta(8) + packetDelta(8)
// + reverseOctetDelta(8) + reversePacketDelta(8) = 52 bytes
pub const DATA_RECORD_SIZE: usize = 52;

// Number of fields in our template
pub const TEMPLATE_FIELD_COUNT: u16 = 12;

// NAT event types (RFC 8158)
pub const NAT44_SESSION_CREATE: u8 = 4;
pub const NAT44_SESSION_DELETE: u8 = 5;
