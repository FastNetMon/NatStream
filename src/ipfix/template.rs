use super::constants::*;

/// Field specification for a template record.
pub struct FieldSpec {
    pub ie_id: u16,
    pub length: u16,
}

/// The NAT event template fields in order.
pub const NAT_TEMPLATE_FIELDS: &[FieldSpec] = &[
    FieldSpec { ie_id: IE_NAT_EVENT, length: 1 },
    FieldSpec { ie_id: IE_PROTOCOL_IDENTIFIER, length: 1 },
    FieldSpec { ie_id: IE_SOURCE_IPV4_ADDRESS, length: 4 },
    FieldSpec { ie_id: IE_DESTINATION_IPV4_ADDRESS, length: 4 },
    FieldSpec { ie_id: IE_SOURCE_TRANSPORT_PORT, length: 2 },
    FieldSpec { ie_id: IE_DESTINATION_TRANSPORT_PORT, length: 2 },
    FieldSpec { ie_id: IE_POST_NAT_SOURCE_IPV4_ADDRESS, length: 4 },
    FieldSpec { ie_id: IE_POST_NAPT_SOURCE_TRANSPORT_PORT, length: 2 },
    FieldSpec { ie_id: IE_OCTET_DELTA_COUNT, length: 8 },
    FieldSpec { ie_id: IE_PACKET_DELTA_COUNT, length: 8 },
    FieldSpec { ie_id: IE_POST_OCTET_DELTA_COUNT, length: 8 },
    FieldSpec { ie_id: IE_POST_PACKET_DELTA_COUNT, length: 8 },
];

/// Calculate the size of a template set (set header + template record header + field specs).
/// Set header: 4 bytes (set_id=2, length)
/// Template record header: 4 bytes (template_id, field_count)
/// Each field specifier: 4 bytes (ie_id, length)
pub const fn template_set_size() -> usize {
    SET_HEADER_LEN + 4 + NAT_TEMPLATE_FIELDS.len() * 4
}
