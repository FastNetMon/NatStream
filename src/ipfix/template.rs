use super::constants::*;

/// Field specification for a template record.
pub struct FieldSpec {
    pub ie_id: u16,
    pub length: u16,
    /// Private Enterprise Number, for enterprise-specific Information Elements.
    /// Present fields are encoded with the enterprise bit set and carry four
    /// extra bytes in the template (RFC 7011 section 3.2).
    pub enterprise: Option<u32>,
}

/// An IANA-registered Information Element.
const fn ie(ie_id: u16, length: u16) -> FieldSpec {
    FieldSpec {
        ie_id,
        length,
        enterprise: None,
    }
}

/// The reply-direction counterpart of an IE, per RFC 5103.
const fn reverse_ie(ie_id: u16, length: u16) -> FieldSpec {
    FieldSpec {
        ie_id,
        length,
        enterprise: Some(REVERSE_INFORMATION_ELEMENT_PEN),
    }
}

/// The NAT event template fields in order.
pub const NAT_TEMPLATE_FIELDS: &[FieldSpec] = &[
    ie(IE_NAT_EVENT, 1),
    ie(IE_PROTOCOL_IDENTIFIER, 1),
    ie(IE_SOURCE_IPV4_ADDRESS, 4),
    ie(IE_DESTINATION_IPV4_ADDRESS, 4),
    ie(IE_SOURCE_TRANSPORT_PORT, 2),
    ie(IE_DESTINATION_TRANSPORT_PORT, 2),
    ie(IE_POST_NAT_SOURCE_IPV4_ADDRESS, 4),
    ie(IE_POST_NAPT_SOURCE_TRANSPORT_PORT, 2),
    ie(IE_POST_NAT_DESTINATION_IPV4_ADDRESS, 4),
    ie(IE_POST_NAPT_DESTINATION_TRANSPORT_PORT, 2),
    ie(IE_OCTET_DELTA_COUNT, 8),
    ie(IE_PACKET_DELTA_COUNT, 8),
    reverse_ie(IE_OCTET_DELTA_COUNT, 8),
    reverse_ie(IE_PACKET_DELTA_COUNT, 8),
];

/// Size of one field specifier: four bytes, plus the enterprise number when the
/// Information Element is enterprise-specific.
const fn field_specifier_size(field: &FieldSpec) -> usize {
    match field.enterprise {
        Some(_) => FIELD_SPECIFIER_LEN + ENTERPRISE_NUMBER_LEN,
        None => FIELD_SPECIFIER_LEN,
    }
}

/// Calculate the size of a template set (set header + template record header + field specs).
/// Set header: 4 bytes (set_id=2, length)
/// Template record header: 4 bytes (template_id, field_count)
pub const fn template_set_size() -> usize {
    let mut size = SET_HEADER_LEN + 4;
    let mut i = 0;
    while i < NAT_TEMPLATE_FIELDS.len() {
        size += field_specifier_size(&NAT_TEMPLATE_FIELDS[i]);
        i += 1;
    }
    size
}

/// Total size of one data record, derived from the template itself.
pub const fn record_size() -> usize {
    let mut size = 0;
    let mut i = 0;
    while i < NAT_TEMPLATE_FIELDS.len() {
        size += NAT_TEMPLATE_FIELDS[i].length as usize;
        i += 1;
    }
    size
}

// The encoder writes records field by field, so keep the advertised template and
// the bytes actually produced from drifting apart.
const _: () = assert!(
    record_size() == DATA_RECORD_SIZE,
    "DATA_RECORD_SIZE does not match the sum of the template field lengths"
);
const _: () = assert!(
    NAT_TEMPLATE_FIELDS.len() == TEMPLATE_FIELD_COUNT as usize,
    "TEMPLATE_FIELD_COUNT does not match the number of template fields"
);
