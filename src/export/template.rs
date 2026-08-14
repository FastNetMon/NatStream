//! The exported field set: what a record carries, and how it is described to a
//! collector.
//!
//! A profile is a compile-time table of [`FieldShape`]s. Resolving one against a
//! counter width produces the [`Template`] the encoder works from, so the
//! advertised template and the bytes actually written come from a single source.

use anyhow::{Result, bail};

use super::elements::*;

/// Which value of a conntrack event a field carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSource {
    NatEvent,
    Protocol,
    SrcIp,
    DstIp,
    SrcPort,
    DstPort,
    PostNatSrcIp,
    PostNatSrcPort,
    PostNatDstIp,
    PostNatDstPort,
    OrigBytes,
    OrigPackets,
    ReplyBytes,
    ReplyPackets,
}

impl FieldSource {
    /// The width a non-counter source is always written at. Counters are
    /// configurable and return `None`.
    pub const fn natural_len(self) -> Option<u16> {
        match self {
            FieldSource::NatEvent | FieldSource::Protocol => Some(1),
            FieldSource::SrcPort
            | FieldSource::DstPort
            | FieldSource::PostNatSrcPort
            | FieldSource::PostNatDstPort => Some(2),
            FieldSource::SrcIp
            | FieldSource::DstIp
            | FieldSource::PostNatSrcIp
            | FieldSource::PostNatDstIp => Some(4),
            FieldSource::OrigBytes
            | FieldSource::OrigPackets
            | FieldSource::ReplyBytes
            | FieldSource::ReplyPackets => None,
        }
    }
}

/// An Information Element identifier, with its Private Enterprise Number when
/// the element is enterprise-specific.
#[derive(Debug, Clone, Copy)]
pub struct Element {
    pub id: u16,
    pub pen: Option<u32>,
}

const fn ie(id: u16) -> Element {
    Element { id, pen: None }
}

/// The reply-direction counterpart of an IE, per RFC 5103.
const fn reverse_ie(id: u16) -> Element {
    Element {
        id,
        pen: Some(REVERSE_INFORMATION_ELEMENT_PEN),
    }
}

/// How wide a field is on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    /// Fixed by the element's type.
    Fixed(u16),
    /// A byte or packet counter, sized by [`CounterWidth`].
    Counter,
}

/// One entry of a profile table.
pub struct FieldShape {
    pub source: FieldSource,
    pub ipfix: Element,
    pub width: Width,
}

const fn field(source: FieldSource, ipfix: Element, width: Width) -> FieldShape {
    FieldShape {
        source,
        ipfix,
        width,
    }
}

/// Everything: both NAT directions and both counter directions.
pub const PROFILE_FULL: &[FieldShape] = &[
    field(FieldSource::NatEvent, ie(IE_NAT_EVENT), Width::Fixed(1)),
    field(FieldSource::Protocol, ie(IE_PROTOCOL_IDENTIFIER), Width::Fixed(1)),
    field(FieldSource::SrcIp, ie(IE_SOURCE_IPV4_ADDRESS), Width::Fixed(4)),
    field(FieldSource::DstIp, ie(IE_DESTINATION_IPV4_ADDRESS), Width::Fixed(4)),
    field(FieldSource::SrcPort, ie(IE_SOURCE_TRANSPORT_PORT), Width::Fixed(2)),
    field(FieldSource::DstPort, ie(IE_DESTINATION_TRANSPORT_PORT), Width::Fixed(2)),
    field(FieldSource::PostNatSrcIp, ie(IE_POST_NAT_SOURCE_IPV4_ADDRESS), Width::Fixed(4)),
    field(FieldSource::PostNatSrcPort, ie(IE_POST_NAPT_SOURCE_TRANSPORT_PORT), Width::Fixed(2)),
    field(FieldSource::PostNatDstIp, ie(IE_POST_NAT_DESTINATION_IPV4_ADDRESS), Width::Fixed(4)),
    field(FieldSource::PostNatDstPort, ie(IE_POST_NAPT_DESTINATION_TRANSPORT_PORT), Width::Fixed(2)),
    field(FieldSource::OrigBytes, ie(IE_OCTET_DELTA_COUNT), Width::Counter),
    field(FieldSource::OrigPackets, ie(IE_PACKET_DELTA_COUNT), Width::Counter),
    field(FieldSource::ReplyBytes, reverse_ie(IE_OCTET_DELTA_COUNT), Width::Counter),
    field(FieldSource::ReplyPackets, reverse_ie(IE_PACKET_DELTA_COUNT), Width::Counter),
];

/// For collectors that know the source-NAT elements but not the destination
/// ones. Drops postNATDestination* only.
pub const PROFILE_NAT_SOURCE: &[FieldShape] = &[
    field(FieldSource::NatEvent, ie(IE_NAT_EVENT), Width::Fixed(1)),
    field(FieldSource::Protocol, ie(IE_PROTOCOL_IDENTIFIER), Width::Fixed(1)),
    field(FieldSource::SrcIp, ie(IE_SOURCE_IPV4_ADDRESS), Width::Fixed(4)),
    field(FieldSource::DstIp, ie(IE_DESTINATION_IPV4_ADDRESS), Width::Fixed(4)),
    field(FieldSource::SrcPort, ie(IE_SOURCE_TRANSPORT_PORT), Width::Fixed(2)),
    field(FieldSource::DstPort, ie(IE_DESTINATION_TRANSPORT_PORT), Width::Fixed(2)),
    field(FieldSource::PostNatSrcIp, ie(IE_POST_NAT_SOURCE_IPV4_ADDRESS), Width::Fixed(4)),
    field(FieldSource::PostNatSrcPort, ie(IE_POST_NAPT_SOURCE_TRANSPORT_PORT), Width::Fixed(2)),
    field(FieldSource::OrigBytes, ie(IE_OCTET_DELTA_COUNT), Width::Counter),
    field(FieldSource::OrigPackets, ie(IE_PACKET_DELTA_COUNT), Width::Counter),
    field(FieldSource::ReplyBytes, reverse_ie(IE_OCTET_DELTA_COUNT), Width::Counter),
    field(FieldSource::ReplyPackets, reverse_ie(IE_PACKET_DELTA_COUNT), Width::Counter),
];

/// Only elements every collector's base registry knows. This carries **no NAT
/// information at all** — the pre-NAT five-tuple and counters, nothing more.
/// It exists for collectors that cannot decode natEvent or the postNAT
/// elements, which are not in RFC 3954's field table.
pub const PROFILE_FLOW_ONLY: &[FieldShape] = &[
    field(FieldSource::Protocol, ie(IE_PROTOCOL_IDENTIFIER), Width::Fixed(1)),
    field(FieldSource::SrcIp, ie(IE_SOURCE_IPV4_ADDRESS), Width::Fixed(4)),
    field(FieldSource::DstIp, ie(IE_DESTINATION_IPV4_ADDRESS), Width::Fixed(4)),
    field(FieldSource::SrcPort, ie(IE_SOURCE_TRANSPORT_PORT), Width::Fixed(2)),
    field(FieldSource::DstPort, ie(IE_DESTINATION_TRANSPORT_PORT), Width::Fixed(2)),
    field(FieldSource::OrigBytes, ie(IE_OCTET_DELTA_COUNT), Width::Counter),
    field(FieldSource::OrigPackets, ie(IE_PACKET_DELTA_COUNT), Width::Counter),
    field(FieldSource::ReplyBytes, reverse_ie(IE_OCTET_DELTA_COUNT), Width::Counter),
    field(FieldSource::ReplyPackets, reverse_ie(IE_PACKET_DELTA_COUNT), Width::Counter),
];

/// A declared width must match what the source actually produces, or the record
/// and the template it advertises would disagree.
const fn shapes_are_consistent(shapes: &[FieldShape]) -> bool {
    let mut i = 0;
    while i < shapes.len() {
        let ok = match (shapes[i].width, shapes[i].source.natural_len()) {
            (Width::Fixed(declared), Some(natural)) => declared == natural,
            (Width::Counter, None) => true,
            _ => false,
        };
        if !ok {
            return false;
        }
        i += 1;
    }
    true
}

const _: () = assert!(shapes_are_consistent(PROFILE_FULL));
const _: () = assert!(shapes_are_consistent(PROFILE_NAT_SOURCE));
const _: () = assert!(shapes_are_consistent(PROFILE_FLOW_ONLY));

/// Which export protocol to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Protocol {
    /// IPFIX, RFC 7011.
    Ipfix,
    /// NetFlow v9, RFC 3954.
    Netflow9,
}

impl Protocol {
    pub const fn version(self) -> u16 {
        match self {
            Protocol::Ipfix => IPFIX_VERSION,
            Protocol::Netflow9 => NETFLOW9_VERSION,
        }
    }

    pub const fn header_len(self) -> usize {
        match self {
            Protocol::Ipfix => IPFIX_HEADER_LEN,
            Protocol::Netflow9 => NETFLOW9_HEADER_LEN,
        }
    }

    /// The set / FlowSet ID that introduces a template.
    pub const fn template_set_id(self) -> u16 {
        match self {
            Protocol::Ipfix => IPFIX_TEMPLATE_SET_ID,
            Protocol::Netflow9 => NETFLOW9_TEMPLATE_FLOWSET_ID,
        }
    }

    /// Whether enterprise-specific Information Elements can be expressed.
    /// NetFlow v9 field specifiers are a flat (type, length) pair.
    pub const fn supports_enterprise(self) -> bool {
        matches!(self, Protocol::Ipfix)
    }

    /// Byte boundary that sets are padded to, if the protocol asks for it.
    pub const fn set_alignment(self) -> usize {
        match self {
            Protocol::Ipfix => 1,
            Protocol::Netflow9 => NETFLOW9_ALIGNMENT,
        }
    }
}

/// The NetFlow v9 field type for a source.
///
/// v9 has no enterprise mechanism, so the RFC 5103 reverse counters that IPFIX
/// carries as IE 1/2 + PEN 29305 map onto the dedicated OUT_BYTES/OUT_PKTS
/// types instead.
///
/// Take care here: 23/24 are *correct* under v9 and *wrong* under IPFIX, where
/// the same numbers mean postOctetDeltaCount/postPacketDeltaCount — the forward
/// direction as modified by a middlebox, not the reverse direction. Same
/// numbers, opposite meaning; do not "unify" these.
const fn netflow9_type(source: FieldSource, ipfix_id: u16) -> u16 {
    match source {
        FieldSource::ReplyBytes => V9_OUT_BYTES,
        FieldSource::ReplyPackets => V9_OUT_PKTS,
        _ => ipfix_id,
    }
}

/// Which field set to export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Profile {
    /// Both NAT directions and both counter directions (14 fields).
    Full,
    /// Source translation only, no postNATDestination elements (12 fields).
    NatSource,
    /// Five-tuple and counters only; no NAT elements at all (9 fields).
    FlowOnly,
}

impl Profile {
    pub fn shapes(self) -> &'static [FieldShape] {
        match self {
            Profile::Full => PROFILE_FULL,
            Profile::NatSource => PROFILE_NAT_SOURCE,
            Profile::FlowOnly => PROFILE_FLOW_ONLY,
        }
    }
}

/// How many bytes each byte/packet counter occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterWidth {
    /// NetFlow v9's default width for IN_BYTES and friends.
    Four,
    /// Wide enough for conntrack's u64 counters.
    Eight,
}

impl CounterWidth {
    pub const fn bytes(self) -> u16 {
        match self {
            CounterWidth::Four => 4,
            CounterWidth::Eight => 8,
        }
    }

    pub fn from_bytes(bytes: u8) -> Result<Self> {
        match bytes {
            4 => Ok(CounterWidth::Four),
            8 => Ok(CounterWidth::Eight),
            other => bail!("counter width must be 4 or 8 bytes, got {other}"),
        }
    }
}

/// One field of the resolved template.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedField {
    pub id: u16,
    pub pen: Option<u32>,
    pub length: u16,
    pub source: FieldSource,
}

/// A profile resolved against a counter width: the exact fields the encoder
/// writes and the template it advertises.
#[derive(Debug, Clone)]
pub struct Template {
    pub fields: Vec<ResolvedField>,
    pub record_size: usize,
    pub template_id: u16,
    pub protocol: Protocol,
    pub profile: Profile,
    pub counter_width: CounterWidth,
}

/// Round up to the next multiple of `alignment`.
pub const fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

impl Template {
    pub fn resolve(
        protocol: Protocol,
        profile: Profile,
        counter_width: CounterWidth,
        template_id: u16,
    ) -> Result<Self> {
        if template_id < MIN_TEMPLATE_ID {
            bail!("template ID must be at least {MIN_TEMPLATE_ID}, got {template_id}");
        }

        let fields: Vec<ResolvedField> = profile
            .shapes()
            .iter()
            .map(|shape| {
                let (id, pen) = match protocol {
                    Protocol::Ipfix => (shape.ipfix.id, shape.ipfix.pen),
                    Protocol::Netflow9 => (netflow9_type(shape.source, shape.ipfix.id), None),
                };
                ResolvedField {
                    id,
                    pen,
                    length: match shape.width {
                        Width::Fixed(n) => n,
                        Width::Counter => counter_width.bytes(),
                    },
                    source: shape.source,
                }
            })
            .collect();

        debug_assert!(
            protocol.supports_enterprise() || fields.iter().all(|f| f.pen.is_none()),
            "enterprise elements cannot be expressed under this protocol"
        );

        let record_size = fields.iter().map(|f| f.length as usize).sum();

        let template = Template {
            fields,
            record_size,
            template_id,
            protocol,
            profile,
            counter_width,
        };

        // A message that cannot hold its own template plus one record would
        // never make progress.
        let smallest_useful = protocol.header_len()
            + template.set_size()
            + template.data_set_size(1);
        if smallest_useful > MAX_MSG_SIZE {
            bail!(
                "a {record_size}-byte record with a {}-byte template does not fit \
                 in the {MAX_MSG_SIZE}-byte message budget",
                template.set_size()
            );
        }

        Ok(template)
    }

    /// Size of the encoded template set: set header, template record header,
    /// then one specifier per field, padded if the protocol asks for it.
    pub fn set_size(&self) -> usize {
        let specifiers: usize = self
            .fields
            .iter()
            .map(|f| match f.pen {
                Some(_) => FIELD_SPECIFIER_LEN + ENTERPRISE_NUMBER_LEN,
                None => FIELD_SPECIFIER_LEN,
            })
            .sum();
        align_up(
            SET_HEADER_LEN + 4 + specifiers,
            self.protocol.set_alignment(),
        )
    }

    /// Size of a data set holding `records` records, including any padding.
    pub fn data_set_size(&self, records: usize) -> usize {
        align_up(
            SET_HEADER_LEN + records * self.record_size,
            self.protocol.set_alignment(),
        )
    }

    pub fn field_count(&self) -> u16 {
        self.fields.len() as u16
    }

    /// Records that fit in a message that also carries the template — the
    /// worst case, and so the figure worth reporting.
    pub fn max_records_per_message(&self) -> usize {
        let budget = MAX_MSG_SIZE - self.protocol.header_len() - self.set_size();
        let mut records = 0;
        while self.data_set_size(records + 1) <= budget {
            records += 1;
        }
        records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_PROTOCOLS: [Protocol; 2] = [Protocol::Ipfix, Protocol::Netflow9];
    const ALL_PROFILES: [Profile; 3] = [Profile::Full, Profile::NatSource, Profile::FlowOnly];
    const ALL_WIDTHS: [CounterWidth; 2] = [CounterWidth::Four, CounterWidth::Eight];

    fn resolve(protocol: Protocol, profile: Profile, width: CounterWidth) -> Template {
        Template::resolve(protocol, profile, width, DEFAULT_TEMPLATE_ID).unwrap()
    }

    /// Every (protocol, profile, width) combination the CLI can ask for.
    fn every_configuration() -> impl Iterator<Item = (Protocol, Profile, CounterWidth)> {
        ALL_PROTOCOLS.into_iter().flat_map(|protocol| {
            ALL_PROFILES.into_iter().flat_map(move |profile| {
                ALL_WIDTHS
                    .into_iter()
                    .map(move |width| (protocol, profile, width))
            })
        })
    }

    /// The profile table in the README, which is what an operator picks from.
    /// Field count and record size are the two numbers they have to match
    /// against their collector, so a silent change to either is a bug.
    #[test]
    fn profiles_carry_the_documented_field_count_and_record_size() {
        let expected = [
            (Profile::Full, 14, 58, 42),
            (Profile::NatSource, 12, 52, 36),
            (Profile::FlowOnly, 9, 45, 29),
        ];

        for (profile, fields, wide_record, narrow_record) in expected {
            for protocol in ALL_PROTOCOLS {
                let wide = resolve(protocol, profile, CounterWidth::Eight);
                assert_eq!(wide.field_count(), fields, "{profile:?} field count");
                assert_eq!(wide.record_size, wide_record, "{profile:?} 8-byte counters");

                let narrow = resolve(protocol, profile, CounterWidth::Four);
                assert_eq!(narrow.field_count(), fields, "{profile:?} field count");
                assert_eq!(
                    narrow.record_size, narrow_record,
                    "{profile:?} 4-byte counters"
                );
            }
        }
    }

    /// The record layout table in the README, in order. These IDs are what a
    /// collector matches its own registry against.
    #[test]
    fn the_full_profile_advertises_the_documented_elements_in_order() {
        let ipfix = resolve(Protocol::Ipfix, Profile::Full, CounterWidth::Eight);
        let specifiers: Vec<(u16, Option<u32>, u16)> = ipfix
            .fields
            .iter()
            .map(|f| (f.id, f.pen, f.length))
            .collect();

        const PEN: Option<u32> = Some(REVERSE_INFORMATION_ELEMENT_PEN);
        assert_eq!(
            specifiers,
            vec![
                (230, None, 1), // natEvent
                (4, None, 1),   // protocolIdentifier
                (8, None, 4),   // sourceIPv4Address
                (12, None, 4),  // destinationIPv4Address
                (7, None, 2),   // sourceTransportPort
                (11, None, 2),  // destinationTransportPort
                (225, None, 4), // postNATSourceIPv4Address
                (227, None, 2), // postNAPTSourceTransportPort
                (226, None, 4), // postNATDestinationIPv4Address
                (228, None, 2), // postNAPTDestinationTransportPort
                (1, None, 8),   // octetDeltaCount
                (2, None, 8),   // packetDeltaCount
                (1, PEN, 8),    // reverseOctetDeltaCount
                (2, PEN, 8),    // reversePacketDeltaCount
            ]
        );
    }

    /// Same values, but v9 has no enterprise mechanism, so the reverse counters
    /// become the dedicated OUT_BYTES/OUT_PKTS types.
    #[test]
    fn the_netflow9_full_profile_swaps_the_reverse_elements_for_out_counters() {
        let v9 = resolve(Protocol::Netflow9, Profile::Full, CounterWidth::Eight);
        let ids: Vec<u16> = v9.fields.iter().map(|f| f.id).collect();

        assert_eq!(
            ids,
            vec![230, 4, 8, 12, 7, 11, 225, 227, 226, 228, 1, 2, V9_OUT_BYTES, V9_OUT_PKTS]
        );
    }

    /// IEs 23/24 mean postOctetDeltaCount/postPacketDeltaCount under IPFIX —
    /// the forward direction through a middlebox, not the reverse direction.
    /// Emitting them there would report a different quantity under the same
    /// numbers, so IPFIX must keep the RFC 5103 enterprise elements.
    #[test]
    fn ipfix_never_borrows_the_netflow9_out_counter_types() {
        for (profile, width) in ALL_PROFILES.into_iter().flat_map(|p| {
            ALL_WIDTHS.into_iter().map(move |w| (p, w))
        }) {
            let template = resolve(Protocol::Ipfix, profile, width);
            for field in &template.fields {
                if field.pen.is_none() {
                    assert!(
                        field.id != V9_OUT_BYTES && field.id != V9_OUT_PKTS,
                        "{profile:?}: IE {} means something else under IPFIX",
                        field.id
                    );
                }
            }
        }
    }

    #[test]
    fn netflow9_never_resolves_an_enterprise_element() {
        for (profile, width) in ALL_PROFILES.into_iter().flat_map(|p| {
            ALL_WIDTHS.into_iter().map(move |w| (p, w))
        }) {
            let template = resolve(Protocol::Netflow9, profile, width);
            assert!(
                template.fields.iter().all(|f| f.pen.is_none()),
                "{profile:?}: v9 field specifiers cannot carry a PEN"
            );
        }
    }

    /// `flow-only` exists for collectors that cannot decode the NAT elements.
    /// If any of them leaked back in, the profile would fail on exactly the
    /// collectors it was added for.
    #[test]
    fn the_flow_only_profile_carries_no_nat_elements() {
        const NAT_ELEMENTS: [u16; 5] = [
            IE_NAT_EVENT,
            IE_POST_NAT_SOURCE_IPV4_ADDRESS,
            IE_POST_NAPT_SOURCE_TRANSPORT_PORT,
            IE_POST_NAT_DESTINATION_IPV4_ADDRESS,
            IE_POST_NAPT_DESTINATION_TRANSPORT_PORT,
        ];

        for protocol in ALL_PROTOCOLS {
            let template = resolve(protocol, Profile::FlowOnly, CounterWidth::Eight);
            for field in &template.fields {
                assert!(
                    !NAT_ELEMENTS.contains(&field.id),
                    "{protocol:?}: IE {} is a NAT element",
                    field.id
                );
            }
            // What it does carry: the pre-NAT five-tuple and the counters.
            assert!(
                template
                    .fields
                    .iter()
                    .any(|f| f.source == FieldSource::SrcIp),
                "the pre-NAT five-tuple is the point of the profile"
            );
        }
    }

    /// `nat-source` drops the destination translation and nothing else.
    #[test]
    fn the_nat_source_profile_drops_only_the_destination_translation() {
        let template = resolve(Protocol::Ipfix, Profile::NatSource, CounterWidth::Eight);
        let sources: Vec<FieldSource> = template.fields.iter().map(|f| f.source).collect();

        assert!(sources.contains(&FieldSource::NatEvent));
        assert!(sources.contains(&FieldSource::PostNatSrcIp));
        assert!(sources.contains(&FieldSource::PostNatSrcPort));
        assert!(!sources.contains(&FieldSource::PostNatDstIp));
        assert!(!sources.contains(&FieldSource::PostNatDstPort));
    }

    /// A resolved field's declared width must match what the encoder will
    /// actually write for that source, or the record and the template it
    /// advertises would disagree on the wire.
    #[test]
    fn every_resolved_field_is_as_wide_as_its_source() {
        for (protocol, profile, width) in every_configuration() {
            let template = resolve(protocol, profile, width);
            for field in &template.fields {
                match field.source.natural_len() {
                    Some(natural) => assert_eq!(
                        field.length, natural,
                        "{protocol:?}/{profile:?}: {:?} is a fixed-width source",
                        field.source
                    ),
                    None => assert_eq!(
                        field.length,
                        width.bytes(),
                        "{protocol:?}/{profile:?}: {:?} is a counter",
                        field.source
                    ),
                }
            }
            let declared: usize = template.fields.iter().map(|f| f.length as usize).sum();
            assert_eq!(declared, template.record_size);
        }
    }

    // ---- Sizing ----

    /// `set_size` is what the encoder writes into the set header before it has
    /// written the set, so it has to match the specifiers exactly.
    #[test]
    fn the_template_set_size_accounts_for_every_specifier() {
        for (protocol, profile, width) in every_configuration() {
            let template = resolve(protocol, profile, width);
            let specifiers: usize = template
                .fields
                .iter()
                .map(|f| match f.pen {
                    Some(_) => FIELD_SPECIFIER_LEN + ENTERPRISE_NUMBER_LEN,
                    None => FIELD_SPECIFIER_LEN,
                })
                .sum();

            let unpadded = SET_HEADER_LEN + 4 + specifiers;
            assert_eq!(
                template.set_size(),
                align_up(unpadded, protocol.set_alignment())
            );
            assert_eq!(
                template.set_size() % protocol.set_alignment(),
                0,
                "{protocol:?} sets must land on their alignment"
            );
        }
    }

    #[test]
    fn data_sets_are_padded_only_where_the_protocol_asks() {
        let ipfix = resolve(Protocol::Ipfix, Profile::Full, CounterWidth::Eight);
        // IPFIX sets are not padded, so the size is exact for any count.
        for records in 0..4 {
            assert_eq!(
                ipfix.data_set_size(records),
                SET_HEADER_LEN + records * 58
            );
        }

        // A 58-byte record leaves an odd v9 FlowSet for odd counts, which RFC
        // 3954 asks to be padded up to a 4-byte boundary.
        let v9 = resolve(Protocol::Netflow9, Profile::Full, CounterWidth::Eight);
        for records in 0..4 {
            let size = v9.data_set_size(records);
            assert_eq!(size % NETFLOW9_ALIGNMENT, 0, "{records} records");
            assert!(size >= SET_HEADER_LEN + records * 58);
            assert!(size < SET_HEADER_LEN + records * 58 + NETFLOW9_ALIGNMENT);
        }
    }

    /// The figure logged at startup, and the one an operator sizes their
    /// collector against. It must be achievable in the worst case — a message
    /// that also carries the template.
    #[test]
    fn the_reported_capacity_fits_alongside_the_template() {
        for (protocol, profile, width) in every_configuration() {
            let template = resolve(protocol, profile, width);
            let capacity = template.max_records_per_message();
            let label = format!("{protocol:?}/{profile:?}/{width:?}");

            assert!(capacity > 0, "{label}: no records fit");

            let used = |records| {
                protocol.header_len() + template.set_size() + template.data_set_size(records)
            };
            assert!(used(capacity) <= MAX_MSG_SIZE, "{label}: capacity overflows");
            assert!(
                used(capacity + 1) > MAX_MSG_SIZE,
                "{label}: one more record would still have fit"
            );
        }
    }

    #[test]
    fn align_up_rounds_to_the_next_multiple() {
        assert_eq!(align_up(0, 4), 0);
        assert_eq!(align_up(1, 4), 4);
        assert_eq!(align_up(4, 4), 4);
        assert_eq!(align_up(5, 4), 8);
        // Alignment of 1 is the IPFIX case: never any padding.
        for value in 0..8 {
            assert_eq!(align_up(value, 1), value);
        }
    }

    // ---- Validation ----

    /// Template IDs below 256 collide with the set / FlowSet identifiers, so a
    /// collector would read a data set as a template set.
    #[test]
    fn template_ids_below_the_reserved_range_are_rejected() {
        for id in [0, 1, 2, 255] {
            let err = Template::resolve(
                Protocol::Ipfix,
                Profile::Full,
                CounterWidth::Eight,
                id,
            )
            .expect_err("template ID {id} must be rejected");
            assert!(
                err.to_string().contains("at least 256"),
                "unhelpful error: {err}"
            );
        }

        assert!(
            Template::resolve(
                Protocol::Ipfix,
                Profile::Full,
                CounterWidth::Eight,
                MIN_TEMPLATE_ID
            )
            .is_ok(),
            "256 is the first usable ID"
        );
        assert!(
            Template::resolve(
                Protocol::Ipfix,
                Profile::Full,
                CounterWidth::Eight,
                u16::MAX
            )
            .is_ok()
        );
    }

    #[test]
    fn the_template_id_is_carried_through_to_the_resolved_template() {
        let template = Template::resolve(
            Protocol::Ipfix,
            Profile::Full,
            CounterWidth::Eight,
            4242,
        )
        .unwrap();
        assert_eq!(template.template_id, 4242);
    }

    #[test]
    fn counter_width_accepts_only_four_or_eight_bytes() {
        assert_eq!(CounterWidth::from_bytes(4).unwrap(), CounterWidth::Four);
        assert_eq!(CounterWidth::from_bytes(8).unwrap(), CounterWidth::Eight);
        assert_eq!(CounterWidth::Four.bytes(), 4);
        assert_eq!(CounterWidth::Eight.bytes(), 8);

        for bad in [0u8, 1, 2, 3, 5, 6, 7, 9, 16, 255] {
            let err = CounterWidth::from_bytes(bad)
                .expect_err("width {bad} must be rejected");
            assert!(
                err.to_string().contains("must be 4 or 8"),
                "unhelpful error: {err}"
            );
        }
    }

    // ---- Protocol traits ----

    #[test]
    fn each_protocol_reports_its_own_wire_constants() {
        assert_eq!(Protocol::Ipfix.version(), 10);
        assert_eq!(Protocol::Ipfix.header_len(), 16);
        assert_eq!(Protocol::Ipfix.template_set_id(), 2);
        assert!(Protocol::Ipfix.supports_enterprise());
        assert_eq!(Protocol::Ipfix.set_alignment(), 1, "IPFIX sets are unpadded");

        assert_eq!(Protocol::Netflow9.version(), 9);
        assert_eq!(Protocol::Netflow9.header_len(), 20);
        assert_eq!(Protocol::Netflow9.template_set_id(), 0);
        assert!(!Protocol::Netflow9.supports_enterprise());
        assert_eq!(Protocol::Netflow9.set_alignment(), 4);
    }
}
