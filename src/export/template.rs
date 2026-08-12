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
    pub profile: Profile,
    pub counter_width: CounterWidth,
}

impl Template {
    pub fn resolve(profile: Profile, counter_width: CounterWidth, template_id: u16) -> Result<Self> {
        if template_id < MIN_TEMPLATE_ID {
            bail!("template ID must be at least {MIN_TEMPLATE_ID}, got {template_id}");
        }

        let fields: Vec<ResolvedField> = profile
            .shapes()
            .iter()
            .map(|shape| ResolvedField {
                id: shape.ipfix.id,
                pen: shape.ipfix.pen,
                length: match shape.width {
                    Width::Fixed(n) => n,
                    Width::Counter => counter_width.bytes(),
                },
                source: shape.source,
            })
            .collect();

        let record_size = fields.iter().map(|f| f.length as usize).sum();

        let template = Template {
            fields,
            record_size,
            template_id,
            profile,
            counter_width,
        };

        // A message that cannot hold its own template plus one record would
        // never make progress.
        let smallest_useful = IPFIX_HEADER_LEN + template.set_size() + SET_HEADER_LEN + record_size;
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
    /// then one specifier per field.
    pub fn set_size(&self) -> usize {
        let specifiers: usize = self
            .fields
            .iter()
            .map(|f| match f.pen {
                Some(_) => FIELD_SPECIFIER_LEN + ENTERPRISE_NUMBER_LEN,
                None => FIELD_SPECIFIER_LEN,
            })
            .sum();
        SET_HEADER_LEN + 4 + specifiers
    }

    pub fn field_count(&self) -> u16 {
        self.fields.len() as u16
    }

    /// Records that fit in a message that also carries the template — the
    /// worst case, and so the figure worth reporting.
    pub fn max_records_per_message(&self) -> usize {
        let available =
            MAX_MSG_SIZE - IPFIX_HEADER_LEN - self.set_size() - SET_HEADER_LEN;
        available / self.record_size
    }
}
