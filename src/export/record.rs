//! The data record body, which is identical under every export protocol.
//!
//! IPFIX and NetFlow v9 differ in their message header and in how a template is
//! described, but a record is just the field values concatenated in template
//! order — so this is written once and shared.

use crate::event::ConntrackEvent;

use super::template::{FieldSource, ResolvedField};

/// A field's value, before it is written at the width the template advertises.
enum Value {
    Byte(u8),
    Port(u16),
    Addr([u8; 4]),
    Counter(u64),
}

fn value_of(source: FieldSource, event: &ConntrackEvent) -> Value {
    match source {
        FieldSource::NatEvent => Value::Byte(event.nat_event.nat_event_code()),
        FieldSource::Protocol => Value::Byte(event.protocol),
        FieldSource::SrcIp => Value::Addr(event.src_ip.octets()),
        FieldSource::DstIp => Value::Addr(event.dst_ip.octets()),
        FieldSource::SrcPort => Value::Port(event.src_port),
        FieldSource::DstPort => Value::Port(event.dst_port),
        FieldSource::PostNatSrcIp => Value::Addr(event.post_nat_src_ip.octets()),
        FieldSource::PostNatSrcPort => Value::Port(event.post_nat_src_port),
        FieldSource::PostNatDstIp => Value::Addr(event.post_nat_dst_ip.octets()),
        FieldSource::PostNatDstPort => Value::Port(event.post_nat_dst_port),
        FieldSource::OrigBytes => Value::Counter(event.orig_bytes),
        FieldSource::OrigPackets => Value::Counter(event.orig_packets),
        FieldSource::ReplyBytes => Value::Counter(event.reply_bytes),
        FieldSource::ReplyPackets => Value::Counter(event.reply_packets),
    }
}

/// Largest value a counter of `len` bytes can carry.
const fn counter_max(len: usize) -> u64 {
    if len >= 8 {
        u64::MAX
    } else {
        (1u64 << (len * 8)) - 1
    }
}

/// Write one record at `offset`, advancing it. Returns how many counters had to
/// be clamped because the configured width could not hold them.
///
/// The caller guarantees the record fits; field widths are validated when the
/// template is resolved.
pub fn write_record(
    buf: &mut [u8],
    offset: &mut usize,
    fields: &[ResolvedField],
    event: &ConntrackEvent,
) -> u64 {
    let mut saturated = 0;

    for field in fields {
        let len = field.length as usize;
        debug_assert!(
            field.source.natural_len().is_none_or(|n| n as usize == len),
            "field width does not match its source"
        );

        match value_of(field.source, event) {
            Value::Byte(value) => {
                buf[*offset] = value;
                *offset += 1;
            }
            Value::Port(value) => {
                buf[*offset..*offset + 2].copy_from_slice(&value.to_be_bytes());
                *offset += 2;
            }
            Value::Addr(value) => {
                buf[*offset..*offset + 4].copy_from_slice(&value);
                *offset += 4;
            }
            Value::Counter(value) => {
                // Truncating a counter would report a plausible wrong number;
                // clamping at least reports a number the collector can spot.
                let max = counter_max(len);
                let value = if value > max {
                    saturated += 1;
                    max
                } else {
                    value
                };
                buf[*offset..*offset + len].copy_from_slice(&value.to_be_bytes()[8 - len..]);
                *offset += len;
            }
        }
    }

    saturated
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::NatEventType;
    use crate::export::elements::{
        DEFAULT_TEMPLATE_ID, NAT44_SESSION_CREATE, NAT44_SESSION_DELETE,
    };
    use crate::export::template::{CounterWidth, Profile, Protocol, Template};
    use std::net::Ipv4Addr;

    fn event() -> ConntrackEvent {
        ConntrackEvent {
            nat_event: NatEventType::Create,
            protocol: 17,
            src_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            src_port: 1234,
            dst_port: 53,
            post_nat_src_ip: Ipv4Addr::new(203, 0, 113, 5),
            post_nat_src_port: 40000,
            post_nat_dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            post_nat_dst_port: 53,
            orig_bytes: 700,
            orig_packets: 7,
            reply_bytes: 900,
            reply_packets: 9,
        }
    }

    fn template(profile: Profile, width: CounterWidth) -> Template {
        Template::resolve(Protocol::Ipfix, profile, width, DEFAULT_TEMPLATE_ID).unwrap()
    }

    /// Encode one record on its own, returning the bytes and the clamp count.
    fn encode(template: &Template, event: &ConntrackEvent) -> (Vec<u8>, u64) {
        let mut buf = vec![0u8; template.record_size];
        let mut offset = 0;
        let saturated = write_record(&mut buf, &mut offset, &template.fields, event);
        assert_eq!(
            offset, template.record_size,
            "a record must occupy exactly the advertised size"
        );
        (buf, saturated)
    }

    fn be16(bytes: &[u8]) -> u16 {
        u16::from_be_bytes([bytes[0], bytes[1]])
    }

    fn be32(bytes: &[u8]) -> u32 {
        u32::from_be_bytes(bytes[..4].try_into().unwrap())
    }

    fn be64(bytes: &[u8]) -> u64 {
        u64::from_be_bytes(bytes[..8].try_into().unwrap())
    }

    #[test]
    fn a_full_record_carries_every_field_in_template_order() {
        let template = template(Profile::Full, CounterWidth::Eight);
        let (r, saturated) = encode(&template, &event());

        assert_eq!(saturated, 0);
        assert_eq!(r[0], NAT44_SESSION_CREATE);
        assert_eq!(r[1], 17, "protocolIdentifier");
        assert_eq!(&r[2..6], &[192, 168, 1, 10]);
        assert_eq!(&r[6..10], &[8, 8, 8, 8]);
        assert_eq!(be16(&r[10..12]), 1234);
        assert_eq!(be16(&r[12..14]), 53);
        assert_eq!(&r[14..18], &[203, 0, 113, 5]);
        assert_eq!(be16(&r[18..20]), 40000);
        assert_eq!(&r[20..24], &[8, 8, 8, 8]);
        assert_eq!(be16(&r[24..26]), 53);
        assert_eq!(be64(&r[26..34]), 700);
        assert_eq!(be64(&r[34..42]), 7);
        assert_eq!(be64(&r[42..50]), 900);
        assert_eq!(be64(&r[50..58]), 9);
    }

    #[test]
    fn the_nat_event_code_follows_the_event_type() {
        let template = template(Profile::Full, CounterWidth::Eight);

        let (create, _) = encode(&template, &event());
        assert_eq!(create[0], NAT44_SESSION_CREATE);

        let mut ev = event();
        ev.nat_event = NatEventType::Delete;
        let (delete, _) = encode(&template, &ev);
        assert_eq!(delete[0], NAT44_SESSION_DELETE);
    }

    /// The narrow record is the same values in the same order, with the four
    /// counters at half the width.
    #[test]
    fn narrow_counters_shrink_only_the_counters() {
        let template = template(Profile::Full, CounterWidth::Four);
        let (r, saturated) = encode(&template, &event());

        assert_eq!(saturated, 0);
        assert_eq!(r.len(), 42);
        // Everything up to the counters is byte-identical to the wide record.
        let (wide, _) = encode(&self::template(Profile::Full, CounterWidth::Eight), &event());
        assert_eq!(&r[..26], &wide[..26]);

        assert_eq!(be32(&r[26..30]), 700);
        assert_eq!(be32(&r[30..34]), 7);
        assert_eq!(be32(&r[34..38]), 900);
        assert_eq!(be32(&r[38..42]), 9);
    }

    /// A `flow-only` record stops after the five-tuple and the counters — no
    /// natEvent byte, no postNAT addresses.
    #[test]
    fn a_flow_only_record_holds_the_pre_nat_tuple_and_counters() {
        let template = template(Profile::FlowOnly, CounterWidth::Eight);
        let (r, _) = encode(&template, &event());

        assert_eq!(r.len(), 45);
        assert_eq!(r[0], 17, "the record now opens on the protocol");
        assert_eq!(&r[1..5], &[192, 168, 1, 10], "pre-NAT source");
        assert_eq!(&r[5..9], &[8, 8, 8, 8]);
        assert_eq!(be16(&r[9..11]), 1234);
        assert_eq!(be16(&r[11..13]), 53);
        assert_eq!(be64(&r[13..21]), 700);
        assert_eq!(be64(&r[21..29]), 7);
        assert_eq!(be64(&r[29..37]), 900);
        assert_eq!(be64(&r[37..45]), 9);

        // The translated address must not appear anywhere in the record.
        assert!(
            !r.windows(4).any(|w| w == [203, 0, 113, 5]),
            "flow-only must carry no NAT information"
        );
    }

    #[test]
    fn a_nat_source_record_stops_after_the_source_translation() {
        let template = template(Profile::NatSource, CounterWidth::Eight);
        let (r, _) = encode(&template, &event());

        assert_eq!(r.len(), 52);
        assert_eq!(r[0], NAT44_SESSION_CREATE);
        assert_eq!(&r[14..18], &[203, 0, 113, 5], "postNATSourceIPv4Address");
        assert_eq!(be16(&r[18..20]), 40000);
        // The counters follow immediately; no destination translation.
        assert_eq!(be64(&r[20..28]), 700);
        assert_eq!(be64(&r[28..36]), 7);
    }

    // ---- Counter clamping ----

    #[test]
    fn counter_max_is_the_widest_value_the_field_can_hold() {
        assert_eq!(counter_max(4), u32::MAX as u64);
        assert_eq!(counter_max(8), u64::MAX);
    }

    /// A counter too wide for its field is clamped, so the collector sees an
    /// obviously pegged value rather than a plausible small one.
    #[test]
    fn an_oversized_counter_is_clamped_to_the_field_maximum() {
        let template = template(Profile::Full, CounterWidth::Four);

        let mut ev = event();
        ev.orig_bytes = u32::MAX as u64 + 1;
        let (r, saturated) = encode(&template, &ev);

        assert_eq!(saturated, 1);
        assert_eq!(
            be32(&r[26..30]),
            u32::MAX,
            "clamped, not truncated to a small value"
        );
    }

    /// Truncation is the failure this guards against: the low 32 bits of 2^32
    /// are zero, so a truncating encoder would report a busy flow as idle.
    #[test]
    fn clamping_never_reports_a_smaller_number_than_the_truth() {
        let template = template(Profile::Full, CounterWidth::Four);

        for value in [
            u32::MAX as u64 + 1, // truncates to 0
            1u64 << 32,
            (1u64 << 32) | 5, // truncates to 5
            u64::MAX,
        ] {
            let mut ev = event();
            ev.orig_bytes = value;
            let (r, saturated) = encode(&template, &ev);

            assert_eq!(saturated, 1, "value {value} must be reported as clamped");
            assert_eq!(be32(&r[26..30]), u32::MAX, "value {value}");
        }
    }

    #[test]
    fn a_counter_that_exactly_fills_the_field_is_not_clamped() {
        let template = template(Profile::Full, CounterWidth::Four);

        let mut ev = event();
        ev.orig_bytes = u32::MAX as u64;
        let (r, saturated) = encode(&template, &ev);

        assert_eq!(saturated, 0, "the maximum value still fits");
        assert_eq!(be32(&r[26..30]), u32::MAX);
    }

    #[test]
    fn every_oversized_counter_is_counted_separately() {
        let template = template(Profile::Full, CounterWidth::Four);

        let mut ev = event();
        ev.orig_bytes = u64::MAX;
        ev.orig_packets = 1;
        ev.reply_bytes = u64::MAX;
        ev.reply_packets = u64::MAX;
        let (_, saturated) = encode(&template, &ev);

        assert_eq!(saturated, 3, "three of the four counters overflowed");
    }

    #[test]
    fn wide_counters_hold_everything_conntrack_can_report() {
        let template = template(Profile::Full, CounterWidth::Eight);

        let mut ev = event();
        ev.orig_bytes = u64::MAX;
        ev.reply_packets = u64::MAX;
        let (r, saturated) = encode(&template, &ev);

        assert_eq!(saturated, 0, "conntrack counters are u64");
        assert_eq!(be64(&r[26..34]), u64::MAX);
        assert_eq!(be64(&r[50..58]), u64::MAX);
    }

    /// Every profile and width must produce a record of exactly the size the
    /// template advertises, since the encoder reserves space from that figure.
    #[test]
    fn a_record_always_occupies_exactly_the_advertised_size() {
        for protocol in [Protocol::Ipfix, Protocol::Netflow9] {
            for profile in [Profile::Full, Profile::NatSource, Profile::FlowOnly] {
                for width in [CounterWidth::Four, CounterWidth::Eight] {
                    let template =
                        Template::resolve(protocol, profile, width, DEFAULT_TEMPLATE_ID).unwrap();
                    // `encode` asserts the offset lands on record_size.
                    encode(&template, &event());
                }
            }
        }
    }
}
