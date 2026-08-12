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
