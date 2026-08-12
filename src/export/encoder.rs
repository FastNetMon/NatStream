use std::time::{SystemTime, UNIX_EPOCH};

use crate::event::ConntrackEvent;

use super::elements::*;
use super::record::write_record;
use super::template::Template;

#[inline]
fn put_u16(buf: &mut [u8], offset: &mut usize, value: u16) {
    buf[*offset..*offset + 2].copy_from_slice(&value.to_be_bytes());
    *offset += 2;
}

#[inline]
fn put_u32(buf: &mut [u8], offset: &mut usize, value: u32) {
    buf[*offset..*offset + 4].copy_from_slice(&value.to_be_bytes());
    *offset += 4;
}

/// Pre-allocated IPFIX message encoder.
pub struct Encoder {
    buf: [u8; MAX_MSG_SIZE],
    offset: usize,
    record_count: u32,
    data_set_offset: usize,
    data_set_open: bool,
    template_included: bool,
    sequence_number: u32,
    observation_domain_id: u32,
    template: Template,
    saturated_counters: u64,
}

impl Encoder {
    pub fn new(observation_domain_id: u32, template: Template) -> Self {
        Encoder {
            buf: [0u8; MAX_MSG_SIZE],
            offset: 0,
            record_count: 0,
            data_set_offset: 0,
            data_set_open: false,
            template_included: false,
            sequence_number: 0,
            observation_domain_id,
            template,
            saturated_counters: 0,
        }
    }

    /// How many counter values have been clamped because the configured counter
    /// width could not hold them.
    pub fn saturated_counters(&self) -> u64 {
        self.saturated_counters
    }

    /// Begin a new message. If `include_template` is true, the template set is
    /// written first.
    ///
    /// The data set header is deferred until the first record, so a message
    /// that ends up with no records carries no empty data set — which lets a
    /// template be sent on its own when there is no traffic to attach it to.
    pub fn begin_message(&mut self, include_template: bool) {
        self.record_count = 0;
        self.data_set_open = false;
        self.template_included = include_template;

        // Reserve space for the message header (filled in finalize)
        self.offset = IPFIX_HEADER_LEN;

        if include_template {
            self.write_template_set();
        }
    }

    /// Try to add a record to the current message. Returns false if the message
    /// is full and the record was not added.
    pub fn add_record(&mut self, event: &ConntrackEvent) -> bool {
        // The data set header has to fit too if this is the first record.
        let needed = if self.data_set_open {
            self.template.record_size
        } else {
            SET_HEADER_LEN + self.template.record_size
        };
        if self.offset + needed > MAX_MSG_SIZE {
            return false;
        }

        if !self.data_set_open {
            // Data set header (set_id = template ID, length = placeholder)
            self.data_set_offset = self.offset;
            let template_id = self.template.template_id;
            put_u16(&mut self.buf, &mut self.offset, template_id);
            put_u16(&mut self.buf, &mut self.offset, 0);
            self.data_set_open = true;
        }

        let Encoder {
            buf,
            offset,
            template,
            ..
        } = self;
        let saturated = write_record(buf, offset, &template.fields, event);

        self.saturated_counters += saturated;
        self.record_count += 1;
        true
    }

    /// Returns true if the current message carries the template set.
    pub fn template_included(&self) -> bool {
        self.template_included
    }

    /// Returns true if the current message is worth sending: it holds records,
    /// the template, or both.
    pub fn has_pending_output(&self) -> bool {
        self.record_count > 0 || self.template_included
    }

    /// Finalize the message: fill in the header and the data set length.
    /// Returns the ready-to-send bytes and the number of records.
    pub fn finalize(&mut self) -> (&[u8], u32) {
        let msg_len = self.offset as u16;
        let export_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        // Fill IPFIX message header
        // Version (2 bytes)
        self.buf[0..2].copy_from_slice(&IPFIX_VERSION.to_be_bytes());
        // Length (2 bytes)
        self.buf[2..4].copy_from_slice(&msg_len.to_be_bytes());
        // Export Time (4 bytes)
        self.buf[4..8].copy_from_slice(&export_time.to_be_bytes());
        // Sequence Number (4 bytes)
        self.buf[8..12].copy_from_slice(&self.sequence_number.to_be_bytes());
        // Observation Domain ID (4 bytes)
        self.buf[12..16].copy_from_slice(&self.observation_domain_id.to_be_bytes());

        // Fill data set length, if this message has a data set at all
        if self.data_set_open {
            let data_set_len = (self.offset - self.data_set_offset) as u16;
            self.buf[self.data_set_offset + 2..self.data_set_offset + 4]
                .copy_from_slice(&data_set_len.to_be_bytes());
        }

        // Update sequence number (cumulative record count). RFC 7011 expects
        // this counter to wrap at 2^32 rather than to be an error.
        let count = self.record_count;
        self.sequence_number = self.sequence_number.wrapping_add(count);

        (&self.buf[..self.offset], count)
    }

    fn write_template_set(&mut self) {
        let Encoder {
            buf,
            offset,
            template,
            ..
        } = self;

        // Set header: set_id=2 (template), length
        put_u16(buf, offset, IPFIX_TEMPLATE_SET_ID);
        put_u16(buf, offset, template.set_size() as u16);

        // Template record header: template_id, field_count
        put_u16(buf, offset, template.template_id);
        put_u16(buf, offset, template.field_count());

        // Field specifiers. Enterprise-specific elements set the enterprise bit
        // in the IE ID and append the Private Enterprise Number.
        for field in &template.fields {
            match field.pen {
                Some(pen) => {
                    put_u16(buf, offset, field.id | ENTERPRISE_BIT);
                    put_u16(buf, offset, field.length);
                    put_u32(buf, offset, pen);
                }
                None => {
                    put_u16(buf, offset, field.id);
                    put_u16(buf, offset, field.length);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::NatEventType;
    use crate::export::template::{CounterWidth, Profile};
    use std::net::Ipv4Addr;

    fn template() -> Template {
        Template::resolve(Profile::Full, CounterWidth::Eight, DEFAULT_TEMPLATE_ID).unwrap()
    }

    fn encoder() -> Encoder {
        Encoder::new(0, template())
    }

    fn event() -> ConntrackEvent {
        ConntrackEvent {
            nat_event: NatEventType::Create,
            protocol: 6,
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

    fn be16(bytes: &[u8]) -> u16 {
        u16::from_be_bytes([bytes[0], bytes[1]])
    }

    fn be32(bytes: &[u8]) -> u32 {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn be64(bytes: &[u8]) -> u64 {
        u64::from_be_bytes(bytes[..8].try_into().unwrap())
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Captured from the exporter on the wire before the field table was
    /// introduced, with the export time zeroed. The default configuration must
    /// keep producing exactly these bytes.
    const GOLDEN_IPFIX_TEMPLATE_MESSAGE: &str = "000a005800000000000000000000000000020048\
                                                 0100000e00e600010004000100080004000c0004\
                                                 00070002000b000200e1000400e3000200e20004\
                                                 00e4000200010008000200088001000800007279\
                                                 8002000800007279";

    #[test]
    fn the_default_template_message_is_unchanged_on_the_wire() {
        let mut enc = encoder();
        enc.begin_message(true);
        let (msg, _) = enc.finalize();

        let mut msg = msg.to_vec();
        msg[4..8].fill(0); // export time varies

        assert_eq!(hex(&msg), GOLDEN_IPFIX_TEMPLATE_MESSAGE);
    }

    #[test]
    fn message_header_describes_the_message() {
        let mut enc = Encoder::new(42, template());
        enc.begin_message(false);
        assert!(enc.add_record(&event()));
        let (msg, count) = enc.finalize();

        assert_eq!(count, 1);
        assert_eq!(be16(&msg[0..2]), IPFIX_VERSION);
        assert_eq!(be16(&msg[2..4]) as usize, msg.len(), "length field must match");
        assert_ne!(be32(&msg[4..8]), 0, "export time should be set");
        assert_eq!(be32(&msg[8..12]), 0, "first message starts at sequence 0");
        assert_eq!(be32(&msg[12..16]), 42, "observation domain id");
    }

    #[test]
    fn a_template_only_message_carries_no_data_set() {
        let mut enc = encoder();
        enc.begin_message(true);

        assert!(enc.template_included());
        assert!(enc.has_pending_output(), "a template alone is worth sending");

        let set_size = enc.template.set_size();
        let (msg, count) = enc.finalize();
        assert_eq!(count, 0);
        assert_eq!(msg.len(), IPFIX_HEADER_LEN + set_size);
        assert_eq!(be16(&msg[2..4]) as usize, msg.len());

        // Exactly one set, the template set, with no empty data set trailing it.
        assert_eq!(be16(&msg[16..18]), IPFIX_TEMPLATE_SET_ID);
        assert_eq!(be16(&msg[18..20]) as usize, set_size);
        assert_eq!(be16(&msg[20..22]), DEFAULT_TEMPLATE_ID);
        assert_eq!(be16(&msg[22..24]), 14);
    }

    #[test]
    fn an_empty_message_without_a_template_is_not_worth_sending() {
        let mut enc = encoder();
        enc.begin_message(false);
        assert!(!enc.has_pending_output());
    }

    #[test]
    fn the_template_describes_the_fields_the_encoder_writes() {
        let mut enc = encoder();
        enc.begin_message(true);
        let fields = enc.template.fields.clone();
        let (msg, _) = enc.finalize();

        let mut offset = IPFIX_HEADER_LEN + SET_HEADER_LEN + 4; // sets, template header
        let mut record_size = 0;
        for field in &fields {
            let raw_id = be16(&msg[offset..]);
            let length = be16(&msg[offset + 2..]);
            offset += FIELD_SPECIFIER_LEN;

            assert_eq!(length, field.length);
            match field.pen {
                Some(pen) => {
                    assert_eq!(raw_id & ENTERPRISE_BIT, ENTERPRISE_BIT, "enterprise bit");
                    assert_eq!(raw_id & !ENTERPRISE_BIT, field.id);
                    assert_eq!(be32(&msg[offset..]), pen);
                    offset += ENTERPRISE_NUMBER_LEN;
                }
                None => {
                    assert_eq!(raw_id, field.id);
                    assert_eq!(raw_id & ENTERPRISE_BIT, 0, "no enterprise bit");
                }
            }
            record_size += length as usize;
        }

        assert_eq!(offset, msg.len(), "template set consumes the whole message");
        assert_eq!(record_size, 58);
    }

    #[test]
    fn record_fields_are_written_in_template_order() {
        let mut enc = encoder();
        enc.begin_message(false);
        assert!(enc.add_record(&event()));
        let record_size = enc.template.record_size;
        let (msg, _) = enc.finalize();

        // Data set header, then the record.
        assert_eq!(be16(&msg[16..18]), DEFAULT_TEMPLATE_ID);
        assert_eq!(be16(&msg[18..20]) as usize, SET_HEADER_LEN + record_size);

        let r = &msg[20..];
        assert_eq!(r.len(), record_size);
        assert_eq!(r[0], NAT44_SESSION_CREATE);
        assert_eq!(r[1], 6);
        assert_eq!(&r[2..6], &[192, 168, 1, 10]);
        assert_eq!(&r[6..10], &[8, 8, 8, 8]);
        assert_eq!(be16(&r[10..12]), 1234);
        assert_eq!(be16(&r[12..14]), 53);
        assert_eq!(&r[14..18], &[203, 0, 113, 5]);
        assert_eq!(be16(&r[18..20]), 40000);
        assert_eq!(&r[20..24], &[8, 8, 8, 8]);
        assert_eq!(be16(&r[24..26]), 53);
        assert_eq!(be64(&r[26..34]), 700, "octetDeltaCount");
        assert_eq!(be64(&r[34..42]), 7, "packetDeltaCount");
        assert_eq!(be64(&r[42..50]), 900, "reverseOctetDeltaCount");
        assert_eq!(be64(&r[50..58]), 9, "reversePacketDeltaCount");
    }

    #[test]
    fn a_delete_event_sets_the_delete_nat_event_code() {
        let mut enc = encoder();
        enc.begin_message(false);
        let mut ev = event();
        ev.nat_event = NatEventType::Delete;
        assert!(enc.add_record(&ev));
        let (msg, _) = enc.finalize();
        assert_eq!(msg[20], NAT44_SESSION_DELETE);
    }

    /// Fill a message and return (records accepted, encoded length).
    fn fill(include_template: bool) -> (u32, usize) {
        let mut enc = encoder();
        enc.begin_message(include_template);
        let mut accepted = 0;
        while enc.add_record(&event()) {
            accepted += 1;
            assert!(accepted < 1000, "add_record never reported the message full");
        }
        let (msg, count) = enc.finalize();
        assert_eq!(count, accepted);
        (accepted, msg.len())
    }

    #[test]
    fn a_full_message_stays_within_the_mtu_budget() {
        for include_template in [false, true] {
            let (records, len) = fill(include_template);
            assert!(records > 0);
            assert!(
                len <= MAX_MSG_SIZE,
                "{len} bytes exceeds the {MAX_MSG_SIZE} byte limit"
            );
            // One more record would not have fit.
            assert!(len + 58 > MAX_MSG_SIZE);
        }
    }

    #[test]
    fn a_template_leaves_room_for_fewer_records() {
        let (without, _) = fill(false);
        let (with, _) = fill(true);
        assert!(with < without);
    }

    #[test]
    fn a_rejected_record_fits_in_a_fresh_message() {
        let mut enc = encoder();
        enc.begin_message(false);
        while enc.add_record(&event()) {}
        enc.finalize();

        // This is the recovery path the worker takes when a message fills up.
        enc.begin_message(false);
        assert!(enc.add_record(&event()));
    }

    #[test]
    fn the_sequence_number_counts_records_sent_before_each_message() {
        let mut enc = encoder();

        enc.begin_message(false);
        assert!(enc.add_record(&event()));
        assert!(enc.add_record(&event()));
        let (msg, count) = enc.finalize();
        assert_eq!(count, 2);
        assert_eq!(be32(&msg[8..12]), 0);

        enc.begin_message(false);
        assert!(enc.add_record(&event()));
        let (msg, _) = enc.finalize();
        assert_eq!(be32(&msg[8..12]), 2, "counts records, not messages");

        // A template-only message carries no records and must not advance it.
        enc.begin_message(true);
        let (msg, count) = enc.finalize();
        assert_eq!(count, 0);
        assert_eq!(be32(&msg[8..12]), 3);

        enc.begin_message(false);
        assert!(enc.add_record(&event()));
        let (msg, _) = enc.finalize();
        assert_eq!(be32(&msg[8..12]), 3);
    }

    #[test]
    fn the_sequence_number_wraps_instead_of_overflowing() {
        let mut enc = encoder();
        enc.sequence_number = u32::MAX;
        enc.begin_message(false);
        assert!(enc.add_record(&event()));
        assert!(enc.add_record(&event()));
        enc.finalize();
        assert_eq!(enc.sequence_number, 1);
    }

    #[test]
    fn narrow_counters_clamp_instead_of_truncating() {
        let template =
            Template::resolve(Profile::Full, CounterWidth::Four, DEFAULT_TEMPLATE_ID).unwrap();
        let mut enc = Encoder::new(0, template);
        enc.begin_message(false);

        let mut ev = event();
        ev.orig_bytes = u64::MAX;
        ev.orig_packets = 5;
        assert!(enc.add_record(&ev));

        assert_eq!(enc.saturated_counters(), 1, "only the oversized counter");

        let (msg, _) = enc.finalize();
        let r = &msg[20..];
        assert_eq!(be32(&r[26..30]), u32::MAX, "clamped, not wrapped to a small value");
        assert_eq!(be32(&r[30..34]), 5);
    }
}
