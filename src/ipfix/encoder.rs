use std::time::{SystemTime, UNIX_EPOCH};

use crate::event::ConntrackEvent;

use super::constants::*;
use super::template::{template_set_size, NAT_TEMPLATE_FIELDS};

/// Pre-allocated IPFIX message encoder.
pub struct IpfixEncoder {
    buf: [u8; MAX_IPFIX_MSG_SIZE],
    offset: usize,
    record_count: u32,
    data_set_offset: usize,
    sequence_number: u32,
    observation_domain_id: u32,
}

impl IpfixEncoder {
    pub fn new(observation_domain_id: u32) -> Self {
        IpfixEncoder {
            buf: [0u8; MAX_IPFIX_MSG_SIZE],
            offset: 0,
            record_count: 0,
            data_set_offset: 0,
            sequence_number: 0,
            observation_domain_id,
        }
    }

    /// Begin a new IPFIX message. If `include_template` is true, the template set
    /// is written first. The data set header is always written.
    pub fn begin_message(&mut self, include_template: bool) {
        self.offset = 0;
        self.record_count = 0;

        // Reserve space for IPFIX message header (filled in finalize)
        self.offset = IPFIX_HEADER_LEN;

        // Write template set if requested
        if include_template {
            self.write_template_set();
        }

        // Write data set header (set_id = template ID, length = placeholder)
        self.data_set_offset = self.offset;
        self.write_u16(NAT_TEMPLATE_ID); // set ID
        self.write_u16(0); // length placeholder
    }

    /// Try to add a record to the current message. Returns false if the message
    /// is full and the record was not added.
    pub fn add_record(&mut self, event: &ConntrackEvent) -> bool {
        if self.offset + DATA_RECORD_SIZE > MAX_IPFIX_MSG_SIZE {
            return false;
        }

        // natEvent (1 byte)
        self.buf[self.offset] = event.nat_event.as_ipfix_value();
        self.offset += 1;

        // protocolIdentifier (1 byte)
        self.buf[self.offset] = event.protocol;
        self.offset += 1;

        // sourceIPv4Address (4 bytes)
        self.write_ipv4(event.src_ip);

        // destinationIPv4Address (4 bytes)
        self.write_ipv4(event.dst_ip);

        // sourceTransportPort (2 bytes)
        self.write_u16(event.src_port);

        // destinationTransportPort (2 bytes)
        self.write_u16(event.dst_port);

        // postNATSourceIPv4Address (4 bytes)
        self.write_ipv4(event.post_nat_src_ip);

        // postNAPTSourceTransportPort (2 bytes)
        self.write_u16(event.post_nat_src_port);

        // octetDeltaCount (8 bytes)
        self.write_u64(event.orig_bytes);

        // packetDeltaCount (8 bytes)
        self.write_u64(event.orig_packets);

        // reverseOctetDeltaCount (8 bytes)
        self.write_u64(event.reply_bytes);

        // reversePacketDeltaCount (8 bytes)
        self.write_u64(event.reply_packets);

        self.record_count += 1;
        true
    }

    /// Returns true if at least one record has been added.
    pub fn has_records(&self) -> bool {
        self.record_count > 0
    }

    /// Finalize the message: fill in IPFIX header and data set length.
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

        // Fill data set length
        let data_set_len = (self.offset - self.data_set_offset) as u16;
        self.buf[self.data_set_offset + 2..self.data_set_offset + 4]
            .copy_from_slice(&data_set_len.to_be_bytes());

        // Update sequence number (cumulative record count)
        let count = self.record_count;
        self.sequence_number += count;

        (&self.buf[..self.offset], count)
    }

    fn write_template_set(&mut self) {
        let set_len = template_set_size() as u16;

        // Set header: set_id=2 (template), length
        self.write_u16(TEMPLATE_SET_ID);
        self.write_u16(set_len);

        // Template record header: template_id, field_count
        self.write_u16(NAT_TEMPLATE_ID);
        self.write_u16(TEMPLATE_FIELD_COUNT);

        // Field specifiers. Enterprise-specific elements set the enterprise bit
        // in the IE ID and append the Private Enterprise Number.
        for field in NAT_TEMPLATE_FIELDS {
            match field.enterprise {
                Some(pen) => {
                    self.write_u16(field.ie_id | ENTERPRISE_BIT);
                    self.write_u16(field.length);
                    self.write_u32(pen);
                }
                None => {
                    self.write_u16(field.ie_id);
                    self.write_u16(field.length);
                }
            }
        }
    }

    #[inline]
    fn write_u16(&mut self, val: u16) {
        self.buf[self.offset..self.offset + 2].copy_from_slice(&val.to_be_bytes());
        self.offset += 2;
    }

    #[inline]
    fn write_u32(&mut self, val: u32) {
        self.buf[self.offset..self.offset + 4].copy_from_slice(&val.to_be_bytes());
        self.offset += 4;
    }

    #[inline]
    fn write_u64(&mut self, val: u64) {
        self.buf[self.offset..self.offset + 8].copy_from_slice(&val.to_be_bytes());
        self.offset += 8;
    }

    #[inline]
    fn write_ipv4(&mut self, addr: std::net::Ipv4Addr) {
        self.buf[self.offset..self.offset + 4].copy_from_slice(&addr.octets());
        self.offset += 4;
    }
}
