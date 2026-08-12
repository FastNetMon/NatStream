use std::net::Ipv4Addr;

use log::debug;

use crate::event::{ConntrackEvent, NatEventType};

use super::constants::*;

/// Parse all conntrack messages from a netlink recv buffer.
/// Calls the callback for each valid NAT event found.
pub fn parse_conntrack_messages<F>(buf: &[u8], mut callback: F)
where
    F: FnMut(ConntrackEvent),
{
    let len = buf.len();
    let mut offset = 0;

    while offset + NLMSG_HDRLEN <= len {
        // Parse nlmsghdr: u32 len, u16 type, u16 flags, u32 seq, u32 pid
        let nlmsg_len = read_u32(&buf[offset..]) as usize;
        let nlmsg_type = read_u16(&buf[offset + 4..]);

        if nlmsg_len < NLMSG_HDRLEN + NFGENMSG_LEN || offset + nlmsg_len > len {
            break;
        }

        // Only conntrack messages carry the event layout parsed below. Without
        // this check the low byte alone decides, and NLMSG_ERROR (0x2) is
        // indistinguishable from IPCTNL_MSG_CT_DELETE, as is any message from
        // another nfnetlink subsystem whose type happens to collide.
        if nlmsg_type < NLMSG_MIN_TYPE || (nlmsg_type >> 8) != NFNL_SUBSYS_CTNETLINK {
            offset = nla_align(offset + nlmsg_len);
            continue;
        }

        // Determine event type from nlmsg_type subsystem message
        let msg_type = (nlmsg_type & 0xFF) as u8;
        let nat_event = match msg_type {
            IPCTNL_MSG_CT_NEW => NatEventType::Create,
            IPCTNL_MSG_CT_DELETE => NatEventType::Delete,
            _ => {
                offset = nla_align(offset + nlmsg_len);
                continue;
            }
        };

        // Parse nfgenmsg: u8 nfgen_family, u8 version, u16 res_id
        let nfgen_family = buf[offset + NLMSG_HDRLEN];

        // Only handle IPv4
        if nfgen_family != libc::AF_INET as u8 {
            offset = nla_align(offset + nlmsg_len);
            continue;
        }

        // Parse NLA tree
        let nla_start = offset + NLMSG_HDRLEN + NFGENMSG_LEN;
        let nla_end = offset + nlmsg_len;

        if let Some(event) = parse_nla_tree(nat_event, &buf[nla_start..nla_end]) {
            callback(event);
        }

        offset = nla_align(offset + nlmsg_len);
    }
}

/// Parse the NLA attribute tree within a single conntrack message.
fn parse_nla_tree(nat_event: NatEventType, data: &[u8]) -> Option<ConntrackEvent> {
    let mut src_ip = Ipv4Addr::UNSPECIFIED;
    let mut dst_ip = Ipv4Addr::UNSPECIFIED;
    let mut protocol: u8 = 0;
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut post_nat_src_ip = Ipv4Addr::UNSPECIFIED;
    let mut post_nat_src_port: u16 = 0;
    let mut post_nat_dst_ip = Ipv4Addr::UNSPECIFIED;
    let mut post_nat_dst_port: u16 = 0;
    let mut status: u32 = 0;
    let mut orig_bytes: u64 = 0;
    let mut orig_packets: u64 = 0;
    let mut reply_bytes: u64 = 0;
    let mut reply_packets: u64 = 0;
    let mut has_status = false;

    let mut offset = 0;
    while offset + NLA_HDRLEN <= data.len() {
        let nla_len = read_u16(&data[offset..]) as usize;
        let nla_type = read_u16(&data[offset + 2..]) & NLA_TYPE_MASK;

        if nla_len < NLA_HDRLEN || offset + nla_len > data.len() {
            break;
        }

        let payload = &data[offset + NLA_HDRLEN..offset + nla_len];

        match nla_type {
            CTA_TUPLE_ORIG => {
                parse_tuple(payload, &mut src_ip, &mut dst_ip, &mut protocol, &mut src_port, &mut dst_port);
            }
            CTA_TUPLE_REPLY => {
                // The reply tuple is the original tuple with both translations
                // applied and the direction swapped: its source is what the
                // destination was rewritten to, and its destination is what the
                // source was rewritten to. Either half is unchanged when that
                // direction is not translated.
                let mut _reply_proto: u8 = 0;
                parse_tuple(
                    payload,
                    &mut post_nat_dst_ip,
                    &mut post_nat_src_ip,
                    &mut _reply_proto,
                    &mut post_nat_dst_port,
                    &mut post_nat_src_port,
                );
            }
            CTA_STATUS => {
                if payload.len() >= 4 {
                    status = read_u32_be(payload);
                    has_status = true;
                }
            }
            CTA_COUNTERS_ORIG => {
                parse_counters(payload, &mut orig_bytes, &mut orig_packets);
            }
            CTA_COUNTERS_REPLY => {
                parse_counters(payload, &mut reply_bytes, &mut reply_packets);
            }
            _ => {}
        }

        offset = nla_align(offset + nla_len);
    }

    // Filter: must have status with NAT bits set
    if !has_status || (status & IPS_NAT_MASK) == 0 {
        debug!("Skipping non-NAT event (status=0x{:08x})", status);
        return None;
    }

    Some(ConntrackEvent {
        nat_event,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        post_nat_src_ip,
        post_nat_src_port,
        post_nat_dst_ip,
        post_nat_dst_port,
        orig_bytes,
        orig_packets,
        reply_bytes,
        reply_packets,
    })
}

/// Parse a CTA_TUPLE (ORIG or REPLY) nested attribute.
fn parse_tuple(
    data: &[u8],
    src_ip: &mut Ipv4Addr,
    dst_ip: &mut Ipv4Addr,
    protocol: &mut u8,
    src_port: &mut u16,
    dst_port: &mut u16,
) {
    let mut offset = 0;
    while offset + NLA_HDRLEN <= data.len() {
        let nla_len = read_u16(&data[offset..]) as usize;
        let nla_type = read_u16(&data[offset + 2..]) & NLA_TYPE_MASK;

        if nla_len < NLA_HDRLEN || offset + nla_len > data.len() {
            break;
        }

        let payload = &data[offset + NLA_HDRLEN..offset + nla_len];

        match nla_type {
            CTA_TUPLE_IP => {
                parse_tuple_ip(payload, src_ip, dst_ip);
            }
            CTA_TUPLE_PROTO => {
                parse_tuple_proto(payload, protocol, src_port, dst_port);
            }
            _ => {}
        }

        offset = nla_align(offset + nla_len);
    }
}

/// Parse CTA_TUPLE_IP nested attributes.
fn parse_tuple_ip(data: &[u8], src_ip: &mut Ipv4Addr, dst_ip: &mut Ipv4Addr) {
    let mut offset = 0;
    while offset + NLA_HDRLEN <= data.len() {
        let nla_len = read_u16(&data[offset..]) as usize;
        let nla_type = read_u16(&data[offset + 2..]) & NLA_TYPE_MASK;

        if nla_len < NLA_HDRLEN || offset + nla_len > data.len() {
            break;
        }

        let payload = &data[offset + NLA_HDRLEN..offset + nla_len];

        match nla_type {
            CTA_IP_V4_SRC if payload.len() >= 4 => {
                *src_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            }
            CTA_IP_V4_DST if payload.len() >= 4 => {
                *dst_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            }
            _ => {}
        }

        offset = nla_align(offset + nla_len);
    }
}

/// Parse CTA_TUPLE_PROTO nested attributes.
fn parse_tuple_proto(data: &[u8], protocol: &mut u8, src_port: &mut u16, dst_port: &mut u16) {
    let mut offset = 0;
    while offset + NLA_HDRLEN <= data.len() {
        let nla_len = read_u16(&data[offset..]) as usize;
        let nla_type = read_u16(&data[offset + 2..]) & NLA_TYPE_MASK;

        if nla_len < NLA_HDRLEN || offset + nla_len > data.len() {
            break;
        }

        let payload = &data[offset + NLA_HDRLEN..offset + nla_len];

        match nla_type {
            CTA_PROTO_NUM if !payload.is_empty() => *protocol = payload[0],
            CTA_PROTO_SRC_PORT if payload.len() >= 2 => *src_port = read_u16_be(payload),
            CTA_PROTO_DST_PORT if payload.len() >= 2 => *dst_port = read_u16_be(payload),
            _ => {}
        }

        offset = nla_align(offset + nla_len);
    }
}

/// Parse CTA_COUNTERS nested attributes.
fn parse_counters(data: &[u8], bytes: &mut u64, packets: &mut u64) {
    let mut offset = 0;
    while offset + NLA_HDRLEN <= data.len() {
        let nla_len = read_u16(&data[offset..]) as usize;
        let nla_type = read_u16(&data[offset + 2..]) & NLA_TYPE_MASK;

        if nla_len < NLA_HDRLEN || offset + nla_len > data.len() {
            break;
        }

        let payload = &data[offset + NLA_HDRLEN..offset + nla_len];

        match nla_type {
            CTA_COUNTERS_PACKETS if payload.len() >= 8 => *packets = read_u64_be(payload),
            CTA_COUNTERS_BYTES if payload.len() >= 8 => *bytes = read_u64_be(payload),
            _ => {}
        }

        offset = nla_align(offset + nla_len);
    }
}

// Helper functions for reading native-endian and network-byte-order integers

#[inline]
fn read_u16(data: &[u8]) -> u16 {
    u16::from_ne_bytes([data[0], data[1]])
}

#[inline]
fn read_u32(data: &[u8]) -> u32 {
    u32::from_ne_bytes([data[0], data[1], data[2], data[3]])
}

#[inline]
fn read_u16_be(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

#[inline]
fn read_u32_be(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

#[inline]
fn read_u64_be(data: &[u8]) -> u64 {
    u64::from_be_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}

#[inline]
fn nla_align(len: usize) -> usize {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}
