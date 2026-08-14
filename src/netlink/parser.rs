use std::net::Ipv4Addr;

use log::debug;

use crate::event::{ConntrackEvent, NatEventType};

// A module of nothing but protocol constants, named after the RFC field
// they encode. Listing them individually would be a maintenance burden
// with nothing to show for it.
#[allow(clippy::wildcard_imports)]
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
        if nfgen_family != NFPROTO_IPV4 {
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
                parse_tuple(
                    payload,
                    &mut src_ip,
                    &mut dst_ip,
                    &mut protocol,
                    &mut src_port,
                    &mut dst_port,
                );
            }
            CTA_TUPLE_REPLY => {
                // The reply tuple is the original tuple with both translations
                // applied and the direction swapped: its source is what the
                // destination was rewritten to, and its destination is what the
                // source was rewritten to. Either half is unchanged when that
                // direction is not translated.
                // The reply tuple repeats the original's protocol; parse_tuple
                // needs somewhere to put it, and we have it already.
                let mut repeated_proto: u8 = 0;
                parse_tuple(
                    payload,
                    &mut post_nat_dst_ip,
                    &mut post_nat_src_ip,
                    &mut repeated_proto,
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
        debug!("Skipping non-NAT event (status=0x{status:08x})");
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

/// Parse a `CTA_TUPLE` (ORIG or REPLY) nested attribute.
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

/// Parse `CTA_TUPLE_IP` nested attributes.
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

/// Parse `CTA_TUPLE_PROTO` nested attributes.
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

/// Parse `CTA_COUNTERS` nested attributes.
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

#[cfg(test)]
mod tests {
    use super::*;

    mod fixture {
        use super::{
            CTA_COUNTERS_BYTES, CTA_COUNTERS_PACKETS, CTA_IP_V4_DST, CTA_IP_V4_SRC,
            CTA_PROTO_DST_PORT, CTA_PROTO_NUM, CTA_PROTO_SRC_PORT, CTA_TUPLE_IP, CTA_TUPLE_PROTO,
            NFNL_SUBSYS_CTNETLINK, NLA_ALIGNTO, NLA_HDRLEN, NLMSG_HDRLEN,
        };
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/netlink.rs"
        ));
    }
    use fixture::{attr, counters, ct_event, message, nested, tuple};

    fn parse(buf: &[u8]) -> Vec<ConntrackEvent> {
        let mut events = Vec::new();
        parse_conntrack_messages(buf, |event| events.push(event));
        events
    }

    /// SNAT: 192.168.1.10:1234 -> 8.8.8.8:53, source rewritten to 203.0.113.5:40000.
    #[rustfmt::skip] // the tuple pair reads as a table
    fn snat_event() -> Vec<u8> {
        ct_event(
            IPCTNL_MSG_CT_NEW,
            NFPROTO_IPV4,
            &[
                tuple(CTA_TUPLE_ORIG, [192, 168, 1, 10], [8, 8, 8, 8], 6, 1234, 53),
                tuple(CTA_TUPLE_REPLY, [8, 8, 8, 8], [203, 0, 113, 5], 6, 53, 40000),
                attr(CTA_STATUS, &IPS_SRC_NAT.to_be_bytes()),
                counters(CTA_COUNTERS_ORIG, 7, 700),
                counters(CTA_COUNTERS_REPLY, 9, 900),
            ],
        )
    }

    #[test]
    fn snat_event_reports_the_translated_source() {
        let events = parse(&snat_event());
        assert_eq!(events.len(), 1);
        let e = &events[0];

        assert_eq!(e.nat_event, NatEventType::Create);
        assert_eq!(e.protocol, 6);
        assert_eq!(e.src_ip, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(e.src_port, 1234);
        assert_eq!(e.dst_ip, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(e.dst_port, 53);

        // The reply tuple's destination is what the source was rewritten to.
        assert_eq!(e.post_nat_src_ip, Ipv4Addr::new(203, 0, 113, 5));
        assert_eq!(e.post_nat_src_port, 40000);
        // The destination was not translated, so it is unchanged.
        assert_eq!(e.post_nat_dst_ip, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(e.post_nat_dst_port, 53);

        assert_eq!(e.orig_packets, 7);
        assert_eq!(e.orig_bytes, 700);
        assert_eq!(e.reply_packets, 9);
        assert_eq!(e.reply_bytes, 900);
    }

    #[test]
    #[rustfmt::skip] // the tuple pair reads as a table
    fn dnat_event_reports_the_translated_destination() {
        // 10.0.0.1:5000 -> 203.0.113.1:80, destination rewritten to 10.0.0.99:8080.
        let buf = ct_event(
            IPCTNL_MSG_CT_NEW,
            NFPROTO_IPV4,
            &[
                tuple(CTA_TUPLE_ORIG, [10, 0, 0, 1], [203, 0, 113, 1], 6, 5000, 80),
                tuple(CTA_TUPLE_REPLY, [10, 0, 0, 99], [10, 0, 0, 1], 6, 8080, 5000),
                attr(CTA_STATUS, &IPS_DST_NAT.to_be_bytes()),
            ],
        );

        let events = parse(&buf);
        assert_eq!(events.len(), 1);
        let e = &events[0];

        assert_eq!(e.post_nat_dst_ip, Ipv4Addr::new(10, 0, 0, 99));
        assert_eq!(e.post_nat_dst_port, 8080);
        // The source was not translated, so it is reported unchanged rather
        // than being confused with the rewritten destination.
        assert_eq!(e.post_nat_src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(e.post_nat_src_port, 5000);
    }

    #[test]
    #[rustfmt::skip] // the tuple pair reads as a table
    fn delete_message_yields_a_delete_event() {
        let buf = ct_event(
            IPCTNL_MSG_CT_DELETE,
            NFPROTO_IPV4,
            &[
                tuple(CTA_TUPLE_ORIG, [192, 168, 1, 10], [8, 8, 8, 8], 17, 1234, 53),
                tuple(CTA_TUPLE_REPLY, [8, 8, 8, 8], [203, 0, 113, 5], 17, 53, 40000),
                attr(CTA_STATUS, &IPS_SRC_NAT.to_be_bytes()),
            ],
        );

        let events = parse(&buf);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].nat_event, NatEventType::Delete);
    }

    #[test]
    fn events_without_nat_status_are_filtered() {
        let buf = ct_event(
            IPCTNL_MSG_CT_NEW,
            NFPROTO_IPV4,
            &[
                tuple(CTA_TUPLE_ORIG, [10, 0, 0, 1], [10, 0, 0, 2], 6, 1000, 2000),
                tuple(CTA_TUPLE_REPLY, [10, 0, 0, 2], [10, 0, 0, 1], 6, 2000, 1000),
                attr(CTA_STATUS, &0x0000_0188u32.to_be_bytes()),
            ],
        );

        assert!(parse(&buf).is_empty());
    }

    #[test]
    fn events_missing_status_are_filtered() {
        let buf = ct_event(
            IPCTNL_MSG_CT_NEW,
            NFPROTO_IPV4,
            &[tuple(
                CTA_TUPLE_ORIG,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                6,
                1000,
                2000,
            )],
        );

        assert!(parse(&buf).is_empty());
    }

    #[test]
    #[rustfmt::skip] // the tuple pair reads as a table
    fn netlink_control_messages_are_not_events() {
        // NLMSG_ERROR is 0x2, the same low byte as IPCTNL_MSG_CT_DELETE. Without
        // a subsystem check this parses as a NAT session teardown.
        let buf = message(
            0x2,
            NFPROTO_IPV4,
            &[
                tuple(CTA_TUPLE_ORIG, [10, 0, 0, 1], [10, 0, 0, 2], 6, 1000, 2000),
                tuple(CTA_TUPLE_REPLY, [10, 0, 0, 2], [203, 0, 113, 9], 6, 2000, 1000),
                attr(CTA_STATUS, &IPS_SRC_NAT.to_be_bytes()),
            ],
        );

        assert!(parse(&buf).is_empty());
    }

    #[test]
    fn other_nfnetlink_subsystems_are_ignored() {
        // Subsystem 2 is the expectation table; its message type 0 would
        // otherwise look like IPCTNL_MSG_CT_NEW.
        let subsys_ctnetlink_exp: u16 = 2;
        let exp_msg_new: u16 = 0;
        let buf = message(
            (subsys_ctnetlink_exp << 8) | exp_msg_new,
            NFPROTO_IPV4,
            &[
                tuple(CTA_TUPLE_ORIG, [10, 0, 0, 1], [10, 0, 0, 2], 6, 1000, 2000),
                attr(CTA_STATUS, &IPS_SRC_NAT.to_be_bytes()),
            ],
        );

        assert!(parse(&buf).is_empty());
    }

    #[test]
    fn non_ipv4_events_are_skipped() {
        let buf = ct_event(
            IPCTNL_MSG_CT_NEW,
            NFPROTO_IPV6,
            &[attr(CTA_STATUS, &IPS_SRC_NAT.to_be_bytes())],
        );

        assert!(parse(&buf).is_empty());
    }

    #[test]
    fn several_messages_in_one_datagram_are_all_parsed() {
        let mut buf = snat_event();
        buf.extend_from_slice(&snat_event());
        buf.extend_from_slice(&snat_event());

        assert_eq!(parse(&buf).len(), 3);
    }

    #[test]
    fn a_truncated_datagram_yields_only_whole_messages() {
        let mut buf = snat_event();
        let whole = buf.len();
        buf.extend_from_slice(&snat_event());
        buf.truncate(whole + 24); // second message cut mid-attribute

        assert_eq!(parse(&buf).len(), 1);
    }

    #[test]
    fn malformed_input_does_not_panic() {
        // Every prefix of a valid datagram, plus some obvious garbage.
        let valid = snat_event();
        for len in 0..valid.len() {
            parse(&valid[..len]);
        }
        parse(&[0xFF; 64]);
        parse(&[0x00; 64]);

        // A message claiming a length shorter than its own header must not
        // send the parser backwards or into a loop.
        let mut short = snat_event();
        short[0..4].copy_from_slice(&4u32.to_ne_bytes());
        parse(&short);
    }

    #[test]
    fn attributes_with_short_payloads_are_ignored() {
        let buf = ct_event(
            IPCTNL_MSG_CT_NEW,
            NFPROTO_IPV4,
            &[
                nested(
                    CTA_TUPLE_ORIG,
                    &[nested(
                        CTA_TUPLE_IP,
                        &[
                            attr(CTA_IP_V4_SRC, &[10, 0]),
                            attr(CTA_IP_V4_DST, &[10, 0, 0, 2]),
                        ],
                    )],
                ),
                attr(CTA_STATUS, &IPS_SRC_NAT.to_be_bytes()),
            ],
        );

        let events = parse(&buf);
        assert_eq!(events.len(), 1);
        // The truncated source address is left at its default, not read past.
        assert_eq!(events[0].src_ip, Ipv4Addr::UNSPECIFIED);
        assert_eq!(events[0].dst_ip, Ipv4Addr::new(10, 0, 0, 2));
    }
}
