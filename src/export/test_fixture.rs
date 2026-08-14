use std::net::Ipv4Addr;

use crate::event::{ConntrackEvent, NatEventType};

pub(crate) fn event(protocol: u8) -> ConntrackEvent {
    ConntrackEvent {
        nat_event: NatEventType::Create,
        protocol,
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

pub(crate) fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

pub(crate) fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes[..4].try_into().unwrap())
}

pub(crate) fn be64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes[..8].try_into().unwrap())
}
