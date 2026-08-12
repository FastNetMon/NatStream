use std::fmt;
use std::net::Ipv4Addr;

use crate::ipfix::constants::{NAT44_SESSION_CREATE, NAT44_SESSION_DELETE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatEventType {
    Create,
    Delete,
}

impl NatEventType {
    pub fn as_ipfix_value(self) -> u8 {
        match self {
            NatEventType::Create => NAT44_SESSION_CREATE,
            NatEventType::Delete => NAT44_SESSION_DELETE,
        }
    }
}

impl fmt::Display for NatEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NatEventType::Create => write!(f, "CREATE"),
            NatEventType::Delete => write!(f, "DELETE"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConntrackEvent {
    pub nat_event: NatEventType,
    pub protocol: u8,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub post_nat_src_ip: Ipv4Addr,
    pub post_nat_src_port: u16,
    pub orig_bytes: u64,
    pub orig_packets: u64,
    pub reply_bytes: u64,
    pub reply_packets: u64,
}

impl fmt::Display for ConntrackEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} proto={} {}:{} -> {}:{} nat={}:{} orig={}/{} reply={}/{}",
            self.nat_event,
            self.protocol,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.post_nat_src_ip,
            self.post_nat_src_port,
            self.orig_bytes,
            self.orig_packets,
            self.reply_bytes,
            self.reply_packets,
        )
    }
}
