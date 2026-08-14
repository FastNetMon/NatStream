//! What the exporter can chew through, per second.
//!
//! The daemon's hot path is three steps: pull a datagram off the netlink
//! socket, decode the conntrack events in it, and encode those into export
//! messages. The two that cost CPU — decoding and encoding — are measured
//! here, together and apart, so a change can be weighed against a baseline.
//!
//!     cargo bench                          # everything
//!     cargo bench -- decode                # one group
//!     ./benches/compare.sh --save before   # the regression workflow
//!
//! What this deliberately does not measure is the `recvfrom` itself: its cost
//! is the kernel's, not ours, and it cannot be reproduced without a live
//! conntrack. `tests/e2e/throughput.py` covers that end of it against a real
//! kernel.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use conntrack_exporter::event::{ConntrackEvent, NatEventType};
use conntrack_exporter::export::elements::DEFAULT_TEMPLATE_ID;
use conntrack_exporter::export::template::{CounterWidth, Profile, Protocol, Template};
use conntrack_exporter::export::{Encoder, template};
use conntrack_exporter::netlink::constants::{
    CTA_COUNTERS_BYTES, CTA_COUNTERS_ORIG, CTA_COUNTERS_PACKETS, CTA_COUNTERS_REPLY, CTA_IP_V4_DST,
    CTA_IP_V4_SRC, CTA_PROTO_DST_PORT, CTA_PROTO_NUM, CTA_PROTO_SRC_PORT, CTA_STATUS, CTA_TUPLE_IP,
    CTA_TUPLE_ORIG, CTA_TUPLE_PROTO, CTA_TUPLE_REPLY, IPCTNL_MSG_CT_DELETE, IPCTNL_MSG_CT_NEW,
    IPS_SRC_NAT, NFNL_SUBSYS_CTNETLINK, NFPROTO_IPV4, NLA_ALIGNTO, NLA_HDRLEN, NLMSG_HDRLEN,
};
use conntrack_exporter::netlink::parse_conntrack_messages;

// ---- Building netlink datagrams as the kernel delivers them ----

const NLA_F_NESTED: u16 = 0x8000;

/// Conntrack status for a session that was never translated. The parser rejects
/// these on the status check, which is the cheapest path through it.
const IPS_ESTABLISHED_NO_NAT: u32 = 0x0000_0188;

fn attr(nla_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(NLA_HDRLEN + payload.len() + 3);
    let len = u16::try_from(NLA_HDRLEN + payload.len()).expect("attribute fits in u16");
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&nla_type.to_ne_bytes());
    out.extend_from_slice(payload);
    while out.len() % NLA_ALIGNTO != 0 {
        out.push(0);
    }
    out
}

fn nested(nla_type: u16, children: &[Vec<u8>]) -> Vec<u8> {
    attr(nla_type | NLA_F_NESTED, &children.concat())
}

fn tuple(nla_type: u16, src: [u8; 4], dst: [u8; 4], proto: u8, sport: u16, dport: u16) -> Vec<u8> {
    nested(
        nla_type,
        &[
            nested(
                CTA_TUPLE_IP,
                &[attr(CTA_IP_V4_SRC, &src), attr(CTA_IP_V4_DST, &dst)],
            ),
            nested(
                CTA_TUPLE_PROTO,
                &[
                    attr(CTA_PROTO_NUM, &[proto]),
                    attr(CTA_PROTO_SRC_PORT, &sport.to_be_bytes()),
                    attr(CTA_PROTO_DST_PORT, &dport.to_be_bytes()),
                ],
            ),
        ],
    )
}

fn counters(nla_type: u16, packets: u64, bytes: u64) -> Vec<u8> {
    nested(
        nla_type,
        &[
            attr(CTA_COUNTERS_PACKETS, &packets.to_be_bytes()),
            attr(CTA_COUNTERS_BYTES, &bytes.to_be_bytes()),
        ],
    )
}

fn message(nlmsg_type: u16, family: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![family, 0, 0, 0]; // nfgen_family, version, res_id
    body.extend_from_slice(&attrs.concat());

    let mut out = Vec::with_capacity(NLMSG_HDRLEN + body.len());
    let len = u32::try_from(NLMSG_HDRLEN + body.len()).expect("message fits in u32");
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&nlmsg_type.to_ne_bytes());
    out.extend_from_slice(&0u16.to_ne_bytes()); // flags
    out.extend_from_slice(&0u32.to_ne_bytes()); // seq
    out.extend_from_slice(&0u32.to_ne_bytes()); // pid
    out.extend_from_slice(&body);
    while out.len() % NLA_ALIGNTO != 0 {
        out.push(0);
    }
    out
}

fn ct_event(msg_type: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
    message(
        (NFNL_SUBSYS_CTNETLINK << 8) | u16::from(msg_type),
        NFPROTO_IPV4,
        attrs,
    )
}

/// A masqueraded session, varied by `index` so the benchmark is not measuring
/// one tuple's worth of branch prediction and cache residency.
fn nat_event(index: u32, msg_type: u8) -> Vec<u8> {
    let host = u8::try_from(index % 250 + 2).expect("bounded above");
    let port = u16::try_from(1024 + index % 60_000).expect("bounded above");
    let counted = msg_type == IPCTNL_MSG_CT_DELETE;

    let mut attrs = vec![
        tuple(
            CTA_TUPLE_ORIG,
            [192, 168, 1, host],
            [8, 8, 8, 8],
            6,
            port,
            443,
        ),
        tuple(
            CTA_TUPLE_REPLY,
            [8, 8, 8, 8],
            [203, 0, 113, 5],
            6,
            443,
            port ^ 0x5555,
        ),
        attr(CTA_STATUS, &IPS_SRC_NAT.to_be_bytes()),
    ];
    if counted {
        // Counters only carry anything on teardown, and the accounting
        // extension is only present when nf_conntrack_acct is on.
        attrs.push(counters(CTA_COUNTERS_ORIG, 12, 4_096));
        attrs.push(counters(CTA_COUNTERS_REPLY, 9, 60_000));
    }
    ct_event(msg_type, &attrs)
}

/// A session that was never translated: everything the exporter is not
/// interested in, which on a real box is most of the traffic.
fn plain_event(index: u32) -> Vec<u8> {
    let host = u8::try_from(index % 250 + 2).expect("bounded above");
    let port = u16::try_from(1024 + index % 60_000).expect("bounded above");
    ct_event(
        IPCTNL_MSG_CT_NEW,
        &[
            tuple(CTA_TUPLE_ORIG, [10, 0, 0, host], [10, 0, 1, 1], 6, port, 80),
            tuple(
                CTA_TUPLE_REPLY,
                [10, 0, 1, 1],
                [10, 0, 0, host],
                6,
                80,
                port,
            ),
            attr(CTA_STATUS, &IPS_ESTABLISHED_NO_NAT.to_be_bytes()),
        ],
    )
}

/// One recv buffer's worth. The kernel batches whatever is queued into a single
/// datagram, so a busy exporter sees many messages per `recvfrom`, not one.
///
/// `nat_in` gives the proportion that are NAT sessions: 1 for all of them, 4
/// for one in four.
fn datagram(events: usize, nat_in: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    for index in 0..u32::try_from(events).expect("event count fits in u32") {
        if index % nat_in == 0 {
            let msg_type = if index % (nat_in * 2) == 0 {
                IPCTNL_MSG_CT_NEW
            } else {
                IPCTNL_MSG_CT_DELETE
            };
            buf.extend_from_slice(&nat_event(index, msg_type));
        } else {
            buf.extend_from_slice(&plain_event(index));
        }
    }
    buf
}

fn sample_event() -> ConntrackEvent {
    ConntrackEvent {
        nat_event: NatEventType::Delete,
        protocol: 6,
        src_ip: "192.168.1.10".parse().expect("literal address"),
        dst_ip: "8.8.8.8".parse().expect("literal address"),
        src_port: 51_234,
        dst_port: 443,
        post_nat_src_ip: "203.0.113.5".parse().expect("literal address"),
        post_nat_src_port: 40_000,
        post_nat_dst_ip: "8.8.8.8".parse().expect("literal address"),
        post_nat_dst_port: 443,
        orig_bytes: 4_096,
        orig_packets: 12,
        reply_bytes: 60_000,
        reply_packets: 9,
    }
}

fn template_for(protocol: Protocol, profile: Profile, width: CounterWidth) -> Template {
    Template::resolve(protocol, profile, width, DEFAULT_TEMPLATE_ID).expect("a valid configuration")
}

/// Encode a batch the way the worker does, rolling over into a fresh message
/// whenever the current one fills up.
fn encode_batch(encoder: &mut Encoder, events: &[ConntrackEvent]) -> u32 {
    let mut messages = 1;
    encoder.begin_message(false);
    for event in events {
        if !encoder.add_record(event) {
            let (bytes, _) = encoder.finalize();
            black_box(bytes.len());
            messages += 1;
            encoder.begin_message(false);
            assert!(
                encoder.add_record(event),
                "a record must fit a fresh message"
            );
        }
    }
    let (bytes, _) = encoder.finalize();
    black_box(bytes.len());
    messages
}

// ---- Decoding ----

/// How fast conntrack events come out of a netlink datagram.
fn decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");

    for events in [1usize, 16, 128] {
        let elements = u64::try_from(events).expect("event count fits in u64");

        // Every event is a NAT session, so every one is decoded in full and
        // handed to the callback.
        let all_nat = datagram(events, 1);
        group.throughput(Throughput::Elements(elements));
        group.bench_with_input(BenchmarkId::new("all_nat", events), &all_nat, |b, buf| {
            b.iter(|| {
                let mut decoded = 0u32;
                parse_conntrack_messages(black_box(buf), |event| {
                    black_box(&event);
                    decoded += 1;
                });
                decoded
            });
        });

        // One in four, which is closer to a real box: most conntrack events are
        // not NAT and are rejected on the status check.
        let mixed = datagram(events, 4);
        group.throughput(Throughput::Elements(elements));
        group.bench_with_input(
            BenchmarkId::new("one_nat_in_four", events),
            &mixed,
            |b, buf| {
                b.iter(|| {
                    let mut decoded = 0u32;
                    parse_conntrack_messages(black_box(buf), |event| {
                        black_box(&event);
                        decoded += 1;
                    });
                    decoded
                });
            },
        );
    }

    // The reject path on its own: how cheaply an uninteresting event is thrown
    // away, which is what the exporter spends most of its time doing.
    let none_nat = datagram(128, u32::MAX);
    group.throughput(Throughput::Elements(128));
    group.bench_with_input(BenchmarkId::new("no_nat", 128), &none_nat, |b, buf| {
        b.iter(|| {
            let mut decoded = 0u32;
            parse_conntrack_messages(black_box(buf), |event| {
                black_box(&event);
                decoded += 1;
            });
            decoded
        });
    });

    group.finish();
}

// ---- Encoding ----

/// How fast decoded events turn into export messages, across every
/// configuration an operator can ask for.
fn encode(c: &mut Criterion) {
    const BATCH: usize = 256;
    let events = vec![sample_event(); BATCH];

    let mut group = c.benchmark_group("encode");
    group.throughput(Throughput::Elements(
        u64::try_from(BATCH).expect("batch fits in u64"),
    ));

    for protocol in [Protocol::Ipfix, Protocol::Netflow9] {
        for profile in [Profile::Full, Profile::NatSource, Profile::FlowOnly] {
            for width in [CounterWidth::Eight, CounterWidth::Four] {
                let template = template_for(protocol, profile, width);
                let label = format!(
                    "{}/{}/{}B",
                    match protocol {
                        Protocol::Ipfix => "ipfix",
                        Protocol::Netflow9 => "netflow9",
                    },
                    match profile {
                        Profile::Full => "full",
                        Profile::NatSource => "nat-source",
                        Profile::FlowOnly => "flow-only",
                    },
                    width.bytes(),
                );

                group.bench_function(BenchmarkId::new("batch", label), |b| {
                    let mut encoder = Encoder::new(0, template.clone());
                    b.iter(|| encode_batch(&mut encoder, black_box(&events)));
                });
            }
        }
    }
    group.finish();

    // A template-only message, which goes out on every retransmit interval even
    // when there is no traffic at all.
    let mut group = c.benchmark_group("encode_template");
    for protocol in [Protocol::Ipfix, Protocol::Netflow9] {
        let template = template_for(protocol, Profile::Full, CounterWidth::Eight);
        let name = match protocol {
            Protocol::Ipfix => "ipfix",
            Protocol::Netflow9 => "netflow9",
        };
        group.bench_function(name, |b| {
            let mut encoder = Encoder::new(0, template.clone());
            b.iter(|| {
                encoder.begin_message(true);
                let (bytes, _) = encoder.finalize();
                black_box(bytes.len())
            });
        });
    }
    group.finish();
}

// ---- Both together ----

/// The whole CPU path: a datagram in, finished export messages out. This is the
/// number that says how many conntrack events per second the exporter can keep
/// up with, short of the kernel's own costs.
fn pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline");

    for events in [16usize, 128] {
        for nat_in in [1u32, 4] {
            let buf = datagram(events, nat_in);
            group.throughput(Throughput::Elements(
                u64::try_from(events).expect("event count fits in u64"),
            ));

            for (protocol, width, name) in [
                (Protocol::Ipfix, CounterWidth::Eight, "ipfix"),
                (Protocol::Netflow9, CounterWidth::Four, "netflow9"),
            ] {
                let template = template_for(protocol, Profile::Full, width);
                let label = format!("{name}/1_in_{nat_in}");

                group.bench_with_input(BenchmarkId::new(label, events), &buf, |b, buf| {
                    let mut encoder = Encoder::new(0, template.clone());
                    b.iter(|| {
                        let mut decoded = Vec::with_capacity(events);
                        parse_conntrack_messages(black_box(buf), |event| decoded.push(event));
                        encode_batch(&mut encoder, &decoded)
                    });
                });
            }
        }
    }

    group.finish();
}

// ---- Resolving a configuration ----

/// Startup work, benchmarked because it is cheap to keep an eye on rather than
/// because it is hot: it happens once.
fn resolve(c: &mut Criterion) {
    c.bench_function("template/resolve", |b| {
        b.iter(|| {
            template_for(
                black_box(Protocol::Ipfix),
                black_box(Profile::Full),
                black_box(CounterWidth::Eight),
            )
        });
    });

    c.bench_function("template/max_records_per_message", |b| {
        let template = template_for(Protocol::Netflow9, Profile::Full, CounterWidth::Eight);
        b.iter(|| black_box(&template).max_records_per_message());
    });

    c.bench_function("template/align_up", |b| {
        b.iter(|| template::align_up(black_box(1471), black_box(4)));
    });
}

criterion_group!(benches, decode, encode, pipeline, resolve);
criterion_main!(benches);
