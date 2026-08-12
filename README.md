# spank_ipfixd

`spank_ipfixd` is a Linux daemon that exports conntrack NAT events as IPFIX (RFC 7011) records over UDP.

It listens to netlink conntrack notifications, extracts NAT-relevant flow fields, and sends them as IPFIX data records to a configured collector.

## What it does

- Subscribes to `NFNLGRP_CONNTRACK_NEW` and `NFNLGRP_CONNTRACK_DESTROY` on `NETLINK_NETFILTER`.
- Filters events to IPv4 NAT sessions (`IPS_SRC_NAT` or `IPS_DST_NAT`).
- Emits records for CREATE/DELETE flow events.
- Encodes records in a single fixed IPFIX template (ID `256`) and retransmits the template every 30 seconds.
- Flushes buffered IPFIX messages with:
  - immediate send when buffer is full
  - 100ms timeout flush for sparse traffic
- Supports a simple self-supervised daemon mode that restarts the worker process on crash.

## Requirements

- Linux (Netlink netfilter API required)
- Rust 1.85+ (project uses edition 2024)
- `CAP_NET_ADMIN` (or root) for netlink socket setup and buffer/socket options

## Build

```bash
cargo build             # debug
cargo build --release   # optimized release
```

Binary output is `target/debug/spank_ipfixd` or `target/release/spank_ipfixd`.

## Run

```bash
sudo ./target/release/spank_ipfixd --collector <IP>:<port>
```

Examples:

```bash
# Basic foreground mode
sudo ./target/release/spank_ipfixd --collector 203.0.113.10:4739

# Override buffers and domain id
sudo ./target/release/spank_ipfixd \
  --collector 203.0.113.10:4739 \
  --recv-buf 8388608 \
  --send-buf 8388608 \
  --domain-id 100

# Run with self-supervision and verbose logs
sudo ./target/release/spank_ipfixd --collector 203.0.113.10:4739 --daemon -v
```

## Command-line options

- `--collector <host:port>` (required): IPFIX collector endpoint.
- `--recv-buf <bytes>`: netlink receive buffer size (default: `4194304`).
- `--send-buf <bytes>`: UDP send buffer size (default: `4194304`).
- `--domain-id <u32>`: IPFIX observation domain ID (default: `0`).
- `-v`, `--verbose`: enable debug logging.
- `--daemon`: run as a background supervisor/worker pair with restart on worker crash.

## IPFIX record layout (12 fields)

1. `natEvent` (1)
2. `protocolIdentifier` (1)
3. `sourceIPv4Address` (4)
4. `destinationIPv4Address` (4)
5. `sourceTransportPort` (2)
6. `destinationTransportPort` (2)
7. `postNATSourceIPv4Address` (4)
8. `postNAPTSourceTransportPort` (2)
9. `octetDeltaCount` (8)
10. `packetDeltaCount` (8)
11. `postOctetDeltaCount` (8)
12. `postPacketDeltaCount` (8)

All counters are emitted per event using values read from conntrack counters.

## Notes

- Uses only a small set of dependencies and manual encoding/parsing for hot-path efficiency.
- Messages are capped to an MTU-safe size of 1472 bytes.
- Drop and error logging is emitted every 10 seconds for netlink drops and UDP send failures.

## License

No license file is present in this repository yet.
