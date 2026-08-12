# conntrack_exporter

`conntrack_exporter` is a Linux daemon that exports conntrack NAT events as IPFIX (RFC 7011) records over UDP.

It listens to netlink conntrack notifications, extracts NAT-relevant flow fields, and sends them as IPFIX data records to a configured collector.

## What it does

- Subscribes to `NFNLGRP_CONNTRACK_NEW` and `NFNLGRP_CONNTRACK_DESTROY` on `NETLINK_NETFILTER`.
- Filters events to IPv4 NAT sessions (`IPS_SRC_NAT` or `IPS_DST_NAT`).
- Emits records for CREATE/DELETE flow events.
- Encodes records in a single fixed IPFIX template (ID `256`) and retransmits the template every 30 seconds, on its own message if no traffic is flowing.
- Flushes buffered IPFIX messages with:
  - immediate send when buffer is full
  - 100ms timeout flush for sparse traffic
- Supports a simple self-supervised daemon mode that restarts the worker process on crash, with exponential backoff.

## Requirements

- Linux (Netlink netfilter API required)
- Rust 1.85+ (project uses edition 2024)
- `CAP_NET_ADMIN` (or root) for netlink socket setup and buffer/socket options

On startup the exporter sets `nf_conntrack_events=1`, without which there are no
events to export at all, and `nf_conntrack_acct=1`, without which every counter
is zero. Failing to enable events is fatal; failing to enable accounting only
warns. Use `--no-sysctl` to leave both alone on hosts where they are already
configured or `/proc/sys` is read-only. Note that these settings are
net-namespace-wide and are not restored on exit.

## Build

```bash
cargo build             # debug
cargo build --release   # optimized release
cargo test              # unit tests for the parser and encoder
```

Binary output is `target/debug/conntrack_exporter` or `target/release/conntrack_exporter`.

## Run

```bash
sudo ./target/release/conntrack_exporter --collector <IP>:<port>
```

Examples:

```bash
# Basic foreground mode
sudo ./target/release/conntrack_exporter --collector 203.0.113.10:4739

# Override buffers and domain id
sudo ./target/release/conntrack_exporter \
  --collector 203.0.113.10:4739 \
  --recv-buf 8388608 \
  --send-buf 8388608 \
  --domain-id 100

# Run with self-supervision, a log file and verbose logs
sudo ./target/release/conntrack_exporter --collector 203.0.113.10:4739 \
  --daemon --log-file /var/log/conntrack_exporter.log -v
```

Under systemd, prefer `Type=simple` without `--daemon` and let journald capture
stderr, rather than the built-in supervisor.

## Command-line options

- `-c`, `--collector <ip:port>` (required): IPFIX collector endpoint.
- `--recv-buf <bytes>`: netlink receive buffer size (default: `4194304`).
- `--send-buf <bytes>`: UDP send buffer size (default: `4194304`).
- `--domain-id <u32>`: IPFIX observation domain ID (default: `0`).
- `-v`, `--verbose`: enable debug logging.
- `--daemon`: run as a background supervisor/worker pair with restart on worker crash.
- `--log-file <path>`: in `--daemon` mode, append log output here instead of discarding it.
- `--no-sysctl`: do not touch the `nf_conntrack` sysctls.

## IPFIX record layout (14 fields, 58 bytes)

| # | Information Element | ID | Bytes |
|---|---|---|---|
| 1 | `natEvent` | 230 | 1 |
| 2 | `protocolIdentifier` | 4 | 1 |
| 3 | `sourceIPv4Address` | 8 | 4 |
| 4 | `destinationIPv4Address` | 12 | 4 |
| 5 | `sourceTransportPort` | 7 | 2 |
| 6 | `destinationTransportPort` | 11 | 2 |
| 7 | `postNATSourceIPv4Address` | 225 | 4 |
| 8 | `postNAPTSourceTransportPort` | 227 | 2 |
| 9 | `postNATDestinationIPv4Address` | 226 | 4 |
| 10 | `postNAPTDestinationTransportPort` | 228 | 2 |
| 11 | `octetDeltaCount` | 1 | 8 |
| 12 | `packetDeltaCount` | 2 | 8 |
| 13 | `reverseOctetDeltaCount` | 1 + PEN 29305 | 8 |
| 14 | `reversePacketDeltaCount` | 2 + PEN 29305 | 8 |

Fields 7–10 come from the conntrack reply tuple, so SNAT, DNAT and combined
translations all report the address and port they actually rewrote; a direction
that was not translated simply repeats the original value.

Fields 13 and 14 are RFC 5103 reverse Information Elements, which is how a
bidirectional flow reports its reply direction. Collectors must handle
enterprise-specific field specifiers to decode them.

Counters come from the conntrack accounting counters, so they are zero on CREATE
events and hold the flow's totals on DELETE.

## Notes

- Uses only a small set of dependencies and manual encoding/parsing for hot-path efficiency.
- Messages are capped to an MTU-safe size of 1472 bytes.
- Every 10 seconds, any netlink drops, UDP send failures, truncated datagrams and
  messages from a non-kernel sender are logged.
- The daemon runs as root throughout; it does not yet drop privileges after
  opening its sockets.

## License

No license file is present in this repository yet.
