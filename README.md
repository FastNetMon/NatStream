# NatStream

NatStream is a Linux daemon that exports conntrack NAT events as IPFIX (RFC 7011) or NetFlow v9 (RFC 3954) records over UDP.

It listens to netlink conntrack notifications, extracts NAT-relevant flow fields, and sends them as flow records to a configured collector.

Upstream: <https://github.com/FastNetMon/NatStream>

## Install (Debian / Ubuntu)

Every release publishes a `.deb` per target distribution, with a `SHA256SUMS`
alongside them:
<https://github.com/FastNetMon/NatStream/releases/latest>.

To build one yourself, `./build.sh` produces a `.deb` for a target
distribution, inside a Docker container based on that distribution. No build
tooling is needed on the host beyond Docker. This is the same script the
release workflow runs, so a locally built package is the packaged one.

```bash
./build.sh trixie      # Debian 13        -> dist/natstream_*~deb13_*.deb
./build.sh 24.04       # Ubuntu 24.04 LTS -> dist/natstream_*~ubuntu24.04_*.deb
./build.sh 26.04       # Ubuntu 26.04 LTS -> dist/natstream_*~ubuntu26.04_*.deb
./build.sh all         # all three
```

The Rust toolchain is pinned (`RUST_VERSION`, default 1.97.1) and installed in the
container, because the distros' own `rustc` is not usable across all targets —
Ubuntu 24.04 ships 1.75 and this crate needs 1.85+ for edition 2024. Each target
links its own distro's glibc and gets a `libc6` dependency derived from the
binary with `dpkg-shlibdeps`, rather than a guess. In practice the binary
currently only needs `GLIBC_2.34`, so the three are interchangeable today; the
per-distro build is what keeps that true if it ever stops being.

Override the packaging metadata with `MAINTAINER=`, `DEB_REVISION=` and
`RUST_VERSION=` in the environment. `./build.sh --help` lists everything.

### The package

| Path | |
|---|---|
| `/usr/sbin/natstream` | the daemon |
| `/lib/systemd/system/natstream.service` | the service unit |
| `/etc/default/natstream` | configuration (a dpkg conffile) |

Installing does **not** enable or start the service, because it has no useful
default collector and would only produce a restart loop. Configure it first:

```bash
sudo dpkg -i natstream_0.1.0-1~deb13_amd64.deb
sudoedit /etc/default/natstream        # set COLLECTOR=ip:port
sudo systemctl enable --now natstream.service
journalctl -u natstream -f
```

`/etc/default/natstream` holds the collector endpoint and any extra
flags:

```sh
COLLECTOR=203.0.113.10:4739
EXPORTER_OPTS=--protocol netflow9 --profile nat-source --counter-width 4
```

### The service

The unit runs the daemon in the foreground under `Type=simple` and lets journald
take its output — systemd supervises it, so the daemon's own `--daemon`
supervisor is not used and would only get in the way.

It does **not run as root**. The exporter needs `CAP_NET_ADMIN` to join the
conntrack netlink group, force its socket buffer sizes, and set the
`nf_conntrack` sysctls — the kernel's net sysctl handler grants `CAP_NET_ADMIN`
holders owner-level access, so no root and no `CAP_DAC_OVERRIDE` are required.
The unit therefore uses `DynamicUser=yes` with exactly that one capability,
plus the usual sandboxing (`ProtectHome`, `PrivateDevices`, `ProtectProc`,
`RestrictAddressFamilies=AF_NETLINK AF_INET AF_INET6`, a `@system-service`
syscall filter, and no new privileges). `systemd-analyze security` rates it 2.6.

One directive is deliberately absent: `ProtectKernelTunables=yes` would remount
`/proc/sys` read-only and break the sysctl setup the exporter does at startup.
If you would rather lock that down, set the two sysctls declaratively in
`/etc/sysctl.d/`, add `--no-sysctl` to `EXPORTER_OPTS`, and then add
`ProtectKernelTunables=yes` to a unit override.

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
cargo test              # unit and integration tests
cargo fmt --check       # formatting
cargo clippy            # lints
```

Binary output is `target/debug/natstream` or `target/release/natstream`.

Clippy's `pedantic` lint set lives in `Cargo.toml`. CI checks every target and
treats warnings as errors with `cargo clippy --all-targets -- -D warnings`. The
casts that a wire format necessarily makes are annotated where they are, with
the bound that makes each one safe; the few places where the layout of the
source is doing the explaining carry `#[rustfmt::skip]`.

## Releasing

A release is a tag. `.github/workflows/release.yml` builds one `.deb` per
target with `./build.sh`, then publishes them to a GitHub release:

```bash
# Cargo.toml's version must already say 0.2.0 on the commit being tagged.
git tag -a 0.2.0 -m 'NatStream 0.2.0'
git push origin 0.2.0
```

`0.2.0` and `v0.2.0` both trigger it, since the repository has tags of each
kind. The workflow refuses to build if the tag and `Cargo.toml` disagree, so a
mismatch costs a failed job rather than a wrong package. A version with a
suffix (`0.2.0-rc1`) is published as a pre-release.

Before publishing, the Ubuntu 24.04 package is installed and purged on the
runner, which is the same distribution: a maintainer script that fails, a
binary that will not run, or an install that enables the service fails the
build. The release carries the packages and a `SHA256SUMS` over them.

Running the workflow by hand from the Actions tab builds all three packages and
leaves them as workflow artifacts without publishing anything, which is how to
exercise the packaging path without spending a tag. Giving it a tag instead
builds that tag and attaches the packages to its release, which is how a tag
pushed before this workflow existed gets its packages:

```bash
gh workflow run release.yml --ref master -f tag=0.1.0
```

An existing release keeps its notes; only the packages are attached.

Set the `DEB_MAINTAINER` repository variable to a real `Name <email>`;
without it the packages carry the placeholder maintainer from
`packaging/build-deb.sh`.

## Benchmarks

```bash
cargo bench                  # everything
cargo bench -- decode        # one group
```

The benchmarks measure the two steps that cost CPU — decoding a netlink
datagram into conntrack events, and encoding those into export messages —
separately and together, across every protocol, profile and counter width.
Decoding is measured with all events translated, with one in four translated,
and with none, because rejecting an event the exporter does not care about is
the common case and the cheapest path through the parser.

They deliberately do not measure the `recvmmsg` receive itself: its cost
includes the kernel and cannot be reproduced without a live conntrack.

### Checking a change for regressions

Criterion baselines make the before/after comparison a two-step affair. The
gate is on the lower bound of the confidence interval, so a regression has to
be one the statistics are confident about before it fails:

```bash
./benches/compare.sh --save before      # on the unchanged tree
                                        # ...make the change...
./benches/compare.sh --against before   # exits non-zero if anything got slower
```

`--threshold PCT` sets what counts as a regression (default 5%), `--filter EXPR`
narrows it to some of the benchmarks, and `--list` shows the saved baselines.
Results are only as steady as the machine underneath them; for numbers worth
arguing over, pin the CPU governor to performance.

### What it can take from a real kernel

The microbenchmarks say how fast the code is, not whether the daemon keeps up
with a kernel that is actually producing events. That needs the real thing:

```bash
cargo build --release
./tests/e2e/run-netns.sh --throughput
```

It creates tens of thousands of NAT sessions in a namespace, tears them all
down, and reports what was offered, what the kernel had to drop because the
exporter did not drain its socket in time, and what the collector received.
The netlink drop count is the one that answers the question — records received
is a floor, since a Python collector on loopback is the slower end.

Treat it as a sizing exercise rather than a regression gate: the load is an
instantaneous burst, harsher than real traffic, and the result moves with the
machine. Build for release first, or the number says more about `-O0` than
about the exporter.

## Run

```bash
sudo ./target/release/natstream --collector <IP>:<port>
```

Examples:

```bash
# Basic foreground mode
sudo ./target/release/natstream --collector 203.0.113.10:4739

# Override buffers and domain id
sudo ./target/release/natstream \
  --collector 203.0.113.10:4739 \
  --recv-buf 8388608 \
  --send-buf 8388608 \
  --domain-id 100

# NetFlow v9 to a collector that only decodes the base field registry
sudo ./target/release/natstream \
  --collector 203.0.113.10:2055 \
  --protocol netflow9 \
  --profile flow-only \
  --counter-width 4

# Run with self-supervision, a log file and verbose logs
sudo ./target/release/natstream --collector 203.0.113.10:4739 \
  --daemon --log-file /var/log/natstream.log -v
```

Under systemd, prefer `Type=simple` without `--daemon` and let journald capture
stderr, rather than the built-in supervisor.

## Command-line options

- `-c`, `--collector <ip:port>` (required): flow collector endpoint.
- `--protocol <ipfix|netflow9>`: export protocol (default: `ipfix`).
- `--profile <full|nat-source|flow-only>`: which field set to export (default: `full`).
- `--counter-width <4|8>`: byte and packet counter width (default: `8`).
- `--template-id <u16>`: template ID to advertise (default: `256`, minimum `256`).
- `--template-interval <secs>`: seconds between template retransmissions (default: `30`).
- `--domain-id <u32>`: observation domain ID / NetFlow v9 source ID (default: `0`).
- `--recv-buf <bytes>`: netlink receive buffer size (default: `4194304`).
- `--send-buf <bytes>`: UDP send buffer size (default: `4194304`).
- `-v`, `--verbose`: enable debug logging.
- `--daemon`: run as a background supervisor/worker pair with restart on worker crash.
- `--log-file <path>`: in `--daemon` mode, append log output here instead of discarding it.
- `--no-sysctl`: do not touch the `nf_conntrack` sysctls.

The effective configuration is logged at startup, including the record size and
how many records fit in a message.

## Protocol and profiles

The NAT elements this exporter relies on — `natEvent` and the four `postNAT*`
elements — are IPFIX registry entries and are **not** in RFC 3954's NetFlow v9
field table. They are a Cisco NAT Event Logging convention there. Support
varies by collector and by collector version, which is what the profiles are
for: pick the largest field set your collector actually decodes.

| Profile | Fields | Record (8B / 4B counters) | Carries |
|---|---|---|---|
| `full` | 14 | 58 B / 42 B | Both NAT directions and both counter directions |
| `nat-source` | 12 | 52 B / 36 B | Source translation only; drops `postNATDestination*` |
| `flow-only` | 9 | 45 B / 29 B | **No NAT information at all** — pre-NAT five-tuple and counters only |

Rough starting points, worth confirming against your own version: pmacct
(`nfacctd`) and nfdump 1.7+ handle `full`; ntopng and NEL-aware commercial
collectors generally do too. Collectors limited to their base registry need
`flow-only`, which is a real loss of information — it exports the flow but not
the translation. Use `tshark -d udp.port==<port>,cflow -V` to see exactly what a
dissector makes of your export before blaming a collector.

`--counter-width 4` exists because NetFlow v9's `IN_BYTES`/`OUT_BYTES` default to
four bytes and some collectors expect exactly that. Conntrack counters are 64-bit,
so a value too large for a four-byte field is **clamped, not truncated**, and the
clamp count is reported in the periodic stats line.

## Record layout

Both protocols carry the same field values in the same order; they differ only in
how the elements are identified.

| # | Field | IPFIX IE | NetFlow v9 type | Bytes | Profiles |
|---|---|---|---|---|---|
| 1 | `natEvent` | 230 | 230 | 1 | full, nat-source |
| 2 | `protocolIdentifier` | 4 | 4 `PROTOCOL` | 1 | all |
| 3 | `sourceIPv4Address` | 8 | 8 `IPV4_SRC_ADDR` | 4 | all |
| 4 | `destinationIPv4Address` | 12 | 12 `IPV4_DST_ADDR` | 4 | all |
| 5 | `sourceTransportPort` | 7 | 7 `L4_SRC_PORT` | 2 | all |
| 6 | `destinationTransportPort` | 11 | 11 `L4_DST_PORT` | 2 | all |
| 7 | `postNATSourceIPv4Address` | 225 | 225 | 4 | full, nat-source |
| 8 | `postNAPTSourceTransportPort` | 227 | 227 | 2 | full, nat-source |
| 9 | `postNATDestinationIPv4Address` | 226 | 226 | 4 | full |
| 10 | `postNAPTDestinationTransportPort` | 228 | 228 | 2 | full |
| 11 | `octetDeltaCount` | 1 | 1 `IN_BYTES` | 4 or 8 | all |
| 12 | `packetDeltaCount` | 2 | 2 `IN_PKTS` | 4 or 8 | all |
| 13 | reply octets | 1 + PEN 29305 | 23 `OUT_BYTES` | 4 or 8 | all |
| 14 | reply packets | 2 + PEN 29305 | 24 `OUT_PKTS` | 4 or 8 | all |

Fields 7–10 come from the conntrack reply tuple, so SNAT, DNAT and combined
translations all report the address and port they actually rewrote; a direction
that was not translated simply repeats the original value.

Fields 13 and 14 report the flow's reply direction. Under IPFIX that is an RFC
5103 reverse Information Element, so the collector must handle enterprise-specific
field specifiers. NetFlow v9 has no enterprise mechanism, so it uses the dedicated
`OUT_BYTES`/`OUT_PKTS` types instead. Note these are *not* interchangeable: IEs
23/24 under IPFIX mean `postOctetDeltaCount`/`postPacketDeltaCount`, the forward
direction as modified by a middlebox, which is a different quantity.

Counters come from the conntrack accounting counters, so they are zero on CREATE
events and hold the flow's totals on DELETE.

## Notes

- Uses only a small set of dependencies and manual encoding/parsing for hot-path efficiency.
- Messages are capped to an MTU-safe size of 1472 bytes. NetFlow v9 FlowSets are
  padded to a 4-byte boundary as RFC 3954 asks.
- One process speaks one protocol to one collector. Two collectors means two
  instances, and each is a separate netlink multicast subscriber, so the kernel
  copies every conntrack event once per instance.
- Every 10 seconds, any netlink drops, UDP send failures, truncated datagrams and
  messages from a non-kernel sender are logged.
- The daemon runs as root throughout; it does not yet drop privileges after
  opening its sockets.

## License

Copyright 2026 FastNetMon LTD.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the
full text and [NOTICE](NOTICE) for the copyright notice, or
<https://www.apache.org/licenses/LICENSE-2.0>.
