"""How many real conntrack events per second the exporter keeps up with.

The benchmarks in `benches/` measure decoding and encoding on synthetic
buffers, which is what you want for spotting a regression: it is repeatable and
nothing else is in the way. What they cannot tell you is whether the daemon
keeps up with a kernel that is actually producing events — that involves the
netlink socket, the receive buffer, the scheduler and the collector, none of
which exist in a microbenchmark.

This drives a real conntrack as hard as it can from inside a network namespace
and reports three things separately, because they fail for different reasons:

    events offered    what the kernel actually produced, counted from the
                      conntrack table rather than from what we asked for
    netlink drops     events the kernel could not hand over, because the
                      exporter did not drain its socket fast enough. This is
                      the number that says whether ingest kept up
    records received  what this test's collector decoded, which is a floor:
                      a Python collector on loopback is easily the slow end

Build for release before reading anything into the result. A debug build is
several times slower and drops correspondingly more.

This is a load test, not a benchmark. The figure moves with the machine, the
kernel and whatever else is running, and the load it generates is a burst —
tens of thousands of sessions created at once and torn down at once — which is
harsher than real traffic. Use it to size things, not to gate a change; that is
what `benches/` is for.
"""

import argparse
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flowdecode import Collector  # noqa: E402
from natflow import (  # noqa: E402
    CLIENT_IP,
    COLLECTOR_HOST,
    COLLECTOR_PORT,
    REAL_IP,
    REAL_PORT,
    VIRTUAL_IP,
    VIRTUAL_PORT,
    Failure,
    flush_conntrack,
    run,
    setup_nat,
)
from netns_smoke import Exporter  # noqa: E402


def generate_load(sessions, duration):
    """Create as many NAT'd sessions as we can, and return how many.

    Each one is a datagram to the virtual address from a fresh source port,
    which the DNAT rule rewrites — so each is a new conntrack entry and a NEW
    event, and the flush at the end turns every one into a DESTROY event.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((REAL_IP, REAL_PORT))
    server.setblocking(False)

    # Drain the server socket so its receive queue cannot fill and start
    # dropping, which would stall the sender.
    stop = threading.Event()

    def drain():
        while not stop.is_set():
            try:
                server.recvfrom(65535)
            except (BlockingIOError, OSError):
                time.sleep(0.0005)

    drainer = threading.Thread(target=drain, daemon=True)
    drainer.start()

    created = 0
    deadline = time.monotonic() + duration
    try:
        while created < sessions and time.monotonic() < deadline:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                client.bind((CLIENT_IP, 0))
                client.sendto(b"x", (VIRTUAL_IP, VIRTUAL_PORT))
                created += 1
            except OSError:
                # Ephemeral ports exhausted, or the socket table is full.
                time.sleep(0.01)
            finally:
                client.close()
    finally:
        stop.set()
        drainer.join(timeout=1)
        server.close()

    return created


def conntrack_count():
    """Live conntrack entries in this namespace."""
    with open("/proc/sys/net/netfilter/nf_conntrack_count") as handle:
        return int(handle.read().strip())


def read_exporter_drops(exporter):
    """The netlink drops the exporter reported in its periodic stats line."""
    drops = 0
    for line in exporter.log:
        if "nl_recv=" not in line or "total:" not in line:
            continue
        totals = line.split("total:", 1)[1]
        for field in totals.replace(")", "").split():
            if field.startswith("nl_recv="):
                drops = max(drops, int(field.split("=", 1)[1]))
    return drops


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exporter", required=True, help="path to the binary")
    parser.add_argument("--sessions", type=int, default=20000,
                        help="how many NAT sessions to create (default 20000)")
    parser.add_argument("--duration", type=float, default=20,
                        help="give up generating load after this long")
    parser.add_argument("--settle", type=float, default=15,
                        help="seconds to wait for the exporter to drain and "
                             "report; must exceed its 10s stats interval")
    parser.add_argument("--protocol", default="ipfix", choices=["ipfix", "netflow9"])
    parser.add_argument("--profile", default="full",
                        choices=["full", "nat-source", "flow-only"])
    args = parser.parse_args()

    if "debug" in os.path.normpath(args.exporter).split(os.sep):
        print("warning: this is a debug build; it drops several times more than\n"
              "         a release build. Use target/release/conntrack_exporter.\n",
              file=sys.stderr, flush=True)

    setup_nat()

    extra = ["--protocol", args.protocol, "--profile", args.profile]
    collector_address = f"{COLLECTOR_HOST}:{COLLECTOR_PORT}"

    with Collector(COLLECTOR_HOST, COLLECTOR_PORT,
                   receive_buffer=64 * 1024 * 1024) as collector, \
            Exporter(args.exporter, collector_address, extra) as exporter:

        if not exporter.wait_for_log("Listening for conntrack NAT events", 15):
            raise Failure("the exporter never reached its event loop:\n"
                          + exporter.log_text)

        # Receiving in the background, so the collector's own socket buffer is
        # not what limits the measurement.
        stop_receiving = threading.Event()

        def collect():
            while not stop_receiving.is_set():
                collector.collect_until(lambda _c: False, 0.2)

        receiver = threading.Thread(target=collect, daemon=True)
        receiver.start()

        started = time.monotonic()
        sent = generate_load(args.sessions, args.duration)
        creation_seconds = time.monotonic() - started

        # What the kernel actually tracked. Ephemeral ports get reused, and a
        # datagram that reuses a live tuple joins the existing entry instead of
        # making a new one — so this is well below the number of sends.
        tracked = conntrack_count()

        # Tearing the table down turns every entry into a DESTROY event, so the
        # exporter sees two events per entry in total.
        flush_conntrack()

        # Let the exporter drain what is queued, and let its stats line fire.
        time.sleep(args.settle)
        stop_receiving.set()
        receiver.join(timeout=5)

        offered = tracked * 2  # one CREATE and one DELETE each
        received = len(collector.records)
        netlink_drops = read_exporter_drops(exporter)
        collector_drops = collector.dropped
        rate = offered / creation_seconds if creation_seconds else 0.0

        print()
        print("  --- offered to the exporter ---")
        print(f"  datagrams sent     {sent:>10,}  in {creation_seconds:.2f}s")
        print(f"  conntrack entries  {tracked:>10,}  (ports get reused, so below the sends)")
        print(f"  events offered     {offered:>10,}  one CREATE and one DELETE each, "
              f"~{rate:,.0f}/s")
        print()
        print("  --- what the exporter did with them ---")
        print(f"  netlink drops      {netlink_drops:>10,}  events the kernel could not "
              f"hand over")
        kept = offered - netlink_drops
        if offered:
            print(f"  ingested           {kept / offered * 100:>9.1f}%  of what was offered")
        print()
        print("  --- what this test collector saw ---")
        print(f"  records received   {received:>10,}")
        print(f"  messages received  {len(collector.messages):>10,}")
        if collector_drops is None:
            print("  collector drops         unknown  (SO_MEMINFO unavailable)")
        else:
            print(f"  collector drops    {collector_drops:>10,}  datagrams this test was "
                  f"too slow to read")
        print()
        print("  Records received is a floor, not the exporter's rate: a Python")
        print("  collector on loopback is the slow end here. Netlink drops above")
        print("  are the number that says whether ingest kept up.")
        print()

        if received == 0:
            raise Failure("nothing was exported at all\n" + exporter.log_text)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
