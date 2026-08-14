"""End-to-end smoke test: real conntrack NAT events through the real exporter.

Runs inside a user + network namespace (see `run-netns.sh`), where an
unprivileged user holds CAP_NET_ADMIN over a network stack of its own. That is
enough to set the conntrack sysctls, install a NAT rule and join the conntrack
netlink group, so the exporter runs exactly as it does in production — no
netlink is faked and no record is hand-assembled.

The flow it builds, and everything it asserts about the export, live in
`natflow.py`, which the QEMU test shares.
"""

import argparse
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flowdecode import Collector, describe  # noqa: E402
from natflow import (  # noqa: E402
    COLLECTOR_HOST,
    COLLECTOR_PORT,
    TEMPLATE_INTERVAL,
    Failure,
    check,
    collect_the_session,
    setup_nat,
    verify_export,
)


class Exporter:
    """The exporter under test, with its log captured for assertions."""

    def __init__(self, binary, collector, extra_args, verbose=True):
        # Debug logging formats and writes a line per event. That is what the
        # smoke test reads its assertions from, and exactly what a throughput
        # measurement must not pay for.
        verbosity = ["--verbose"] if verbose else []
        self.command = [binary, "--collector", collector, *verbosity, *extra_args]
        self.process = None
        self.log = []
        self._reader = None

    def __enter__(self):
        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()
        return self

    def _drain(self):
        for line in self.process.stdout:
            self.log.append(line.rstrip("\n"))

    def wait_for_log(self, needle, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(needle in line for line in self.log):
                return True
            if self.process.poll() is not None:
                return False
            time.sleep(0.02)
        return False

    @property
    def log_text(self):
        return "\n".join(self.log)

    def __exit__(self, *_):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self._reader is not None:
            self._reader.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exporter", required=True, help="path to the binary")
    parser.add_argument("--protocol", default="ipfix", choices=["ipfix", "netflow9"])
    parser.add_argument("--profile", default="full",
                        choices=["full", "nat-source", "flow-only"])
    parser.add_argument("--counter-width", default="8", choices=["4", "8"])
    parser.add_argument("--timeout", type=float, default=30,
                        help="seconds to wait for the expected records")
    args = parser.parse_args()

    setup_nat()

    extra = [
        "--protocol", args.protocol,
        "--profile", args.profile,
        "--counter-width", args.counter_width,
        "--template-interval", str(TEMPLATE_INTERVAL),
    ]

    with Collector(COLLECTOR_HOST, COLLECTOR_PORT) as collector, \
            Exporter(args.exporter, f"{COLLECTOR_HOST}:{COLLECTOR_PORT}",
                     extra) as exporter:

        if not exporter.wait_for_log("Listening for conntrack NAT events", 15):
            raise Failure(
                "the exporter never reached its event loop:\n" + exporter.log_text)

        # The startup line the README promises, reporting the resolved shape.
        check(any("Exporting" in line and "record=" in line for line in exporter.log),
              "the effective configuration was not logged:\n" + exporter.log_text)

        client_port, arrived = collect_the_session(
            collector, args.timeout, args.profile)

        verify_export(collector, client_port, arrived, args.protocol,
                      args.profile, args.counter_width,
                      extra_context=f"\n--- exporter ---\n{exporter.log_text}")

        print(f"ok: {args.protocol}/{args.profile}/{args.counter_width}B — "
              f"{len(collector.records)} record(s) over "
              f"{len(collector.messages)} message(s)", flush=True)
        for record in collector.records:
            print(f"  {describe(record)}", flush=True)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
