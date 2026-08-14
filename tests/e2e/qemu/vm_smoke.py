"""Package smoke test, run inside the VM.

Where the namespace test runs the binary directly, this one runs the service as
an operator would get it: the .deb installed, `/etc/default/natstream`
edited, and `systemctl start` from there. That makes the unit file the thing
under test — in particular the claim that the exporter needs no root, only
CAP_NET_ADMIN — which nothing outside a real init system can check.
"""

import os
import subprocess
import sys
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
    run,
    setup_nat,
    verify_export,
)

SERVICE = "natstream.service"
DEFAULTS = "/etc/default/natstream"

# CAP_NET_ADMIN is capability 12; the unit grants this one and nothing else.
CAP_NET_ADMIN = 12
CAP_NET_ADMIN_MASK = 1 << CAP_NET_ADMIN

PROTOCOL = "ipfix"
PROFILE = "full"
COUNTER_WIDTH = "8"


def systemctl(*args, check_exit=True):
    return run("systemctl", *args, check_exit=check_exit)


def unit_property(name):
    return systemctl("show", "-p", name, "--value", SERVICE).stdout.strip()


def journal():
    # Scoped to this boot, so a log line left behind by an earlier run can
    # never be mistaken for the service that is running now.
    result = run("journalctl", "-b", "-u", SERVICE, "--no-pager", "-n", "200",
                 check_exit=False)
    return result.stdout


# ---- What the package installed ----

def verify_package():
    """The paths and the install-time behaviour the README documents."""
    for path in (
        "/usr/sbin/natstream",
        "/lib/systemd/system/natstream.service",
        DEFAULTS,
    ):
        check(os.path.exists(path), f"the package did not install {path}")

    # Installing must not enable the service: it has no collector yet, and
    # starting it would only produce a restart loop.
    state = systemctl("is-enabled", SERVICE, check_exit=False).stdout.strip()
    check(state == "disabled",
          f"the service is '{state}' after install, expected 'disabled'")

    active = systemctl("is-active", SERVICE, check_exit=False).stdout.strip()
    check(active == "inactive",
          f"the service is '{active}' after install, expected 'inactive'")


def configure_service():
    """Point the service at the collector, the way an operator would."""
    options = (f"--protocol {PROTOCOL} --profile {PROFILE} "
               f"--counter-width {COUNTER_WIDTH} "
               f"--template-interval {TEMPLATE_INTERVAL} --verbose")

    lines = []
    for line in open(DEFAULTS):
        if line.startswith("COLLECTOR="):
            line = f"COLLECTOR={COLLECTOR_HOST}:{COLLECTOR_PORT}\n"
        elif line.startswith("EXPORTER_OPTS="):
            line = f"EXPORTER_OPTS={options}\n"
        lines.append(line)

    with open(DEFAULTS, "w") as handle:
        handle.writelines(lines)

    # The shipped file must carry both settings, or the edit above silently
    # produced a configuration the unit cannot use.
    content = "".join(lines)
    check(f"COLLECTOR={COLLECTOR_HOST}:{COLLECTOR_PORT}" in content,
          f"{DEFAULTS} has no COLLECTOR setting to fill in")
    check(f"EXPORTER_OPTS={options}" in content,
          f"{DEFAULTS} has no EXPORTER_OPTS setting to fill in")


# ---- What the unit file promises ----

def process_status(pid):
    status = {}
    with open(f"/proc/{pid}/status") as handle:
        for line in handle:
            key, _, value = line.partition(":")
            status[key] = value.strip()
    return status


def verify_hardening():
    """The unit runs unprivileged with exactly one capability."""
    check(systemctl("is-active", SERVICE, check_exit=False).stdout.strip() == "active",
          f"the service is not running:\n{journal()}")

    pid = unit_property("MainPID")
    check(pid.isdigit() and int(pid) > 0, f"no MainPID for {SERVICE}")
    status = process_status(pid)

    # DynamicUser=yes: systemd allocates a transient unprivileged user, so the
    # daemon that reads every NAT session on the box is not root.
    uids = status["Uid"].split()
    check(uids and all(uid != "0" for uid in uids),
          f"the service runs as uid {uids}; the unit sets DynamicUser=yes "
          f"precisely so it does not run as root")

    user = unit_property("User")
    check(user not in ("", "root"), f"the unit resolved to User={user!r}")

    # AmbientCapabilities/CapabilityBoundingSet=CAP_NET_ADMIN, and nothing else.
    effective = int(status["CapEff"], 16)
    check(effective == CAP_NET_ADMIN_MASK,
          f"CapEff is {effective:#x}, expected exactly CAP_NET_ADMIN "
          f"({CAP_NET_ADMIN_MASK:#x})")

    bounding = int(status["CapBnd"], 16)
    check(bounding == CAP_NET_ADMIN_MASK,
          f"CapBnd is {bounding:#x}, expected exactly CAP_NET_ADMIN "
          f"({CAP_NET_ADMIN_MASK:#x})")

    check(status.get("NoNewPrivs") == "1",
          "NoNewPrivileges is not in effect")

    return pid


def wait_for_startup(timeout=30):
    """Wait until the exporter is in its event loop, and return the journal.

    This is also what makes the checks below race-free. `systemctl start`
    returns once the service has been forked, which can be before systemd's
    child has dropped to the dynamic user and pared its capabilities down — so
    a process inspected at that moment is still root with everything. Waiting
    for the exporter's own first log line means the exec is long done.
    """
    deadline = time.monotonic() + timeout
    while True:
        log = journal()
        if "Listening for conntrack NAT events" in log:
            check("Exporting" in log and "record=" in log,
                  f"the effective configuration was not logged:\n{log}")
            return log

        state = systemctl("is-active", SERVICE, check_exit=False).stdout.strip()
        check(state == "active",
              f"the service went '{state}' during startup:\n{log}")
        check(time.monotonic() < deadline,
              f"the service never reached its event loop in {timeout}s:\n{log}")
        time.sleep(0.1)


def main():
    verify_package()
    configure_service()
    setup_nat()

    with Collector(COLLECTOR_HOST, COLLECTOR_PORT) as collector:
        systemctl("start", SERVICE)
        try:
            # Ordered first: it establishes that the exporter is really running
            # under its final identity, which the checks below then inspect.
            log = wait_for_startup()
            pid = verify_hardening()

            # The exporter sets nf_conntrack_events itself, without root and
            # without ProtectKernelTunables getting in the way.
            check(open("/proc/sys/net/netfilter/nf_conntrack_events").read().strip()
                  != "0",
                  "conntrack event delivery is still off; the service could not "
                  "set the sysctl it needs")

            client_port, arrived = collect_the_session(collector, 30, PROFILE)
            verify_export(collector, client_port, arrived, PROTOCOL, PROFILE,
                          COUNTER_WIDTH,
                          extra_context=f"\n--- journal ---\n{log}")

            # It survived the whole session rather than being restarted under us.
            check(unit_property("MainPID") == pid,
                  f"the service restarted during the test:\n{journal()}")

            # And it stops cleanly on the SIGTERM systemd sends.
            systemctl("stop", SERVICE)
            state = systemctl("is-active", SERVICE, check_exit=False).stdout.strip()
            check(state == "inactive",
                  f"the service is '{state}' after stop, expected 'inactive'")
            check("Worker shutting down" in journal(),
                  f"the service did not shut down cleanly:\n{journal()}")
        finally:
            subprocess.run(["systemctl", "stop", SERVICE],
                           capture_output=True, check=False)

        print(f"{len(collector.records)} record(s) over "
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
