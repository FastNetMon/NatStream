"""The NAT flow the end-to-end tests build, and what they assert about it.

Shared by both end-to-end layers — the namespace test, which runs the binary
directly, and the QEMU test, which runs the packaged service under systemd — so
the two agree on what a correct export looks like and only differ in how the
exporter got started.

The flow is a DNAT: a packet addressed to 10.9.9.9:9999 is rewritten to
10.9.9.1:19999. Every NAT field ends up with a distinct value, so a record that
mixes two of them up cannot pass.
"""

import os
import socket
import struct
import subprocess

from flowdecode import NAT44_SESSION_CREATE, NAT44_SESSION_DELETE, describe

# The flow, before and after translation.
CLIENT_IP = "10.9.9.1"
VIRTUAL_IP = "10.9.9.9"
VIRTUAL_PORT = 9999
REAL_IP = "10.9.9.1"
REAL_PORT = 19999

COLLECTOR_HOST = "127.0.0.1"
COLLECTOR_PORT = 4739

PAYLOAD = b"natstream-e2e"
REPLY = b"reply-from-the-server"

# An IPv4 header and a UDP header on top of the payload.
IPV4_UDP_OVERHEAD = 28

# Short enough to observe a retransmit without stretching the test out.
TEMPLATE_INTERVAL = 2

FIELDS_PER_PROFILE = {"full": 14, "nat-source": 12, "flow-only": 9}
RECORD_SIZES = {
    ("full", "8"): 58, ("full", "4"): 42,
    ("nat-source", "8"): 52, ("nat-source", "4"): 36,
    ("flow-only", "8"): 45, ("flow-only", "4"): 29,
}

# Enough of the conntrack netlink API to ask the kernel to tear the table down.
# Waiting for the entry to time out instead would mean waiting on the conntrack
# garbage collector, whose scan interval is adaptive and can stretch to minutes.
NETLINK_NETFILTER = 12
NFNL_SUBSYS_CTNETLINK = 1
IPCTNL_MSG_CT_DELETE = 2
NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLMSG_ERROR = 0x2
NLMSG_HDRLEN = 16


class Failure(Exception):
    """An assertion the exporter did not satisfy, or a broken test setup."""


def check(condition, message):
    if not condition:
        raise Failure(message)


def run(*command, check_exit=True, input=None):
    result = subprocess.run(command, capture_output=True, text=True, input=input)
    if check_exit and result.returncode != 0:
        raise Failure(
            f"{' '.join(command)} failed ({result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result


def setup_nat():
    """Bring up the network and install the DNAT rule the test exercises."""
    run("ip", "link", "set", "lo", "up")
    # Gives the stack a route for 10.9.9.0/24, so both the pre-NAT and post-NAT
    # addresses are local and the whole exchange stays on loopback.
    existing = run("ip", "-4", "addr", "show", "dev", "lo", check_exit=False)
    if f"{CLIENT_IP}/24" not in existing.stdout:
        run("ip", "addr", "add", f"{CLIENT_IP}/24", "dev", "lo")

    run("nft", "-f", "-", input=f"""
        table ip nat {{
          chain output {{
            type nat hook output priority -100; policy accept;
            ip daddr {VIRTUAL_IP} udp dport {VIRTUAL_PORT} dnat to {REAL_IP}:{REAL_PORT}
          }}
        }}
    """)


def exchange_packets():
    """Send one packet through the NAT rule and get one back.

    The reply is what makes the reply-direction counters non-zero, so the
    DELETE record has something to report in both directions.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((REAL_IP, REAL_PORT))
    server.settimeout(5)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(5)
    try:
        client.connect((VIRTUAL_IP, VIRTUAL_PORT))
        client_port = client.getsockname()[1]
        client.send(PAYLOAD)

        request, sender = server.recvfrom(65535)
        if request != PAYLOAD:
            raise Failure(f"the server got {request!r}, not {PAYLOAD!r}")
        server.sendto(REPLY, sender)

        reply = client.recv(65535)
        if reply != REPLY:
            raise Failure(f"the client got {reply!r}, not {REPLY!r}")

        return client_port
    except socket.timeout as error:
        raise Failure(
            "the NAT'd exchange timed out; the DNAT rule did not take effect"
        ) from error
    finally:
        client.close()
        server.close()


def flush_conntrack():
    """Delete every conntrack entry in this network namespace.

    The kernel emits a real DESTROY notification for each one, carrying its
    final counters — the same event a timeout would produce, but at a moment
    the test chooses rather than whenever the garbage collector next runs.
    """
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    try:
        sock.bind((0, 0))
        sock.settimeout(5)

        # nfgenmsg: family, version, res_id. A DELETE with no filter is a flush.
        body = struct.pack("!BBH", socket.AF_INET, 0, 0)
        header = struct.pack(
            "=IHHII",
            NLMSG_HDRLEN + len(body),
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE,
            NLM_F_REQUEST | NLM_F_ACK,
            1,  # sequence
            0,  # port id, assigned by the kernel
        )
        sock.send(header + body)

        response = sock.recv(65535)
        (message_type,) = struct.unpack_from("=H", response, 4)
        if message_type == NLMSG_ERROR:
            (error,) = struct.unpack_from("=i", response, NLMSG_HDRLEN)
            if error != 0:
                raise Failure(f"could not flush conntrack: {os.strerror(-error)}")
    except socket.timeout as error:
        raise Failure("the conntrack flush was never acknowledged") from error
    finally:
        sock.close()


def assert_nat_fields(record, client_port, profile):
    """Every record describes the flow we generated, whatever the profile."""
    check(record["protocolIdentifier"] == socket.IPPROTO_UDP,
          f"protocol is {record['protocolIdentifier']}, expected UDP")
    check(record["sourceIPv4Address"] == CLIENT_IP,
          f"source is {record['sourceIPv4Address']}, expected {CLIENT_IP}")
    check(record["sourceTransportPort"] == client_port,
          f"source port is {record['sourceTransportPort']}, expected {client_port}")

    # The pre-NAT destination, which is what the client actually addressed.
    check(record["destinationIPv4Address"] == VIRTUAL_IP,
          f"destination is {record['destinationIPv4Address']}, expected {VIRTUAL_IP}")
    check(record["destinationTransportPort"] == VIRTUAL_PORT,
          f"destination port is {record['destinationTransportPort']}, "
          f"expected {VIRTUAL_PORT}")

    if profile == "full":
        # The rewritten destination: the whole point of the exporter.
        check(record["postNATDestinationIPv4Address"] == REAL_IP,
              f"post-NAT destination is {record['postNATDestinationIPv4Address']}, "
              f"expected {REAL_IP}")
        check(record["postNAPTDestinationTransportPort"] == REAL_PORT,
              f"post-NAT destination port is "
              f"{record['postNAPTDestinationTransportPort']}, expected {REAL_PORT}")

    if profile in ("full", "nat-source"):
        # The source was not translated, so it is reported unchanged rather
        # than confused with the rewritten destination.
        check(record["postNATSourceIPv4Address"] == CLIENT_IP,
              f"post-NAT source is {record['postNATSourceIPv4Address']}, "
              f"expected the untranslated {CLIENT_IP}")
        check(record["postNAPTSourceTransportPort"] == client_port,
              f"post-NAT source port is {record['postNAPTSourceTransportPort']}, "
              f"expected the untranslated {client_port}")
    else:
        for name in ("natEvent", "postNATSourceIPv4Address",
                     "postNATDestinationIPv4Address"):
            check(name not in record,
                  f"the {profile} profile must not carry {name}")


def collect_the_session(collector, timeout, profile):
    """Run the flow and wait for both of its records to be exported."""
    client_port = exchange_packets()

    # Wait for the CREATE to be exported before tearing the session down, so
    # the two events are observed as the distinct records they are.
    collector.collect_until(lambda c: len(c.records) >= 1, min(timeout, 10))
    flush_conntrack()

    if profile == "flow-only":
        # Without natEvent the two events are indistinguishable, so wait for
        # the second record instead.
        def wanted(c):
            return len(c.records) >= 2
    else:
        def wanted(c):
            events = {r.get("natEvent") for r in c.records}
            return {NAT44_SESSION_CREATE, NAT44_SESSION_DELETE} <= events

    return client_port, collector.collect_until(wanted, timeout)


def verify_export(collector, client_port, arrived, protocol, profile,
                  counter_width, extra_context=""):
    """Assert everything the exporter promised about this session."""
    decoded = "\n".join(describe(r) for r in collector.records)
    context = f"\n--- records ---\n{decoded}{extra_context}"

    check(arrived, f"the expected records never arrived{context}")

    # ---- The template ----
    check(collector.templates, f"no template was ever sent{context}")
    template = next(iter(collector.templates.values()))
    check(template.template_id == 256,
          f"template id is {template.template_id}, expected the default 256")

    expected_fields = FIELDS_PER_PROFILE[profile]
    check(len(template.fields) == expected_fields,
          f"template has {len(template.fields)} fields, "
          f"expected {expected_fields} for {profile}")

    expected_size = RECORD_SIZES[(profile, counter_width)]
    check(template.record_size == expected_size,
          f"record is {template.record_size}B, expected {expected_size}B")

    # A collector that ages templates out must be refreshed, so the template is
    # retransmitted rather than sent once at startup — and on a message of its
    # own, since the flow is long over by now.
    collector.collect_until(
        lambda c: sum(1 for m in c.messages if m.templates) >= 2,
        TEMPLATE_INTERVAL * 3)

    template_messages = [m for m in collector.messages if m.templates]
    check(len(template_messages) >= 2,
          f"the template was sent {len(template_messages)} time(s) in "
          f"{TEMPLATE_INTERVAL * 3}s; it must be retransmitted{context}")
    check(any(not m.records for m in template_messages[1:]),
          f"no template was retransmitted on its own message, so an idle "
          f"exporter would never refresh one{context}")

    # ---- The records ----
    for record in collector.records:
        assert_nat_fields(record, client_port, profile)

    if profile != "flow-only":
        creates = [r for r in collector.records
                   if r["natEvent"] == NAT44_SESSION_CREATE]
        deletes = [r for r in collector.records
                   if r["natEvent"] == NAT44_SESSION_DELETE]

        # Counters live in the conntrack accounting extension, which is empty
        # when the session is created and holds the totals when it is torn down.
        for record in creates:
            check(record["packetDeltaCount"] == 0,
                  f"a CREATE reported {record['packetDeltaCount']} packets, "
                  f"expected 0{context}")

        final = deletes[-1]
        check(final["packetDeltaCount"] == 1,
              f"the DELETE reported {final['packetDeltaCount']} forward "
              f"packets, expected 1{context}")
        check(final["reversePacketDeltaCount"] == 1,
              f"the DELETE reported {final['reversePacketDeltaCount']} reply "
              f"packets, expected 1{context}")
        check(final["octetDeltaCount"] == len(PAYLOAD) + IPV4_UDP_OVERHEAD,
              f"the DELETE reported {final['octetDeltaCount']} forward bytes, "
              f"expected {len(PAYLOAD) + IPV4_UDP_OVERHEAD}{context}")
        check(final["reverseOctetDeltaCount"] == len(REPLY) + IPV4_UDP_OVERHEAD,
              f"the DELETE reported {final['reverseOctetDeltaCount']} reply "
              f"bytes, expected {len(REPLY) + IPV4_UDP_OVERHEAD}{context}")

    # ---- The transport ----
    expected_version = 10 if protocol == "ipfix" else 9
    for message in collector.messages:
        check(message.version == expected_version,
              f"a message claimed version {message.version}, "
              f"expected {expected_version}")
        check(message.domain_id == 0,
              f"observation domain is {message.domain_id}, expected the default 0")
