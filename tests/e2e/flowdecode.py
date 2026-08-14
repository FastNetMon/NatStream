"""A minimal IPFIX / NetFlow v9 collector, used by the end-to-end tests.

It decodes what the exporter actually puts on the wire — templates first, then
data records interpreted through them — so a test can assert on field values
rather than on a byte blob. Both protocols are normalised onto the same logical
field names, which lets one assertion cover both.

Run it directly to watch a live export:

    python3 tests/e2e/flowdecode.py --bind 127.0.0.1:4739
"""

import argparse
import socket
import struct
import sys
import time

IPFIX_VERSION = 10
NETFLOW9_VERSION = 9

IPFIX_HEADER_LEN = 16
NETFLOW9_HEADER_LEN = 20

IPFIX_TEMPLATE_SET_ID = 2
NETFLOW9_TEMPLATE_FLOWSET_ID = 0

ENTERPRISE_BIT = 0x8000
REVERSE_PEN = 29305

# NAT event codes (RFC 8158)
NAT44_SESSION_CREATE = 4
NAT44_SESSION_DELETE = 5

# (enterprise number, element id) -> logical name. `None` is the IANA registry.
IPFIX_ELEMENTS = {
    (None, 1): "octetDeltaCount",
    (None, 2): "packetDeltaCount",
    (None, 4): "protocolIdentifier",
    (None, 7): "sourceTransportPort",
    (None, 8): "sourceIPv4Address",
    (None, 11): "destinationTransportPort",
    (None, 12): "destinationIPv4Address",
    (None, 225): "postNATSourceIPv4Address",
    (None, 226): "postNATDestinationIPv4Address",
    (None, 227): "postNAPTSourceTransportPort",
    (None, 228): "postNAPTDestinationTransportPort",
    (None, 230): "natEvent",
    (REVERSE_PEN, 1): "reverseOctetDeltaCount",
    (REVERSE_PEN, 2): "reversePacketDeltaCount",
}

# NetFlow v9 has no enterprise mechanism, so the reverse counters arrive as the
# dedicated OUT_BYTES / OUT_PKTS types instead. Everything else matches.
NETFLOW9_ELEMENTS = {
    23: "reverseOctetDeltaCount",
    24: "reversePacketDeltaCount",
}

ADDRESS_FIELDS = {
    "sourceIPv4Address",
    "destinationIPv4Address",
    "postNATSourceIPv4Address",
    "postNATDestinationIPv4Address",
}


class DecodeError(Exception):
    pass


class Field:
    __slots__ = ("name", "length", "element_id", "pen")

    def __init__(self, name, length, element_id, pen):
        self.name = name
        self.length = length
        self.element_id = element_id
        self.pen = pen

    def __repr__(self):
        return f"Field({self.name}, {self.length}B)"


class Template:
    __slots__ = ("template_id", "fields")

    def __init__(self, template_id, fields):
        self.template_id = template_id
        self.fields = fields

    @property
    def record_size(self):
        return sum(field.length for field in self.fields)

    @property
    def names(self):
        return [field.name for field in self.fields]


class Message:
    """One decoded export packet."""

    __slots__ = ("version", "sequence_number", "domain_id", "export_time",
                 "count", "templates", "records", "raw")

    def __init__(self, version, sequence_number, domain_id, export_time, count,
                 templates, records, raw):
        self.version = version
        self.sequence_number = sequence_number
        self.domain_id = domain_id
        self.export_time = export_time
        self.count = count
        self.templates = templates
        self.records = records
        self.raw = raw

    @property
    def protocol(self):
        return "ipfix" if self.version == IPFIX_VERSION else "netflow9"


def _element_name(element_id, pen, version):
    if version == NETFLOW9_VERSION and element_id in NETFLOW9_ELEMENTS:
        return NETFLOW9_ELEMENTS[element_id]
    name = IPFIX_ELEMENTS.get((pen, element_id))
    if name is not None:
        return name
    if pen is not None:
        return f"enterprise({pen}):{element_id}"
    return f"element({element_id})"


def _decode_value(name, raw):
    if name in ADDRESS_FIELDS:
        if len(raw) != 4:
            raise DecodeError(f"{name} is {len(raw)} bytes, expected 4")
        return ".".join(str(b) for b in raw)
    return int.from_bytes(raw, "big")


def _parse_template_set(payload, version):
    """Parse a template set / FlowSet body into Template objects."""
    templates = []
    offset = 0
    # A trailing run of padding zeros is not another template record.
    while offset + 4 <= len(payload) and payload[offset:offset + 4] != b"\x00" * 4:
        template_id, field_count = struct.unpack_from("!HH", payload, offset)
        offset += 4

        fields = []
        for _ in range(field_count):
            if offset + 4 > len(payload):
                raise DecodeError("template record runs past the end of its set")
            raw_id, length = struct.unpack_from("!HH", payload, offset)
            offset += 4

            pen = None
            element_id = raw_id
            if version == IPFIX_VERSION and raw_id & ENTERPRISE_BIT:
                if offset + 4 > len(payload):
                    raise DecodeError("enterprise number runs past the end of its set")
                element_id = raw_id & ~ENTERPRISE_BIT
                (pen,) = struct.unpack_from("!I", payload, offset)
                offset += 4
            elif version == NETFLOW9_VERSION and raw_id & ENTERPRISE_BIT:
                raise DecodeError(
                    f"NetFlow v9 field specifier {raw_id:#x} has the enterprise "
                    "bit set, which v9 cannot express"
                )

            fields.append(Field(_element_name(element_id, pen, version), length,
                                element_id, pen))

        templates.append(Template(template_id, fields))

    return templates


def _parse_data_set(payload, template):
    records = []
    size = template.record_size
    if size == 0:
        raise DecodeError(f"template {template.template_id} has a zero-byte record")

    offset = 0
    # Anything shorter than a whole record is the set's padding.
    while len(payload) - offset >= size:
        record = {}
        for field in template.fields:
            raw = payload[offset:offset + field.length]
            record[field.name] = _decode_value(field.name, raw)
            offset += field.length
        records.append(record)

    return records


def decode(datagram, templates=None):
    """Decode one export packet, using and updating `templates` (id -> Template)."""
    if templates is None:
        templates = {}

    if len(datagram) < 4:
        raise DecodeError(f"datagram is only {len(datagram)} bytes")

    (version,) = struct.unpack_from("!H", datagram, 0)

    if version == IPFIX_VERSION:
        if len(datagram) < IPFIX_HEADER_LEN:
            raise DecodeError("short IPFIX header")
        length, export_time, sequence, domain_id = struct.unpack_from(
            "!HIII", datagram, 2)
        if length != len(datagram):
            raise DecodeError(
                f"IPFIX header claims {length} bytes, datagram is {len(datagram)}")
        offset = IPFIX_HEADER_LEN
        count = None
        template_set_id = IPFIX_TEMPLATE_SET_ID
    elif version == NETFLOW9_VERSION:
        if len(datagram) < NETFLOW9_HEADER_LEN:
            raise DecodeError("short NetFlow v9 header")
        count, _uptime, export_time, sequence, domain_id = struct.unpack_from(
            "!HIIII", datagram, 2)
        offset = NETFLOW9_HEADER_LEN
        template_set_id = NETFLOW9_TEMPLATE_FLOWSET_ID
    else:
        raise DecodeError(f"unknown export version {version}")

    new_templates = []
    records = []

    while offset + 4 <= len(datagram):
        set_id, set_length = struct.unpack_from("!HH", datagram, offset)
        if set_length < 4:
            raise DecodeError(f"set {set_id} claims a {set_length}-byte length")
        if offset + set_length > len(datagram):
            raise DecodeError(f"set {set_id} runs past the end of the datagram")

        payload = datagram[offset + 4:offset + set_length]

        if set_id == template_set_id:
            for template in _parse_template_set(payload, version):
                templates[template.template_id] = template
                new_templates.append(template)
        elif set_id < 256:
            raise DecodeError(f"set id {set_id} is reserved")
        else:
            template = templates.get(set_id)
            if template is None:
                # Not fatal: the template may simply not have arrived yet.
                pass
            else:
                records.extend(_parse_data_set(payload, template))

        offset += set_length

    return Message(version, sequence, domain_id, export_time, count,
                   new_templates, records, datagram)


class Collector:
    """A UDP socket that decodes what it receives, keeping template state."""

    def __init__(self, host="127.0.0.1", port=4739):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, port))
        self.templates = {}
        self.messages = []

    @property
    def address(self):
        host, port = self.socket.getsockname()
        return f"{host}:{port}"

    @property
    def records(self):
        return [record for message in self.messages for record in message.records]

    def close(self):
        self.socket.close()

    def collect_until(self, predicate, timeout):
        """Receive until `predicate(self)` holds. Returns whether it did."""
        deadline = time.monotonic() + timeout
        while True:
            if predicate(self):
                return True

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False

            self.socket.settimeout(remaining)
            try:
                datagram, _ = self.socket.recvfrom(65535)
            except socket.timeout:
                return predicate(self)

            self.messages.append(decode(datagram, self.templates))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def describe(record):
    """A one-line, human-readable form of a decoded record."""
    event = {
        NAT44_SESSION_CREATE: "CREATE",
        NAT44_SESSION_DELETE: "DELETE",
    }.get(record.get("natEvent"), "-" if "natEvent" not in record else "?")

    def get(name, default="-"):
        return record.get(name, default)

    return (
        f"{event} proto={get('protocolIdentifier')} "
        f"{get('sourceIPv4Address')}:{get('sourceTransportPort')} -> "
        f"{get('destinationIPv4Address')}:{get('destinationTransportPort')} "
        f"nat={get('postNATSourceIPv4Address')}:{get('postNAPTSourceTransportPort')} -> "
        f"{get('postNATDestinationIPv4Address')}:{get('postNAPTDestinationTransportPort')} "
        f"orig={get('octetDeltaCount')}/{get('packetDeltaCount')} "
        f"reply={get('reverseOctetDeltaCount')}/{get('reversePacketDeltaCount')}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1:4739",
                        help="address:port to listen on (default 127.0.0.1:4739)")
    parser.add_argument("--timeout", type=float, default=0,
                        help="stop after this many seconds (0 means never)")
    args = parser.parse_args()

    host, _, port = args.bind.rpartition(":")
    collector = Collector(host, int(port))
    print(f"listening on {collector.address}", flush=True)

    deadline = time.monotonic() + args.timeout if args.timeout else None
    try:
        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                collector.socket.settimeout(remaining)
            try:
                datagram, sender = collector.socket.recvfrom(65535)
            except socket.timeout:
                break

            try:
                message = decode(datagram, collector.templates)
            except DecodeError as error:
                print(f"{sender[0]}:{sender[1]} undecodable: {error}", flush=True)
                continue

            for template in message.templates:
                print(f"template {template.template_id}: "
                      f"{template.record_size}B {template.names}", flush=True)
            for record in message.records:
                print(describe(record), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        collector.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
