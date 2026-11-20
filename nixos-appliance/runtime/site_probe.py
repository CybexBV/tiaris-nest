"""Network boot evidence for the Nest site check (`src/site_check.rs`).

Runs inside the privileged PXE supervisor; the unprivileged Nest service only
reads the result (`/run/tiaris-nest-pxe/boot-probe.json`).

Two kinds of evidence:

- A boot probe: one DHCPDISCOVER, sent like a UEFI computer would (client
  architecture 7, `PXEClient` vendor class) from a fixed, locally
  administered address derived from the Nest's identity. Every answer is
  sorted: the school's DHCP server (an address), this Nest's own proxy answer,
  another Nest of the organization, or another server that hands out boot
  information (options 60/66/67 or a boot file) pointing elsewhere.
- A dropped-answer monitor: dnsmasq logs each proxy answer it sends
  (`log-dhcp`). Network boot firmware repeats the same DHCPDISCOVER (same
  transaction ID) only while no boot answer reached it; one that received the
  answer goes on to TFTP. So a transaction the Nest answered three times
  within two minutes did not get through. A switch DHCP guard ("DHCP
  snooping") that does not trust the Nest's port does exactly this. The Nest
  service drops a computer from the list once it boots from the Nest.
"""
from __future__ import annotations

import collections
import hashlib
import random
import re
import socket
import struct
import time

SCHEMA = 'tiaris.nest.boot-probe.v1'
REQUEST_SCHEMA = 'tiaris.nest.site-check-request.v1'
MAGIC = b'\x63\x82\x53\x63'
# How long the probe waits for answers. A DHCP server checks that an address is
# free before it offers it to a computer it does not know: dnsmasq (most small
# routers) pings it for 3 seconds, ISC dhcpd for 1, Windows Server up to 5. With
# a 3-second wait the probe gave up a moment before dnsmasq answered, and the
# check said "no DHCP server" on a network whose DHCP server works. A computer's
# own firmware waits 4 seconds and then asks again.
PROBE_SECONDS = 8.0
# A computer whose DISCOVER the Nest answered this often within the window,
# with no boot request in between, did not receive the answers.
DROP_OFFERS = 3
DROP_WINDOW = 120
# How long a dropped or successful answer counts as current evidence.
EVIDENCE_SECONDS = 24 * 3600
MAX_TRACKED_CLIENTS = 4096
MAX_LISTED = 8

MAC_RE = re.compile(r'^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$')
# dnsmasq with log-dhcp, after its "Mon DD HH:MM:SS dnsmasq-dhcp[pid]: " prefix
# (or none when it logs to the journal): "<xid> PXE(<if>) <mac> proxy" for a
# proxy answer, "<xid> PXE(<if>) <ip> <mac> <file>" for a boot server answer,
# then "<xid> sent size: 1 option: 53 message-type N".
PXE_LINE = re.compile(r'(?:^|\s)(\d+) PXE\(([^)]{1,16})\) (?:(\d{1,3}(?:\.\d{1,3}){3}) )?([0-9a-f]{2}(?::[0-9a-f]{2}){5})(?: (\S{1,128}))?\s*$')
TYPE_LINE = re.compile(r'(?:^|\s)(\d+) sent size:\s+1 option: 53 message-type\s+(\d+)\s*$')


def probe_mac(identity):
    """A stable, locally administered unicast address for this Nest's probe."""
    digest = hashlib.sha256(('tiaris-site-check:' + identity).encode()).digest()
    return ':'.join(f'{byte:02x}' for byte in (0x02,) + tuple(digest[:5]))


def discover_packet(mac, xid, arch=7):
    hardware = bytes.fromhex(mac.replace(':', ''))
    packet = struct.pack('!BBBBIHH4s4s4s4s16s64s128s', 1, 1, 6, 0, xid, 0, 0x8000,
                         b'\0' * 4, b'\0' * 4, b'\0' * 4, b'\0' * 4,
                         hardware + b'\0' * 10, b'\0' * 64, b'\0' * 128)
    vendor = b'PXEClient:Arch:%05d:UNDI:003016' % arch
    packet += MAGIC + bytes([53, 1, 1, 55, 5, 1, 3, 6, 66, 67])
    packet += bytes([60, len(vendor)]) + vendor + bytes([93, 2]) + struct.pack('!H', arch)
    packet += bytes([94, 3, 1, 3, 16]) + bytes([97, 17, 0]) + hashlib.sha256(hardware).digest()[:16]
    return packet + b'\xff'


def parse_offer(data, xid):
    """The offer in `data` for `xid`, or None for anything else."""
    if len(data) < 240 or data[0] != 2 or struct.unpack_from('!I', data, 4)[0] != xid or data[236:240] != MAGIC:
        return None
    options, index = {}, 240
    while index < len(data):
        tag = data[index]
        index += 1
        if tag == 255:
            break
        if tag == 0:
            continue
        if index >= len(data):
            return None
        length = data[index]
        index += 1
        options[tag] = data[index:index + length]
        index += length
    if options.get(53) != b'\x02':
        return None
    server = options.get(54, b'')
    file = data[108:236].split(b'\0')[0]
    return {
        'server': socket.inet_ntoa(server) if len(server) == 4 else None,
        'address': socket.inet_ntoa(data[16:20]),
        'next_server': socket.inet_ntoa(data[20:24]),
        'boot_file': bool(file) or 67 in options,
        'boot_host': options.get(66, b'').decode('ascii', 'replace').strip('\0').strip(),
        'pxe_client': options.get(60, b'') == b'PXEClient',
    }


def classify(offers, own, peers):
    """Sorts the answers to one probe (see the module comment)."""
    own_answer = False
    dhcp, peer_answers, others = set(), set(), set()
    known = {own, *peers}
    for offer in offers:
        server = offer['server'] or offer.get('source')
        if not server:
            continue
        if server == own:
            own_answer = True
            continue
        if server in peers:
            peer_answers.add(server)
            continue
        if offer['address'] != '0.0.0.0':
            dhcp.add(server)
        boot = offer['pxe_client'] or offer['boot_file'] or offer['boot_host']
        target = offer['boot_host'] or (offer['next_server'] if offer['next_server'] != '0.0.0.0' else server)
        if boot and target not in known:
            others.add(server)
    return {'own_answer': own_answer, 'dhcp_servers': sorted(dhcp)[:MAX_LISTED],
            'peer_answers': sorted(peer_answers)[:MAX_LISTED], 'other_boot_servers': sorted(others)[:MAX_LISTED]}


def probe(interface, own, peers, identity, seconds=PROBE_SECONDS):
    """Sends one boot DISCOVER on `interface` and sorts the answers."""
    mac = probe_mac(identity)
    xid = random.SystemRandom().randrange(1, 2 ** 32)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
        try:
            sock.bind(('0.0.0.0', 68))
        except OSError:
            return {'outcome': 'error', 'error': 'probe_port_busy'}
        sock.sendto(discover_packet(mac, xid), ('255.255.255.255', 67))
        offers = []
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0 and len(offers) < 32:
            sock.settimeout(remaining)
            try:
                data, remote = sock.recvfrom(4096)
            except (socket.timeout, TimeoutError):
                break
            offer = parse_offer(data, xid)
            if offer is not None:
                offer['source'] = remote[0]
                offers.append(offer)
    except OSError:
        return {'outcome': 'error', 'error': 'probe_failed'}
    finally:
        sock.close()
    return {'outcome': 'ok', **classify(offers, own, set(peers))}


class AnswerMonitor:
    """Follows dnsmasq's log for proxy answers that computers never act on."""

    def __init__(self, ignore=()):
        self.ignore = set(ignore)
        self.pending = collections.OrderedDict()  # xid -> (mac, kind)
        self.offers = collections.OrderedDict()   # (mac, xid) -> deque of times
        self.dropped = collections.OrderedDict()  # mac -> last time
        self.booted = collections.OrderedDict()   # mac -> last time

    def _remember(self, table, key, value):
        table[key] = value
        table.move_to_end(key)
        while len(table) > MAX_TRACKED_CLIENTS:
            table.popitem(last=False)

    def feed(self, line, now=None):
        now = time.time() if now is None else now
        match = PXE_LINE.search(line)
        if match:
            xid, _, address, mac, rest = match.groups()
            if mac in self.ignore:
                return
            kind = 'offer' if address is None and rest == 'proxy' else 'boot'
            self._remember(self.pending, xid, (mac, kind))
            return
        match = TYPE_LINE.search(line)
        if not match or match.group(1) not in self.pending:
            return
        xid = match.group(1)
        mac, kind = self.pending.pop(xid)
        message = int(match.group(2))
        if message == 5 or kind == 'boot':
            # The computer asked the boot service: it received the answer.
            self._remember(self.booted, mac, now)
            for key in [key for key in self.offers if key[0] == mac]:
                del self.offers[key]
            self.dropped.pop(mac, None)
            return
        if message != 2:
            return
        times = self.offers.get((mac, xid)) or collections.deque(maxlen=DROP_OFFERS)
        while times and now - times[0] > DROP_WINDOW:
            times.popleft()
        times.append(now)
        self._remember(self.offers, (mac, xid), times)
        if len(times) >= DROP_OFFERS:
            self._remember(self.dropped, mac, now)

    def summary(self, now=None):
        now = time.time() if now is None else now
        for table in (self.dropped, self.booted):
            for mac in [mac for mac, at in table.items() if now - at > EVIDENCE_SECONDS]:
                del table[mac]
        recent = sorted(self.dropped.items(), key=lambda item: item[1], reverse=True)[:MAX_LISTED]
        return {
            'dropped': [{'mac': mac, 'at': int(at)} for mac, at in recent],
            'dropped_clients': len(self.dropped),
            'dropped_last_at': int(max(self.dropped.values())) if self.dropped else None,
            'booted_clients': len(self.booted),
            'booted_last_at': int(max(self.booted.values())) if self.booted else None,
        }


def requested_at(raw):
    """The request time in a `site-check-request.json` document, or None."""
    try:
        value = raw if isinstance(raw, dict) else None
        if value is None or value.get('schema') != REQUEST_SCHEMA:
            return None
        at = value.get('requested_at')
        return at if type(at) is int and at > 0 else None
    except (AttributeError, TypeError):
        return None


def stamp(result, now=None):
    return {'schema': SCHEMA, 'checked_at': int(time.time() if now is None else now), **result}


if __name__ == '__main__':
    raise SystemExit('site_probe is a module of tiaris-nest-pxe')

__all__ = ['AnswerMonitor', 'classify', 'discover_packet', 'parse_offer', 'probe', 'probe_mac', 'requested_at', 'stamp']
