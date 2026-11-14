"""The site check's network boot evidence and the Nest's time service."""
from importlib.machinery import SourceFileLoader
import importlib.util
from pathlib import Path
import socket
import struct
import sys
import unittest

RUNTIME = Path(__file__).resolve().parents[1] / 'runtime'
sys.path.insert(0, str(RUNTIME))
import site_probe as probe


def script(name):
    loader = SourceFileLoader(name.replace('-', '_'), str(RUNTIME / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


timeservice = script('tiaris-nest-time')
OWN = '192.0.2.2'


def offer(xid, server, address='0.0.0.0', next_server='0.0.0.0', file=b'', options=b''):
    packet = struct.pack('!BBBBIHH4s4s4s4s16s64s128s', 2, 1, 6, 0, xid, 0, 0x8000, b'\0' * 4,
                         socket.inet_aton(address), socket.inet_aton(next_server), b'\0' * 4,
                         b'\x02' + b'\0' * 15, b'\0' * 64, file.ljust(128, b'\0'))
    return packet + probe.MAGIC + bytes([53, 1, 2, 54, 4]) + socket.inet_aton(server) + options + b'\xff'


class BootProbe(unittest.TestCase):
    def test_probe_mac_is_stable_local_unicast(self):
        mac = probe.probe_mac('nest-1')
        self.assertEqual(mac, probe.probe_mac('nest-1'))
        self.assertNotEqual(mac, probe.probe_mac('nest-2'))
        first = int(mac[:2], 16)
        self.assertTrue(first & 0x02 and not first & 0x01)

    def test_discover_looks_like_a_uefi_computer(self):
        packet = probe.discover_packet('02:00:00:00:00:01', 7)
        self.assertEqual(packet[0], 1)
        self.assertEqual(packet[236:240], probe.MAGIC)
        self.assertIn(b'PXEClient:Arch:00007', packet)
        self.assertIn(bytes([53, 1, 1]), packet)
        self.assertEqual(packet[-1], 255)

    def test_parses_only_offers_for_its_transaction(self):
        data = offer(7, '192.0.2.1', address='192.0.2.100')
        parsed = probe.parse_offer(data, 7)
        self.assertEqual(parsed['server'], '192.0.2.1')
        self.assertEqual(parsed['address'], '192.0.2.100')
        self.assertFalse(parsed['boot_file'])
        self.assertIsNone(probe.parse_offer(data, 8))
        self.assertIsNone(probe.parse_offer(data[:200], 7))
        ack = data.replace(bytes([53, 1, 2]), bytes([53, 1, 5]))
        self.assertIsNone(probe.parse_offer(ack, 7))

    def test_sorts_school_dhcp_own_answer_and_peers(self):
        offers = [probe.parse_offer(offer(1, '192.0.2.1', address='192.0.2.100'), 1),
                  probe.parse_offer(offer(1, OWN, next_server=OWN, options=bytes([60, 9]) + b'PXEClient'), 1),
                  probe.parse_offer(offer(1, '192.0.2.4', options=bytes([60, 9]) + b'PXEClient'), 1)]
        result = probe.classify(offers, OWN, {'192.0.2.4'})
        self.assertEqual(result, {'own_answer': True, 'dhcp_servers': ['192.0.2.1'],
                                  'peer_answers': ['192.0.2.4'], 'other_boot_servers': []})

    def test_names_another_boot_server(self):
        offers = [probe.parse_offer(offer(1, '192.0.2.1', address='192.0.2.100', next_server='192.0.2.9', file=b'pxelinux.0'), 1),
                  probe.parse_offer(offer(1, '192.0.2.7', options=bytes([60, 9]) + b'PXEClient'), 1)]
        result = probe.classify(offers, OWN, set())
        self.assertEqual(result['dhcp_servers'], ['192.0.2.1'])
        self.assertEqual(result['other_boot_servers'], ['192.0.2.1', '192.0.2.7'])

    def test_dhcp_options_pointing_at_the_nest_are_fine(self):
        offers = [probe.parse_offer(offer(1, '192.0.2.1', address='192.0.2.100', options=bytes([66, 9]) + OWN.encode()), 1)]
        result = probe.classify(offers, OWN, set())
        self.assertEqual(result['other_boot_servers'], [])

    def test_no_answer_means_no_dhcp_server(self):
        self.assertEqual(probe.classify([], OWN, set())['dhcp_servers'], [])

    def test_request_file(self):
        self.assertEqual(probe.requested_at({'schema': probe.REQUEST_SCHEMA, 'requested_at': 5}), 5)
        self.assertIsNone(probe.requested_at({'schema': 'other', 'requested_at': 5}))
        self.assertIsNone(probe.requested_at({'schema': probe.REQUEST_SCHEMA, 'requested_at': True}))
        self.assertIsNone(probe.requested_at([]))


def proxy_lines(xid, mac, message=2):
    return [f'Nov 14 20:46:10 dnsmasq-dhcp[1]: {xid} vendor class: PXEClient:Arch:00007:UNDI:003000',
            f'Nov 14 20:46:10 dnsmasq-dhcp[1]: {xid} PXE(eth0) {mac} proxy',
            f'Nov 14 20:46:10 dnsmasq-dhcp[1]: {xid} sent size:  1 option: 53 message-type  {message}']


class DroppedAnswers(unittest.TestCase):
    MAC = '02:00:00:00:30:07'

    def feed(self, monitor, lines, now):
        for line in lines:
            monitor.feed(line, now)

    def test_repeated_unanswered_offers_are_dropped(self):
        monitor = probe.AnswerMonitor()
        for second in (0, 4, 12):
            self.feed(monitor, proxy_lines(9, self.MAC), 1000 + second)
        summary = monitor.summary(1020)
        self.assertEqual(summary['dropped_clients'], 1)
        self.assertEqual(summary['dropped_last_at'], 1012)

    def test_a_boot_request_clears_the_computer(self):
        monitor = probe.AnswerMonitor()
        for second in (0, 4, 12):
            self.feed(monitor, proxy_lines(9, self.MAC), 1000 + second)
        self.feed(monitor, [f'dnsmasq-dhcp[1]: 9 PXE(eth0) 192.0.2.3 {self.MAC} snponly.efi',
                            'dnsmasq-dhcp[1]: 9 sent size:  1 option: 53 message-type  5'], 1013)
        summary = monitor.summary(1020)
        self.assertEqual(summary['dropped_clients'], 0)
        self.assertEqual(summary['booted_clients'], 1)

    def test_one_offer_per_transaction_is_normal(self):
        # Firmware, then iPXE, then a quick restart: new transactions, each
        # answered once, as when every answer arrives.
        monitor = probe.AnswerMonitor()
        for xid, second in ((1, 0), (2, 8), (3, 40), (4, 48), (5, 80)):
            self.feed(monitor, proxy_lines(xid, self.MAC), 1000 + second)
        self.assertEqual(monitor.summary(1100)['dropped_clients'], 0)

    def test_the_summary_lists_recent_dropped_computers(self):
        monitor = probe.AnswerMonitor()
        for second in (0, 4, 12):
            self.feed(monitor, proxy_lines(9, self.MAC), 1000 + second)
        self.assertEqual(monitor.summary(1020)['dropped'], [{'mac': self.MAC, 'at': 1012}])

    def test_the_nests_own_probe_is_ignored(self):
        mac = probe.probe_mac('nest-1')
        monitor = probe.AnswerMonitor(ignore={mac})
        for second in (0, 1, 2, 3):
            self.feed(monitor, proxy_lines(5, mac), 1000 + second)
        self.assertEqual(monitor.summary(1010)['dropped_clients'], 0)

    def test_old_evidence_expires(self):
        monitor = probe.AnswerMonitor()
        for second in (0, 4, 12):
            self.feed(monitor, proxy_lines(9, self.MAC), 1000 + second)
        self.assertEqual(monitor.summary(1012 + probe.EVIDENCE_SECONDS + 1)['dropped_clients'], 0)

    def test_unrelated_lines_are_ignored(self):
        monitor = probe.AnswerMonitor()
        for line in ('dnsmasq[1]: started, version 2.93 DNS disabled', 'garbage', '1 sent size: 1 option: 53 message-type 2'):
            monitor.feed(line, 1)
        self.assertEqual(monitor.summary(1), {'dropped': [], 'dropped_clients': 0, 'dropped_last_at': None,
                                              'booted_clients': 0, 'booted_last_at': None})


class TimeService(unittest.TestCase):
    REQUEST = bytes([0x23]) + bytes(39) + b'ORIGINTS'

    def test_answers_a_client_request(self):
        packet = timeservice.reply(self.REQUEST, 1_800_000_000.25, 1_800_000_000.5, 20_000)
        self.assertEqual(len(packet), 48)
        self.assertEqual(packet[0] & 0x7, 4)
        self.assertEqual((packet[0] >> 3) & 0x7, 4)
        self.assertEqual(packet[0] >> 6, 0)
        self.assertEqual(packet[1], timeservice.STRATUM)
        self.assertEqual(packet[24:32], b'ORIGINTS')
        seconds = struct.unpack('!I', packet[40:44])[0] - timeservice.NTP_EPOCH_OFFSET
        self.assertEqual(seconds, 1_800_000_000)

    def test_ignores_anything_but_client_requests(self):
        self.assertIsNone(timeservice.reply(bytes([0x24]) + bytes(47), 1, 1, 0))
        self.assertIsNone(timeservice.reply(bytes([0x23]) + bytes(10), 1, 1, 0))

    def test_serves_only_a_synchronized_clock(self):
        self.assertTrue(timeservice.serving(True, 20_000))
        self.assertFalse(timeservice.serving(False, 20_000))
        self.assertFalse(timeservice.serving(True, 2_000_000))
        self.assertFalse(timeservice.serving(True, None))

    def test_answers_only_private_addresses(self):
        for address in ('10.1.2.3', '172.16.0.9', '192.168.1.20', '100.64.0.5'):
            self.assertTrue(timeservice.private_source(address), address)
        for address in ('8.8.8.8', '127.0.0.1', '169.254.1.1', '0.0.0.0', 'fe80::1', 'nonsense'):
            self.assertFalse(timeservice.private_source(address), address)

    def test_limits_each_address(self):
        limiter = timeservice.Limiter()
        allowed = [limiter.allow('10.0.0.1', 100.0) for _ in range(20)]
        self.assertEqual(allowed.count(True), timeservice.BURST)
        self.assertTrue(limiter.allow('10.0.0.2', 100.0))
        self.assertTrue(limiter.allow('10.0.0.1', 102.0))

    def test_an_unsynchronized_nest_stays_silent(self):
        class Socket:
            sent = []
            def recvfrom(self, size):
                return TimeService.REQUEST, ('10.0.0.5', 50000)
            def sendto(self, packet, address):
                self.sent.append(packet)
        sock = Socket()
        timeservice.serve(sock, clock=lambda: (False, None), once=True)
        self.assertEqual(sock.sent, [])
        timeservice.serve(sock, clock=lambda: (True, 1000), once=True)
        self.assertEqual(len(sock.sent), 1)


if __name__ == '__main__':
    unittest.main()
