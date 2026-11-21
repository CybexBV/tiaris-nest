#!/usr/bin/env python3
"""Site check qualification in disposable network namespaces; no VM.

A school network is a bridge ("hub", 192.0.2.1) with its own DHCP server and
an upstream time server; the Nest (192.0.2.2) runs the PXE supervisor's real
dnsmasq configuration, dropped-answer monitor, boot probe and time service;
a computer (192.0.2.3) behaves like UEFI network boot firmware. The Nest's
Rust checks run through `examples/site-check-probe.rs`.

Cases: a working network, another boot server, no DHCP server, a switch
DHCP guard dropping the Nest's boot answers, and blocked NTP.

It needs no root: run as an ordinary user, it enters a new user, network and
mount namespace (`unshare`), so everything it creates disappears with it.
Requires dnsmasq, nft, ip, unshare and a built `site-check-probe`:

    run-site-check.py --dnsmasq PATH --nft PATH --probe PATH [--receipt FILE]
"""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / 'nixos-appliance/runtime'
sys.path.insert(0, str(RUNTIME))
import site_probe  # noqa: E402

HUB, NEST, CLIENT = '192.0.2.1', '192.0.2.2', '192.0.2.3'
NEST_ID = 'nest-site-check-qualification'


def load(name):
    loader = SourceFileLoader(name.replace('-', '_'), str(RUNTIME / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def run(*command, check=True, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f'{command}: {result.stderr.strip()}')
    return result


def ns(name, *command, **kwargs):
    return run('ip', 'netns', 'exec', name, *command, **kwargs)


# --- roles, each run inside one namespace -----------------------------------

def role_pxe_client(mac, tries):
    """UEFI firmware: repeat one DISCOVER until a boot answer arrives, then ask
    the answering Nest on port 4011 for the boot file (the proxy answer names
    only the server)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'eth0')
    sock.bind(('0.0.0.0', 68))
    xid = int.from_bytes(os.urandom(4), 'big') or 1
    packet = site_probe.discover_packet(mac, xid)
    result = {'sent': 0, 'site_offer': False, 'proxy_offer': False, 'ack': False, 'boot_file': None}
    proxy = None
    for _ in range(tries):
        sock.sendto(packet, ('255.255.255.255', 67))
        result['sent'] += 1
        deadline = time.monotonic() + 1.5
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(4096)
            except (socket.timeout, TimeoutError):
                break
            offer = site_probe.parse_offer(data, xid)
            if offer is None:
                continue
            if offer['server'] == HUB:
                result['site_offer'] = True
            if offer['server'] == NEST:
                result['proxy_offer'] = True
                proxy = data
        if proxy:
            break
    if proxy:
        request = bytearray(packet)
        request[242] = 3  # DHCPREQUEST (option 53 is the first option)
        request[12:16] = socket.inet_aton(CLIENT)  # ciaddr: the address DHCP gave it
        sock.sendto(bytes(request), (NEST, 4011))
        deadline = time.monotonic() + 2
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(4096)
            except (socket.timeout, TimeoutError):
                break
            if len(data) > 240 and struct.unpack_from('!I', data, 4)[0] == xid and bytes([53, 1, 5]) in data[240:]:
                result['ack'] = True
                result['boot_file'] = data[108:236].split(b'\0')[0].decode('ascii', 'replace')
                break
    print(json.dumps(result))


def role_ntp_client(server):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    request = bytearray(48)
    request[0] = 0x23
    request[40:48] = os.urandom(8)
    sock.sendto(bytes(request), (server, 123))
    try:
        data, _ = sock.recvfrom(512)
    except (socket.timeout, TimeoutError):
        print(json.dumps({'answered': False}))
        return
    valid = len(data) >= 48 and data[0] & 7 == 4 and data[24:32] == request[40:48]
    print(json.dumps({'answered': valid, 'stratum': data[1] if valid else None}))


def role_ntp_upstream():
    timeservice = load('tiaris-nest-time')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HUB, 123))
    timeservice.serve(sock, clock=lambda: (True, 5000))


def role_nest(dnsmasq, work):
    """The Nest's supervisor parts; reads `probe`/`quit` commands on stdin."""
    pxe = load('tiaris-nest-pxe')
    pxe.RUN = Path(work) / 'run'
    pxe.RUN.mkdir(exist_ok=True)
    network = {'interface': 'eth0', 'mac': Path('/sys/class/net/eth0/address').read_text().strip(),
               'address': NEST, 'cidr': '192.0.2.0/24'}
    config = pxe.dnsmasq_config(network, 'snponly.efi')
    # In a user namespace dnsmasq keeps its (mapped) root instead of
    # switching users; everything else is the appliance's configuration.
    config = '\n'.join(line for line in config.splitlines() if not line.startswith(('user=', 'group='))) + '\n'
    path = Path(work) / 'proxy.conf'
    path.write_text(config)
    run(dnsmasq, '--test', f'--conf-file={path}')
    supervisor = pxe.Supervisor()
    supervisor.identity = hashlib.sha256(NEST_ID.encode()).hexdigest()
    process = subprocess.Popen([dnsmasq, '--no-daemon', f'--conf-file={path}'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    threading.Thread(target=supervisor.follow, args=(process.stderr,), daemon=True).start()
    timeservice = load('tiaris-nest-time')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 123))
    threading.Thread(target=timeservice.serve, args=(sock,), daemon=True).start()
    time.sleep(0.5)
    print('RESULT ' + json.dumps({'ready': process.poll() is None, 'synchronized': timeservice.kernel_clock()[0]}), flush=True)
    try:
        for line in sys.stdin:
            if line.strip() == 'quit':
                break
            supervisor.status('active', 'proxy_ready', True)
            supervisor.probed_at = 0.0
            supervisor.maybe_probe(network, NEST_ID, Path(work))
            probe = json.loads((pxe.RUN / 'boot-probe.json').read_text())
            print('RESULT ' + json.dumps(probe), flush=True)
    finally:
        process.terminate()
        process.wait(timeout=5)


# --- the orchestrator ---------------------------------------------------------

class Lab:
    def __init__(self, args, work):
        self.args, self.work = args, Path(work)
        self.processes = []
        self.site_dhcp = None

    def start(self, name, *command, **kwargs):
        process = subprocess.Popen(['ip', 'netns', 'exec', name, *command], **kwargs)
        self.processes.append(process)
        return process

    def build(self):
        subprocess.run(['mount', '-t', 'tmpfs', 'none', '/run'], check=True)
        Path('/run/netns').mkdir()
        for name in ('hub', 'nest', 'client'):
            run('ip', 'netns', 'add', name)
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
        ns('hub', 'ip', 'link', 'add', 'br0', 'type', 'bridge')
        ns('hub', 'ip', 'link', 'set', 'br0', 'up')
        ns('hub', 'ip', 'address', 'add', f'{HUB}/24', 'dev', 'br0')
        for port, name, address in (('p2', 'nest', NEST), ('p3', 'client', CLIENT)):
            ns('hub', 'ip', 'link', 'add', port, 'type', 'veth', 'peer', 'name', f'v{port}')
            ns('hub', 'ip', 'link', 'set', port, 'master', 'br0')
            ns('hub', 'ip', 'link', 'set', port, 'up')
            ns('hub', 'ip', 'link', 'set', f'v{port}', 'netns', name)
            ns(name, 'ip', 'link', 'set', f'v{port}', 'name', 'eth0')
            ns(name, 'ip', 'link', 'set', 'eth0', 'up')
            ns(name, 'ip', 'address', 'add', f'{address}/24', 'dev', 'eth0')
        self.start_site_dhcp()
        self.start('hub', sys.executable, __file__, '--role', 'ntp-upstream', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.nest = self.start('nest', sys.executable, __file__, '--role', 'nest', '--dnsmasq', self.args.dnsmasq,
                               '--work', str(self.work), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        ready = self.result()
        if not ready.get('ready'):
            raise RuntimeError(f'the Nest proxy did not start: {ready}')
        return ready

    def start_site_dhcp(self, extra=''):
        if self.site_dhcp is not None:
            self.site_dhcp.terminate()
            self.site_dhcp.wait(timeout=5)
            self.site_dhcp = None
        config = self.work / 'site-dhcp.conf'
        config.write_text('port=0\nno-ping\nbind-interfaces\ninterface=br0\n'
                          f'dhcp-range=192.0.2.100,192.0.2.150,255.255.255.0,1h\ndhcp-leasefile={self.work}/leases\n'
                          f'log-facility=-\npid-file=\n{extra}')
        self.site_dhcp = self.start('hub', self.args.dnsmasq, '--no-daemon', f'--conf-file={config}',
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)

    def stop_site_dhcp(self):
        self.site_dhcp.terminate()
        self.site_dhcp.wait(timeout=5)
        self.site_dhcp = None

    def result(self):
        for line in self.nest.stdout:
            if line.startswith('RESULT '):
                return json.loads(line[7:])
            print('nest: ' + line.rstrip(), flush=True)
        raise RuntimeError('the Nest role stopped')

    def boot_probe(self):
        self.nest.stdin.write('probe\n')
        self.nest.stdin.flush()
        probe = self.result()
        run_dir = self.work / 'run'
        check = json.loads(ns('nest', self.args.probe, 'boot', str(run_dir / 'status.json'), str(run_dir / 'boot-probe.json')).stdout)
        return probe, check

    def pxe_client(self, mac, tries):
        return json.loads(ns('client', sys.executable, __file__, '--role', 'pxe-client', mac, str(tries)).stdout)

    def ntp_client(self, server):
        return json.loads(ns('client', sys.executable, __file__, '--role', 'ntp-client', server).stdout)

    def time_check(self, *flags):
        return json.loads(ns('nest', self.args.probe, 'time', *flags, HUB).stdout)

    def nft(self, name, *rules):
        for rule in rules:
            ns(name, self.args.nft, *rule.split())

    def close(self):
        if getattr(self, 'nest', None) and self.nest.poll() is None:
            try:
                self.nest.stdin.write('quit\n')
                self.nest.stdin.flush()
                self.nest.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()


def orchestrate(args):
    cases = []

    def case(name, expectation, evidence, passed):
        cases.append({'case': name, 'expected': expectation, 'passed': bool(passed), 'evidence': evidence})
        print(f"{'PASS' if passed else 'FAIL'}: {name} ({expectation})", flush=True)

    with tempfile.TemporaryDirectory(prefix='tiaris-site-check-') as work:
        os.chmod(work, 0o755)
        lab = Lab(args, work)
        try:
            ready = lab.build()
            # 1. A working network.
            client = lab.pxe_client('02:00:00:00:10:07', 4)
            probe, check = lab.boot_probe()
            case('network boot works', 'pass boot_answer_served',
                 {'computer': client, 'probe': probe, 'check': check},
                 client['site_offer'] and client['proxy_offer'] and client['ack']
                 and client['boot_file'] == 'snponly.efi' and probe['own_answer'] and probe['booted_clients'] >= 1
                 and probe['dhcp_servers'] == [HUB] and check['status'] == 'pass'
                 and check['reason'] == 'boot_answer_served')
            # Quick restarts of a computer that receives every answer: new
            # transactions, each answered once, are not a dropped answer.
            restarts = [lab.pxe_client('02:00:00:00:20:07', 4) for _ in range(3)]
            probe, check = lab.boot_probe()
            case('healthy restarts are not mistaken', 'pass boot_answer_served',
                 {'computer': restarts, 'probe': probe, 'check': check},
                 all(r['proxy_offer'] and r['ack'] and r['sent'] == 1 for r in restarts)
                 and probe['dropped_clients'] == 0 and check['reason'] == 'boot_answer_served')
            served = lab.ntp_client(NEST)
            case('the Nest serves time to computers', 'NTP answer from 192.0.2.2 while synchronized',
                 {'answer': served, 'nest_clock_synchronized': ready['synchronized']},
                 served['answered'] if ready['synchronized'] else not served['answered'])
            synced = lab.time_check()
            reachable = lab.time_check('--unsynchronized')
            case('time check with NTP reachable', 'pass, or clock_not_synchronized when unset',
                 {'synchronized_clock': synced, 'unset_clock': reachable},
                 reachable['reason'] == 'clock_not_synchronized'
                 and (synced['status'] == 'pass' or not ready['synchronized']))
            # 2. Another server hands out boot information.
            lab.start_site_dhcp('dhcp-boot=pxelinux.0,,192.0.2.9\n')
            probe, check = lab.boot_probe()
            case('another boot server', 'fail other_boot_server', {'probe': probe, 'check': check},
                 check['reason'] == 'other_boot_server' and HUB in probe['other_boot_servers'])
            # 3. No DHCP server answers.
            lab.stop_site_dhcp()
            probe, check = lab.boot_probe()
            case('no DHCP server', 'fail no_dhcp_server', {'probe': probe, 'check': check},
                 check['reason'] == 'no_dhcp_server')
            lab.start_site_dhcp()
            # 4. A switch DHCP guard drops the Nest's answers (DHCP snooping:
            # server messages from an untrusted port never reach computers).
            lab.nft('hub', 'add table bridge guard',
                    'add chain bridge guard forward { type filter hook forward priority 0 ; }',
                    'add rule bridge guard forward iifname p2 udp sport 67 drop')
            client = lab.pxe_client('02:00:00:00:30:07', 4)
            probe, check = lab.boot_probe()
            case('dropped boot answer', 'fail boot_answer_dropped',
                 {'computer': client, 'probe': probe, 'check': check},
                 client['site_offer'] and not client['proxy_offer'] and probe['dropped_clients'] >= 1
                 and check['status'] == 'fail' and check['reason'] == 'boot_answer_dropped')
            lab.nft('hub', 'delete table bridge guard')
            # 5. The school blocks NTP (UDP 123).
            lab.nft('hub', 'add table inet school',
                    'add chain inet school input { type filter hook input priority 0 ; }',
                    'add rule inet school input udp dport 123 drop')
            blocked = lab.time_check('--unsynchronized')
            case('blocked NTP', 'fail ntp_blocked', {'check': blocked},
                 blocked['status'] == 'fail' and blocked['reason'] == 'ntp_blocked')
            lab.nft('hub', 'delete table inet school')
        except Exception as error:  # report what ran, then fail
            cases.append({'case': 'harness', 'passed': False, 'error': f'{type(error).__name__}: {error}'})
            print(f'FAIL: harness ({error})', flush=True)
        finally:
            lab.close()
    receipt = {'schema': 'tiaris.nest.site-check-qualification.v1', 'passed': bool(cases) and all(c['passed'] for c in cases),
               'cases': cases}
    if args.receipt:
        Path(args.receipt).write_text(json.dumps(receipt, indent=2) + '\n')
    print('RECEIPT ' + json.dumps(receipt), flush=True)
    return 0 if receipt['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--role', choices=['nest', 'pxe-client', 'ntp-client', 'ntp-upstream'])
    parser.add_argument('--dnsmasq', default='dnsmasq')
    parser.add_argument('--nft', default='nft')
    parser.add_argument('--probe', help='built examples/site-check-probe')
    parser.add_argument('--work')
    parser.add_argument('--receipt')
    parser.add_argument('values', nargs='*')
    args = parser.parse_args()
    if args.role == 'nest':
        return role_nest(args.dnsmasq, args.work)
    if args.role == 'pxe-client':
        return role_pxe_client(args.values[0], int(args.values[1]))
    if args.role == 'ntp-client':
        return role_ntp_client(args.values[0])
    if args.role == 'ntp-upstream':
        return role_ntp_upstream()
    if not args.probe:
        parser.error('--probe is required')
    if os.geteuid() != 0:
        # A private user, network and mount namespace owns everything below.
        command = ['unshare', '--user', '--map-root-user', '--net', '--mount', '--propagation', 'private',
                   sys.executable, __file__, '--dnsmasq', args.dnsmasq, '--nft', args.nft, '--probe', args.probe]
        if args.receipt:
            command += ['--receipt', args.receipt]
        return subprocess.run(command).returncode
    return orchestrate(args)


if __name__ == '__main__':
    sys.exit(main() or 0)
