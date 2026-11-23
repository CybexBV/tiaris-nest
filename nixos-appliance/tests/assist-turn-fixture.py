"""Isolated TURN component fixture. Keys exist only in the two guests."""
import asyncio
import base64
from functools import partial
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

LAN = '100.64.50.10'
OTHER_LOCAL = '100.64.50.12'
PEER = '100.64.50.20'
PUBLIC = '198.51.100.20'
NEST_IPV6 = 'fd42:50::10'
PEER_IPV6 = 'fd42:50::20'
SCHEMA = 'tiaris.nest.assist-turn.v1'
PORT = 3478
PEER_PORT = 5000
LOW_PORT = 900
IDS = ('20261123-00000001', '20261123-00000002')
PAYLOAD = b'local TURN test' * 8
KEYFILE = Path('/run/turn-test-keys.json')
INBOX = Path('/var/lib/tiaris-nest/state/agent/assist-turn.json')
STATUS = Path('/run/tiaris-nest-turn/status.json')
FIXTURE_HTTP = f'http://{OTHER_LOCAL}:8085'


def keys():
    return json.loads(KEYFILE.read_bytes())


def provision(stage):
    values = keys()
    config = {'schema': SCHEMA, 'enabled': stage != 'off'}
    if stage != 'off':
        selected = {'initial': (0,), 'overlap': (0, 1), 'rotated': (1,)}[stage]
        config.update(port=PORT, relay_ports=[61000, 61040], max_bps=500_000,
                      bps_capacity=5_000_000, total_quota=40, user_quota=2,
                      secrets=[{'id': IDS[i], 'value': values[i]} for i in selected])
    req = urllib.request.Request(FIXTURE_HTTP, data=json.dumps(config).encode(), method='POST')
    with urllib.request.urlopen(req, timeout=3) as response:
        assert response.status == 204


class ConfigurationServer(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        # This fixture is reachable only over the test's virtual LAN.
        size = int(self.headers.get('Content-Length', '0'))
        if not 0 < size <= 4096 or self.client_address[0] != PEER:
            self.send_error(400)
            return
        with tempfile.NamedTemporaryFile(dir=INBOX.parent, delete=False) as file:
            os.fchown(file.fileno(), 985, 985)
            file.write(self.rfile.read(size))
        os.replace(file.name, INBOX)
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(STATUS.read_bytes() if STATUS.exists() else b'{}')


def wait_for_keys(expected):
    end = time.monotonic() + 12
    while time.monotonic() < end:
        with urllib.request.urlopen(FIXTURE_HTTP, timeout=3) as response:
            status = json.load(response)
        if status.get('secret_ids') == list(expected) and status.get('state') == 'running':
            return
        time.sleep(0.1)
    raise AssertionError('TURN did not report the expected key ids')


def credentials(index):
    username = f'{int(time.time()) + 600}:{uuid.uuid4().hex}'
    credential = base64.b64encode(hmac.digest(keys()[index].encode(), username.encode(), 'sha1'))
    return username, credential.decode('ascii')


def uclient(address, index):
    username, credential = credentials(index)
    try:
        result = subprocess.run(
            ['turnutils_uclient', '-c', '-m', '1', '-n', '3', '-e', PEER, '-r', str(PEER_PORT),
             '-u', username, '-w', credential, address],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10, text=True,
        )
    except subprocess.TimeoutExpired:
        raise AssertionError('coturn utilities timed out') from None
    # Never display the tool output or command line containing a credential.
    assert result.returncode == 0 and re.search(r'Total lost packets\s+0\b', result.stdout), (
        'coturn utilities did not complete a lossless relay exchange'
    )


def binding(source, destination, expected):
    from aioice import stun
    msg = stun.Message(stun.Method.BINDING, stun.Class.REQUEST)
    family = socket.AF_INET6 if ':' in source else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as probe:
        probe.bind((source, 0))
        probe.settimeout(1.0)
        probe.sendto(bytes(msg), (destination, PORT))
        try:
            answer, _ = probe.recvfrom(1500)
        except TimeoutError:
            assert not expected, 'private unauthenticated STUN timed out'
            return
        response = stun.parse_message(answer)
        assert expected, 'excluded address reached the STUN listener'
        assert response.message_class == stun.Class.RESPONSE
        assert response.transaction_id == msg.transaction_id
        assert response.attributes['XOR-MAPPED-ADDRESS'] == probe.getsockname()[:2]
        assert 'SOFTWARE' not in response.attributes and 'MAPPED-ADDRESS' not in response.attributes


class Receiver(asyncio.DatagramProtocol):
    def __init__(self):
        self.incoming = asyncio.Queue()

    def datagram_received(self, payload, address):
        self.incoming.put_nowait((payload, address))


async def client(index):
    from aioice import turn
    username, password = credentials(index)
    server = (LAN, PORT)
    _, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
        partial(turn.TurnClientUdpProtocol, server, username, password, 120, 300),
        local_addr=(PEER, 0), remote_addr=server,
    )
    protocol.receiver = Receiver()
    return protocol


async def allocate(protocol):
    address = await asyncio.wait_for(protocol.connect(), 4)
    assert address[0] == LAN and 61000 <= address[1] <= 61040
    return address


async def private_exchange(protocol):
    await protocol.send_data(PAYLOAD, (PEER, PEER_PORT))
    assert await asyncio.wait_for(protocol.receiver.incoming.get(), 2) == (PAYLOAD, (PEER, PEER_PORT))


async def rotation():
    old = await client(0)
    original_relay = await allocate(old)
    try:
        await private_exchange(old)
        await asyncio.to_thread(provision, 'overlap')
        await asyncio.to_thread(wait_for_keys, IDS)
        new = await client(1)
        await allocate(new)
        try:
            await private_exchange(new)
            await private_exchange(old)
        finally:
            await new.delete()
        await asyncio.to_thread(provision, 'rotated')
        await asyncio.to_thread(wait_for_keys, IDS[1:])
        await private_exchange(old)
        assert old.relayed_address == original_relay
        await asyncio.to_thread(uclient, LAN, 1)
        retired = await client(0)
        try:
            await refused(retired.connect(), (401, 441))
        finally:
            retired.transport.close()
    finally:
        await old.delete()


async def refused(call, codes):
    from aioice import stun
    try:
        await asyncio.wait_for(call, 4)
    except stun.TransactionFailed as error:
        assert error.response.attributes['ERROR-CODE'][0] in codes, 'unexpected TURN refusal'
    else:
        raise AssertionError('an excluded TURN request succeeded')


async def no_packet(queue, description):
    try:
        await asyncio.wait_for(queue.get(), 0.5)
    except TimeoutError:
        return
    raise AssertionError(f'received data across {description}')


async def boundary():
    from aioice import stun
    protocol = await client(0)
    relay = await allocate(protocol)
    try:
        for address in (LAN, '127.0.0.1', '0.0.0.0', PEER_IPV6):
            await refused(protocol.channel_bind(0x4010, (address, PEER_PORT)), (403, 443))
        await private_exchange(protocol)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as outside:
            outside.bind((PUBLIC, 0))
            await protocol.channel_bind(0x4010, outside.getsockname())
            protocol.channel_to_peer[0x4010] = outside.getsockname()
            outside.sendto(PAYLOAD, relay)
        await no_packet(protocol.receiver.incoming, 'public ingress to a live allocation')
        await private_exchange(protocol)
    finally:
        await protocol.delete()

    # A kernel denial returns EPERM. Coturn closes that relay socket, so use
    # a separate verified allocation for each egress rule the VM checks.
    for address, port in ((PUBLIC, PEER_PORT), (PEER, LOW_PORT), (OTHER_LOCAL, PEER_PORT)):
        denied = await client(0)
        await allocate(denied)
        try:
            await private_exchange(denied)
            await denied.send_data(PAYLOAD, (address, port))
            await no_packet(denied.receiver.incoming, f'outbound {address}:{port}')
        finally:
            try:
                await asyncio.wait_for(denied.delete(), 2)
            finally:
                denied.transport.close()

    ipv6 = await client(0)
    # RFC 6156's requested address family attribute, absent in older aioice.
    family = (0x0017, 'REQUESTED-ADDRESS-FAMILY', stun.pack_unsigned, stun.unpack_unsigned)
    stun.ATTRIBUTES_BY_TYPE[family[0]] = family
    stun.ATTRIBUTES_BY_NAME[family[1]] = family
    request = stun.Message(stun.Method.ALLOCATE, stun.Class.REQUEST, attributes={
        'REQUESTED-TRANSPORT': 17 << 24, 'REQUESTED-ADDRESS-FAMILY': 2 << 24,
    })
    try:
        await refused(ipv6.request_with_retry(request), (440,))
    finally:
        ipv6.transport.close()


if __name__ == '__main__':
    action = sys.argv[1]
    if action == 'config-server':
        http.server.ThreadingHTTPServer((OTHER_LOCAL, 8085), ConfigurationServer).serve_forever()
    elif action == 'keygen':
        os.umask(0o077)
        KEYFILE.write_text(json.dumps([secrets.token_urlsafe(32), secrets.token_urlsafe(32)]))
    elif action == 'provision':
        provision(sys.argv[2])
    elif action == 'positive':
        binding(PEER, sys.argv[2], True)
        uclient(sys.argv[2], int(sys.argv[3]))
    elif action == 'boundary':
        binding(PUBLIC, LAN, False)
        binding(PEER_IPV6, NEST_IPV6, False)
        binding(PEER, OTHER_LOCAL, False)
        asyncio.run(boundary())
    elif action == 'rotation':
        asyncio.run(rotation())
