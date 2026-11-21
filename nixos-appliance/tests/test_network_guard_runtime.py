"""Execute the boot network guard and first-boot unit graph with disposable fixtures."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'https://manage.example.test'
LEGACY_ORIGIN = 'https://old-manage.example.test'


def fixture_plan(dhcp4):
    interface = {'match': {'macaddress': '52:54:00:12:01:01'}, 'set-name': 'eth1', 'dhcp4': dhcp4, 'dhcp6': False}
    if not dhcp4:
        interface.update(addresses=['192.0.2.42/24'], routes=[{'to': 'default', 'via': '192.0.2.1'}],
                         nameservers={'addresses': ['192.0.2.53']})
    return {'network': {'version': 2, 'renderer': 'networkd', 'ethernets': {'tiaris-nest': interface}}}


@unittest.skipUnless(shutil.which('jq'), 'jq is required')
class NetworkGuardRuntimeTests(unittest.TestCase):
    """The guard re-applies the approved profile; networkd then resets the link."""

    def guard(self, *, dhcp4, approved_failures, fallback_failures=0, replacements=None, stored_origin=ORIGIN,
              marker='stale recovery evidence'):
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        root = Path(temporary)
        control, netplan, binaries = root / 'control', root / 'netplan', root / 'bin'
        for path in (control, netplan, binaries):
            path.mkdir()
        (control / 'netplan-approved.json').write_text(json.dumps(fixture_plan(dhcp4)))
        (control / 'netplan-dhcp-fallback.json').write_text(json.dumps(fixture_plan(True)))
        (control / 'install-plan.json').write_text('{}')
        (control / 'provisioning-state.json').write_text(json.dumps({'manage_origin': stored_origin}))
        (control / 'network-fallback-active').write_text(marker)

        def helper(name, body):
            path = binaries / name
            path.write_text(body)
            path.chmod(0o755)
            return str(path)

        activation = helper('activate', '#!/bin/sh\necho activated >> "$TEST_LOG"\n')
        # The compiled alias: the build's own origin for itself or its legacy name.
        bootstrap = helper('bootstrap', '''#!/bin/sh
test "$1" = effective-manage-origin && test "$#" -eq 2 || exit 2
case "$2" in "$TEST_ORIGIN" | "$TEST_LEGACY_ORIGIN") echo "$TEST_ORIGIN" ;; *) exit 1 ;; esac
''')
        # Fails while the link is "resetting": the first N requests after each
        # activation fail fast, as curl does while the lease/route is absent.
        helper('curl', '''#!/bin/sh
for last; do :; done
test "$last" = "$TEST_ORIGIN/healthz" || exit 2
activations=$(grep -c "^activated$" "$TEST_LOG")
if test "$activations" -eq 1; then allowed=$TEST_APPROVED_FAILURES; else allowed=$TEST_FALLBACK_FAILURES; fi
echo "curl $activations" >> "$TEST_LOG"
attempts=$(grep -c "^curl $activations$" "$TEST_LOG")
if test "$allowed" -ge 0 && test "$attempts" -gt "$allowed"; then exit 0; fi
echo "curl: (7) Failed to connect: Network is unreachable" >&2
exit 7
''')
        helper('chown', '#!/bin/sh\nexit 0\n')
        helper('install', '''#!/usr/bin/env python3
import shutil, sys
args = sys.argv[1:]; paths = []; i = 0
while i < len(args):
    if args[i] in ('-m', '-o', '-g'): i += 2
    else: paths.append(args[i]); i += 1
shutil.copyfile(*paths)
''')
        script = (ROOT / 'runtime/tiaris-nest-network-guard').read_text()
        substitutions = {'/var/lib/tiaris-nest/control': str(control), '/etc/netplan': str(netplan),
                         '/usr/lib/tiaris-nest/tiaris-nest-netplan-activate': activation,
                         '/usr/lib/tiaris-nest/tiaris-nest-bootstrap': bootstrap, **(replacements or {})}
        for old, new in substitutions.items():
            self.assertTrue(old in script, 'missing ' + old)
            script = script.replace(old, new)
        self.assertNotIn('/usr/lib/tiaris-nest/', script)
        log = root / 'log'
        log.touch()
        started = time.monotonic()
        result = subprocess.run(['bash', '-c', script, 'tiaris-nest-network-guard'],
            env={**os.environ, 'PATH': str(binaries) + os.pathsep + os.environ['PATH'], 'TEST_LOG': str(log),
                 'TEST_ORIGIN': ORIGIN, 'TEST_LEGACY_ORIGIN': LEGACY_ORIGIN, 'TEST_APPROVED_FAILURES': str(approved_failures),
                 'TEST_FALLBACK_FAILURES': str(fallback_failures)},
            text=True, capture_output=True, timeout=60)
        return SimpleResult(result, time.monotonic() - started, log.read_text().splitlines(), control, netplan)

    def test_dhcp_retries_while_networkd_reconfigures_the_link(self):
        # v0.2.77: the only request ran during the lease reset and failed boot.
        result = self.guard(dhcp4=True, approved_failures=2)
        self.assertEqual(result.process.returncode, 0, result.process.stderr)
        self.assertEqual(result.log, ['activated', 'curl 1', 'curl 1', 'curl 1'])
        self.assertEqual(sorted(p.name for p in result.control.iterdir()),
                         ['install-plan.json', 'netplan-approved.json', 'netplan-dhcp-fallback.json',
                          'provisioning-state.json'])
        self.assertEqual(json.loads((result.netplan / '90-tiaris-nest.yaml').read_text()), fixture_plan(True))

    def test_dhcp_without_tiaris_keeps_the_approved_profile_and_lets_the_nest_start(self):
        # A restart during an internet fault: the wait is bounded and the unit
        # succeeds, so the Nest service starts and reports the silence itself.
        result = self.guard(dhcp4=True, approved_failures=-1,
                            replacements={'management_reachable 30': 'management_reachable 3'})
        self.assertEqual(result.process.returncode, 0, result.process.stderr)
        self.assertGreaterEqual(result.log.count('curl 1'), 2)
        self.assertEqual(result.log.count('activated'), 1)
        self.assertLess(result.elapsed, 10)
        self.assertEqual(json.loads((result.netplan / '90-tiaris-nest.yaml').read_text()), fixture_plan(True))
        self.assertFalse((result.control / 'network-fallback-active').exists())

    def test_static_fallback_also_retries_after_its_link_reset(self):
        result = self.guard(dhcp4=False, approved_failures=-1, fallback_failures=1,
                            replacements={'management_reachable 30': 'management_reachable 2'})
        self.assertEqual(result.process.returncode, 0, result.process.stderr)
        self.assertEqual(result.log.count('activated'), 2)
        self.assertEqual(result.log[-2:], ['curl 2', 'curl 2'])
        marker = json.loads((result.control / 'network-fallback-active').read_text())
        self.assertEqual(marker['schema'], 'tiaris.nest.network-fallback.v1')
        self.assertEqual(json.loads((result.netplan / '90-tiaris-nest.yaml').read_text()), fixture_plan(True))

    def test_a_fixed_address_without_tiaris_on_either_profile_goes_back_to_the_approved_profile(self):
        # The internet is down, not the address: no DHCP fallback is left
        # behind, and the Nest starts on the address its computers know.
        result = self.guard(dhcp4=False, approved_failures=-1, fallback_failures=-1,
                            replacements={'management_reachable 30': 'management_reachable 2',
                                          'management_reachable 60': 'management_reachable 2'})
        self.assertEqual(result.process.returncode, 0, result.process.stderr)
        self.assertEqual(result.log.count('activated'), 3)
        self.assertIn('curl 1', result.log)
        self.assertIn('curl 2', result.log)
        self.assertLess(result.elapsed, 10)
        self.assertEqual(json.loads((result.netplan / '90-tiaris-nest.yaml').read_text()), fixture_plan(False))
        self.assertFalse((result.control / 'network-fallback-active').exists())

    def test_a_fixed_address_without_tiaris_stays_on_the_dhcp_fallback_it_last_worked_on(self):
        # The fixed address never worked on this network and the Nest served
        # the school on DHCP. A power cut brings the internet back last:
        # nothing probes again after this start, so going back to the fixed
        # address would leave the Nest unreachable until someone restarts it.
        approved = json.dumps(fixture_plan(False))
        marker = json.dumps({'schema': 'tiaris.nest.network-fallback.v1',
                             'approved_sha256': hashlib.sha256(approved.encode()).hexdigest()})
        result = self.guard(dhcp4=False, approved_failures=-1, fallback_failures=-1, marker=marker,
                            replacements={'management_reachable 30': 'management_reachable 2',
                                          'management_reachable 60': 'management_reachable 2'})
        self.assertEqual(result.process.returncode, 0, result.process.stderr)
        self.assertEqual(result.log.count('activated'), 2)
        self.assertEqual(json.loads((result.netplan / '90-tiaris-nest.yaml').read_text()), fixture_plan(True))
        self.assertEqual(json.loads((result.control / 'network-fallback-active').read_text()), json.loads(marker))
        self.assertEqual((result.control / 'network-fallback-active').stat().st_mode & 0o777, 0o600)

    def test_successful_static_retry_does_not_replace_the_approved_profile_with_dhcp(self):
        result = self.guard(dhcp4=False, approved_failures=1)
        self.assertEqual(result.process.returncode, 0, result.process.stderr)
        self.assertEqual(result.log, ['activated', 'curl 1', 'curl 1'])
        self.assertEqual(json.loads((result.netplan / '90-tiaris-nest.yaml').read_text()), fixture_plan(False))
        self.assertFalse((result.control / 'network-fallback-active').exists())

    def test_legacy_recorded_origin_probes_the_build_origin(self):
        # A Nest installed for manage.cybex.net boots a manage.tiaris.com build.
        result = self.guard(dhcp4=True, approved_failures=0, stored_origin=LEGACY_ORIGIN)
        self.assertEqual(result.process.returncode, 0, result.process.stderr)
        self.assertEqual(result.log, ['activated', 'curl 1'])
        self.assertEqual(json.loads((result.control / 'provisioning-state.json').read_text()),
                         {'manage_origin': LEGACY_ORIGIN})

    def test_unknown_recorded_origin_fails_before_any_request(self):
        result = self.guard(dhcp4=True, approved_failures=0, stored_origin='https://other.example.test')
        self.assertNotEqual(result.process.returncode, 0)
        self.assertEqual(result.log, ['activated'])

    def test_retry_windows_preserve_previous_request_budgets(self):
        script = (ROOT / 'runtime/tiaris-nest-network-guard').read_text()
        self.assertEqual(re.findall(r'management_reachable (\d+)', script), ['30', '60'])
        # Each request must keep the hardened transport policy.
        self.assertIn("--proto '=https' --tlsv1.2", script)


class SimpleResult:
    def __init__(self, process, elapsed, log, control, netplan):
        self.process, self.elapsed, self.log, self.control, self.netplan = process, elapsed, log, control, netplan


def unit_block(module, name):
    match = re.search(r'systemd\.services\.' + re.escape(name) + r' = (.*?)\n    systemd\.', module, re.DOTALL)
    if not match:
        raise AssertionError('unit not found: ' + name)
    return match.group(1)


def unit_list(block, key):
    lists = re.findall(r'(?<![A-Za-z])' + key + r' = \[([^\]]*)\]', block)
    return [item for value in lists for item in re.findall(r'"([^"]+)"', value)]


class RecoverySshUnitGraph(unittest.TestCase):
    module = (ROOT / 'module.nix').read_text()

    @unittest.skipUnless(shutil.which('nix-instantiate'), 'requires Nix for real module evaluation')
    def test_evaluated_service_graph_preserves_recovery_ssh(self):
        result = subprocess.run(
            ['nix-instantiate', '--eval', '--read-write-mode', '--strict', '--json', '--expr',
             'import ./nixos-appliance/tests/network-recovery-evaluation.nix {}'],
            cwd=ROOT.parent, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        checks = json.loads(result.stdout)
        self.assertEqual(set(checks), {
            'retryStartsRecoverySsh', 'sshFailureDoesNotFailFirstBoot', 'firstBootDoesNotWaitForSsh',
            'sshRequiresMaterializedTrust', 'sshRequiresFirewall', 'firewallFollowsFirstBoot',
            'nestRetriesFirstBoot', 'networkRuntimeCanRetryWithoutNest', 'networkRetryTimerRemainsEnabled',
            'startUpChecksDoNotWaitForTheNetwork', 'nothingRequiresTheNetworkGuard',
            'bootFileServerWaitsForTheNetworkAndNeverGivesUp'})
        self.assertTrue(all(value is True for value in checks.values()), checks)

    def test_sshd_keeps_requiring_materialized_trust_and_firewall(self):
        sshd = unit_block(self.module, 'sshd')
        self.assertEqual(sorted(unit_list(sshd, 'requires')),
                         ['tiaris-nest-firewall.service', 'tiaris-nest-first-boot.service'])
        self.assertEqual(sorted(unit_list(sshd, 'after')),
                         ['tiaris-nest-firewall.service', 'tiaris-nest-first-boot.service'])

    def test_a_later_successful_first_boot_also_starts_recovery_ssh(self):
        # A failed first attempt fails sshd's start job for the boot. The
        # network-runtime timer re-runs first-boot through tiaris-nest; that
        # transaction must include sshd as it already includes nginx/tftpd.
        first_boot = unit_block(self.module, 'tiaris-nest-first-boot')
        self.assertIn('sshd.service', unit_list(first_boot, 'wants'))
        self.assertNotIn('sshd.service', unit_list(first_boot, 'requires'))
        self.assertNotIn('sshd.service', unit_list(first_boot, 'after'))

    def test_services_start_without_tiaris(self):
        # B25: nginx, the boot file server, SSH and the Nest service require
        # the start-up checks, which therefore never wait for the network; the
        # one unit that asks Tiaris is required by nothing.
        first_boot = unit_block(self.module, 'tiaris-nest-first-boot')
        self.assertNotIn('network-online.target', unit_list(first_boot, 'after') + unit_list(first_boot, 'wants'))
        script = (ROOT / 'runtime/tiaris-nest-first-boot').read_text()
        self.assertNotRegex(script, r'run\([^)]*(network-guard|reconcile-network-runtime)')
        self.assertNotRegex(self.module, r'requires = \[[^\]]*tiaris-nest-network-guard')
        guard = unit_block(self.module, 'tiaris-nest-network-guard')
        self.assertIn('tiaris-nest.service', unit_list(guard, 'before'))


if __name__ == '__main__':
    unittest.main()
