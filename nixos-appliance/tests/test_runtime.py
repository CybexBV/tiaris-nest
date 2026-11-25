"""Safety boundaries and durable recovery, without modifying the host runtime."""
import base64
import contextlib
import copy
import datetime
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

RUNTIME = Path(__file__).resolve().parents[1] / 'runtime'
sys.path.insert(0, str(RUNTIME))
import appliance_state as state
import generation_update as update
import self_cache_trust as trust


def script(name):
    loader = SourceFileLoader(name.removesuffix('.py').replace('-', '_'), str(RUNTIME / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


window = script('tiaris-nest-appliance-update-window')
network = script('tiaris-nest-netplan-activate')
firewall = script('tiaris-nest-firewall')
first_boot = script('tiaris-nest-first-boot')
source_copy = script('source-copy.py')
pxe = script('tiaris-nest-pxe')



class PxeDocument(unittest.TestCase):
    NOW = 1_800_000_000

    def document(self, **changes):
        wrapper = {'received_at': self.NOW, 'bootloader_filename': 'snponly.efi',
                   'desired': {'schema': pxe.SCHEMA, 'server_device_id': 'nest-1', 'complete': True}}
        wrapper.update(changes)
        return wrapper

    def test_without_tiaris_the_last_document_keeps_serving_as_stale(self):
        self.assertEqual(pxe.validate_desired(self.document(), self.NOW)[1:], ('snponly.efi', False))
        desired, _, stale = pxe.validate_desired(self.document(), self.NOW + 7 * 24 * 3600)
        self.assertTrue(stale)
        self.assertEqual(desired['server_device_id'], 'nest-1')

    def test_a_file_nest_0_2_177_wrote_serves_with_the_boot_file_of_its_own_row(self):
        # What an update from 0.2.177 finds, often before it reaches Tiaris.
        before = json.loads((RUNTIME.parents[1] / 'protocol/fixtures/pxe-discovery-nest-0.2.177.json').read_text())
        self.assertEqual(pxe.validate_desired(before, self.NOW + 7 * 24 * 3600)[1:], ('ipxe.efi', True))
        # 0.2.177 did not answer without its own row either.
        before['desired']['peers'] = []
        with self.assertRaisesRegex(pxe.Unavailable, 'awaiting_appliance_report'):
            pxe.validate_desired(before, self.NOW)

    def test_an_incomplete_withdrawn_or_malformed_document_is_refused(self):
        for document, reason in (
                (self.document(desired={'schema': pxe.SCHEMA, 'server_device_id': 'nest-1', 'complete': False}), 'inventory_incomplete'),
                (self.document(desired=None), 'inventory_unavailable'),
                (self.document(received_at='yesterday'), 'inventory_unavailable'),
                (self.document(bootloader_filename='../x.efi'), 'inventory_unavailable'),
                (self.document(desired={'schema': pxe.SCHEMA, 'server_device_id': 'a/b', 'complete': True}), 'invalid_identity')):
            with self.assertRaisesRegex(pxe.Unavailable, reason):
                pxe.validate_desired(document, self.NOW)


class StartCheckReason(unittest.TestCase):
    def test_a_failed_check_names_its_reason_on_the_screen_until_the_checks_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'console-status.json'
            with patch.object(first_boot, 'directory'), \
                    patch.object(first_boot, 'write', lambda target, body, **_: Path(target).write_bytes(body)):
                first_boot.show_failure('The Nest settings are not valid.', path=path)
            status = json.loads(path.read_text())
            self.assertEqual((status['schema'], status['state']), ('tiaris.nest-console-status.v1', 'attention'))
            self.assertEqual(status['attention']['code'], 'start_check_failed')
            self.assertTrue(status['attention']['detail'].startswith('The Nest settings are not valid.'))
            self.assertLessEqual(len(status['attention']['detail']), 240)
            first_boot.clear_failure(path)
            self.assertFalse(path.exists())
            # The Nest service's own status is never removed.
            path.write_text(json.dumps({'state': 'healthy'}))
            first_boot.clear_failure(path)
            self.assertTrue(path.exists())


class ReadBoundary(unittest.TestCase):
    def test_rejects_links_writable_files_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt'
            path.write_text('{}')
            path.chmod(0o600)
            self.assertEqual(state.read(path, owner=os.getuid()), b'{}')
            with self.assertRaises(ValueError):
                state.read(path, owner=os.getuid(), maximum=1)
            path.chmod(0o666)
            with self.assertRaises(ValueError):
                state.read(path, owner=os.getuid())
            path.chmod(0o600)
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaises(OSError):
                state.read(link, owner=os.getuid())
            link.unlink()
            os.link(path, link)
            with self.assertRaises(ValueError):
                state.read(path, owner=os.getuid())

    def test_unknown_generations_are_omitted(self):
        with patch.object(state, 'save') as save:
            state.emit_status({'attempt_id': 'attempt'}, 'waiting_window', 'nest_busy')
            value = save.call_args.args[1]
            self.assertNotIn('candidate_system_generation', value)
            self.assertNotIn('resulting_system_generation', value)
            with self.assertRaises(ValueError):
                state.emit_status({'candidate_generation': '0'}, 'failed', 'failed')


class MaintenancePolicy(unittest.TestCase):
    request = {'attempt_id': 'a', 'release': {'release_id': '1.2.3', 'system_closure': {'sha256': 'digest'}}}

    def policy(self, weekdays, start, duration, timezone='UTC'):
        return {'schedule': {'weekdays': weekdays, 'start': start, 'duration_minutes': duration, 'timezone': timezone}}

    def check(self, policy, timestamp):
        """Whether a Nest that is busy may update at `timestamp`: the night deadline."""
        return window.allowed(policy, self.request, datetime.datetime.fromisoformat(timestamp), lambda now: False)

    def test_saturday_window_crosses_sunday_boundary(self):
        policy = self.policy([6], '23:30', 120)
        self.assertTrue(self.check(policy, '2026-09-20T00:45:00+00:00'))
        self.assertFalse(self.check(policy, '2026-09-20T01:30:00+00:00'))
        self.assertFalse(self.check(policy, '2026-09-19T23:29:00+00:00'))

    def test_timezone_and_repeated_dst_hour(self):
        policy = self.policy([0], '02:15', 30, 'Europe/Amsterdam')
        self.assertTrue(self.check(policy, '2026-10-25T00:20:00+00:00'))
        self.assertTrue(self.check(policy, '2026-10-25T01:20:00+00:00'))
        self.assertFalse(self.check(policy, '2026-10-25T02:20:00+00:00'))

    def test_run_now_binds_attempt_release_and_closure(self):
        policy = self.policy([], '00:00', 60)
        policy['run_now'] = {'attempt_id': 'a', 'release_id': '1.2.3', 'system_closure_sha256': 'digest'}
        self.assertTrue(self.check(policy, '2026-09-20T12:00:00+00:00'))
        for key in policy['run_now']:
            changed = copy.deepcopy(policy)
            changed['run_now'][key] = 'different'
            self.assertFalse(self.check(changed, '2026-09-20T12:00:00+00:00'))

    def test_waits_for_an_idle_nest_until_the_night_and_run_now_skips_it(self):
        policy = self.policy([0], '02:00', 60)
        policy['mode'] = 'when_idle'
        at = datetime.datetime.fromisoformat('2026-09-23T12:00:00+00:00')
        self.assertIsNone(window.waiting_for(policy, self.request, at, lambda now: True))
        self.assertEqual(window.waiting_for(policy, self.request, at, lambda now: False), 'nest_busy')
        policy['run_now'] = {'attempt_id': 'a', 'release_id': '1.2.3', 'system_closure_sha256': 'digest'}
        self.assertIsNone(window.waiting_for(policy, self.request, at, lambda now: False))

    def test_a_nest_that_is_never_idle_updates_in_the_night(self):
        # Every night, 02:00 for two hours, as Manage signs it.
        policy = self.policy(list(range(7)), '02:00', 120)
        policy['mode'] = 'when_idle'
        busy = lambda now: False
        for moment, expected in (('2026-09-23T01:59:00+00:00', 'nest_busy'), ('2026-09-23T02:00:00+00:00', None),
                                 ('2026-09-23T03:59:00+00:00', None), ('2026-09-23T04:00:00+00:00', 'nest_busy')):
            at = datetime.datetime.fromisoformat(moment)
            self.assertEqual(window.waiting_for(policy, self.request, at, busy), expected, moment)

    def test_there_are_no_modes_any_more(self):
        # A policy signed before 19 November 2026 may name `window` or no mode
        # (schema v1): the Nest reads it like any other.
        at = datetime.datetime.fromisoformat('2026-09-23T12:00:00+00:00')
        for mode in (None, 'window', 'when_idle'):
            policy = self.policy([0], '02:00', 60)
            if mode:
                policy['mode'] = mode
            self.assertIsNone(window.waiting_for(policy, self.request, at, lambda now: True))
            self.assertEqual(window.waiting_for(policy, self.request, at, lambda now: False), 'nest_busy')


class NestActivity(unittest.TestCase):
    now = datetime.datetime(2026, 9, 23, 12, 0, tzinfo=datetime.timezone.utc)

    def write(self, directory, **fields):
        report = {'schema': 'tiaris.nest.activity.v1', 'written_at': '2026-09-23T11:59:40Z',
                  'idle_since': '2026-09-23T11:45:00Z', 'busy': [], **fields}
        path = Path(directory) / 'activity.json'
        path.unlink(missing_ok=True)
        path.write_text(json.dumps(report))
        path.chmod(0o644)
        return path

    def idle(self, path, uptime=7200):
        with patch.object(window, 'UID', os.getuid()):
            return window.idle(self.now, path, lambda: uptime)

    def test_quiet_for_ten_minutes_is_idle(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(self.idle(self.write(directory)))
            self.assertFalse(self.idle(self.write(directory, idle_since='2026-09-23T11:51:00Z')))
            self.assertFalse(self.idle(self.write(directory, idle_since=None, busy=['computers_starting'])))
            self.assertFalse(self.idle(self.write(directory, busy=['building_apps'])))

    def test_a_missing_stale_or_forged_report_waits_for_uptime(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / 'missing.json'
            self.assertFalse(self.idle(missing, uptime=600))
            self.assertTrue(self.idle(missing, uptime=3600))
            stale = self.write(directory, written_at='2026-09-23T11:50:00Z')
            self.assertFalse(self.idle(stale, uptime=600))
            self.assertTrue(self.idle(stale, uptime=3600))
            future = self.write(directory, written_at='2026-09-23T12:05:00Z')
            self.assertFalse(self.idle(future, uptime=600))
            unknown = self.write(directory, schema='other')
            self.assertFalse(self.idle(unknown, uptime=600))
            writable = self.write(directory)
            writable.chmod(0o666)
            self.assertFalse(self.idle(writable, uptime=600))


class PrepareThenSwitch(unittest.TestCase):
    attempt = '11111111-1111-4111-8111-111111111111'
    toplevel = '/nix/store/0c7c9lr2kqyskkqm1ppa0w1bx8hlh8sm-nixos-system-nest'

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.body = state.canonical({'attempt_id': self.attempt})
        self.roots = self.directory / 'roots'
        self.roots.mkdir()
        self.system = self.directory / 'system'
        self.system.mkdir()
        (self.roots / ('pending-' + self.attempt)).symlink_to(self.system)
        self.prepared = {'schema': update.PREPARED_SCHEMA, 'attempt_id': self.attempt,
                         'request_sha256': hashlib.sha256(self.body).hexdigest(),
                         'source_system_generation': '1', 'source_system_toplevel': '/source',
                         'cache_path': str(update.STAGING / 'private' / self.attempt / 'cache'),
                         'system_toplevel': str(self.system), 'retire_generations': []}

    def tearDown(self):
        self.temporary.cleanup()

    def found(self, prepared=None, source=None):
        with patch.object(update, 'read', return_value=self.body), \
                patch.object(update, 'load', return_value=prepared or self.prepared), \
                patch.object(update, 'ROOTS', self.roots), \
                patch.object(update, 'current', return_value=source or {'system_generation': '1', 'system_toplevel': '/source'}):
            return update.prepared_update()

    def test_reuses_only_the_exact_prepared_request_on_the_same_system(self):
        self.assertEqual(self.found(), self.prepared)
        for key, value in (('request_sha256', 'different'), ('schema', 'other'), ('attempt_id', 'x'),
                           ('system_toplevel', '/elsewhere'), ('cache_path', '/tmp/cache')):
            with self.subTest(key=key):
                self.assertIsNone(self.found({**self.prepared, key: value}))
        self.assertIsNone(self.found(source={'system_generation': '2', 'system_toplevel': '/source'}))
        (self.roots / ('pending-' + self.attempt)).unlink()
        self.assertIsNone(self.found())

    # The last report of an update that began: its switch was interrupted, or
    # it waited (for Tiaris, then for the Nest to be idle).
    INTERRUPTED = {'status': 'preparing', 'stage': 'activating'}
    WAITED = {'status': 'preparing', 'stage': 'no_manage_contact'}

    def run_stage(self, prepared, waiting, report=None, contact=True):
        calls = []
        with patch.object(update, 'REQUEST', self.directory / 'request.json'), \
                patch.object(update, 'maintenance_lock', return_value=nullcontext()), \
                patch.object(update, 'PENDING', self.directory / 'none'), \
                patch.object(update, 'PREPARE', self.directory / 'none'), \
                patch.object(update, 'COMMIT', self.directory / 'none'), \
                patch.object(update, 'ROLLBACK', self.directory / 'none'), \
                patch.object(update, 'prepared_update', return_value=prepared), \
                patch.object(update, 'drop_prepared', side_effect=lambda: calls.append('drop')), \
                patch.object(update, 'prepare', side_effect=lambda: calls.append('prepare') or self.prepared), \
                patch.object(update, 'waiting_for', side_effect=lambda: calls.append('gate') or (waiting, 'why')), \
                patch.object(update, 'contact_fresh', return_value=contact), \
                patch.object(update, 'last_report', return_value=report or {}), \
                patch.object(update, 'activate', side_effect=lambda receipt: calls.append('activate')), \
                patch.object(update, 'emit_status', side_effect=lambda receipt, status, stage, *a: calls.append((status, stage))):
            (self.directory / 'request.json').write_text('{}')
            update.stage()
        return calls

    def test_prepares_before_waiting_and_switches_only_when_allowed(self):
        self.assertEqual(self.run_stage(None, 'nest_busy'), ['drop', 'prepare', 'gate', ('waiting_window', 'nest_busy')])
        self.assertEqual(self.run_stage(self.prepared, None), ['gate', 'activate'])
        # A switch that a restart interrupted goes on without asking again.
        self.assertEqual(self.run_stage(self.prepared, 'nest_busy', report=self.INTERRUPTED), ['activate'])

    def test_an_update_that_waited_for_tiaris_asks_the_policy_again(self):
        # The link may come back in the middle of a school day. The report
        # stays started; the stage says what the update waits for now.
        self.assertEqual(self.run_stage(self.prepared, 'nest_busy', report=self.WAITED),
                         ['gate', ('preparing', 'nest_busy')])
        self.assertEqual(self.run_stage(self.prepared, 'nest_busy', report={'status': 'preparing', 'stage': 'nest_busy'}),
                         ['gate', ('preparing', 'nest_busy')])
        self.assertEqual(self.run_stage(self.prepared, None, report=self.WAITED), ['gate', 'activate'])

    def test_a_nest_that_cannot_reach_tiaris_keeps_what_it_prepared_and_waits(self):
        # The candidate would have to reach Tiaris to stay: switching now
        # ends in a rollback, and the next try downloads everything again.
        self.assertEqual(self.run_stage(self.prepared, None, contact=False),
                         ['gate', ('waiting_window', 'no_manage_contact')])
        # Also an activation that a power cut interrupted; its report stays started.
        self.assertEqual(self.run_stage(self.prepared, None, report=self.INTERRUPTED, contact=False),
                         [('preparing', 'no_manage_contact')])

    def test_a_replaced_request_leaves_nothing_prepared_behind(self):
        staging, control = self.directory / 'staging', self.directory / 'control'
        other = '22222222-2222-4222-8222-222222222222'
        for parent in (staging / 'private', control / 'appliance-updates'):
            (parent / other).mkdir(parents=True)
            (parent / other / 'receipt.json').write_text('{}')
        (control / 'appliance-updates' / '0.2.30').mkdir()
        (self.roots / ('good-7')).symlink_to(self.system)
        with patch.object(update, 'STAGING', staging), patch.object(update, 'CONTROL', control), \
                patch.object(update, 'ROOTS', self.roots):
            update.drop_prepared(owner=os.getuid())
        self.assertEqual(list((staging / 'private').iterdir()), [])
        self.assertEqual(sorted(path.name for path in (control / 'appliance-updates').iterdir()), ['0.2.30'])
        self.assertEqual(sorted(path.name for path in self.roots.iterdir()), ['good-7'])

    def test_the_gate_names_what_it_waits_for(self):
        for code, output, expected in ((0, '', (None, '')), (0, 'the Nest is idle (quiet)\n', (None, 'the Nest is idle (quiet)')),
                                       (75, 'nest_busy\n', ('nest_busy', '')), (75, '', ('nest_busy', '')),
                                       (75, 'nest_busy\nthe Nest is busy (it is building apps)\n',
                                        ('nest_busy', 'the Nest is busy (it is building apps)'))):
            with patch.object(update.subprocess, 'run', return_value=SimpleNamespace(returncode=code, stdout=output)):
                self.assertEqual(update.waiting_for(), expected)
        with patch.object(update.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout='')):
            with self.assertRaisesRegex(ValueError, 'invalid update policy'):
                update.waiting_for()

    def test_nothing_touches_boot_state_before_the_gate_opens(self):
        source = (RUNTIME / 'generation_update.py').read_text()
        prepare = source[source.index('def prepare():'):source.index('def activate(')]
        for mutation in ('save(PREPARE', 'set_default(', "'--set'", 'switch-to-configuration', 'bootctl', 'reboot', 'retire_generations('):
            self.assertNotIn(mutation, prepare)
        stage = source[source.index('def stage():'):source.index('BOOTSTRAP = ')]
        self.assertLess(stage.index('prepare()'), stage.index('waiting_for()'))
        self.assertLess(stage.index('waiting_for()'), stage.index('activate(prepared)'))


class RoomForAnUpdate(unittest.TestCase):
    """An update is refused for disk space only after the Nest made room."""
    def test_cache_retention_is_asked_first_and_garbage_goes_only_when_still_short(self):
        for retention_frees, expected in ((60, ['retention']), (10, ['retention', 'gc']), (None, ['retention', 'gc'])):
            with self.subTest(retention_frees=retention_frees):
                free, steps = [40], []
                def retention(*command, **kwargs):
                    # As the service user, for exactly the bytes the verifier named.
                    self.assertEqual(command[:5], ('setpriv', '--reuid', '985', '--regid', '985'))
                    self.assertEqual(command[-3:], ('free-cache-space', '--available-bytes', '100'))
                    steps.append('retention')
                    if retention_frees is None:
                        raise subprocess.CalledProcessError(1, command)
                    free[0] += retention_frees
                with patch.object(update.shutil, 'disk_usage', side_effect=lambda path: SimpleNamespace(free=free[0])), \
                        patch.object(update, 'run', side_effect=retention), \
                        patch.object(update, 'collect_garbage', side_effect=lambda: steps.append('gc')):
                    self.assertEqual(update.make_room(100), 'gc' in expected)
                self.assertEqual(steps, expected)
        # The attempt collected the store's garbage before: not again.
        with patch.object(update.shutil, 'disk_usage', return_value=SimpleNamespace(free=40)), \
                patch.object(update, 'run') as retention, patch.object(update, 'collect_garbage') as collect:
            self.assertFalse(update.make_room(100, collect=False))
        retention.assert_called_once()
        collect.assert_not_called()
        with patch.object(update.shutil, 'disk_usage', return_value=SimpleNamespace(free=100)), \
                patch.object(update, 'run') as retention, patch.object(update, 'collect_garbage') as collect:
            update.make_room(100)
        retention.assert_not_called()
        collect.assert_not_called()

    def verify(self, *results):
        commands, room = [], []
        results = iter(results)
        def verifier(command, **kwargs):
            commands.append(command[2:])
            code, output = next(results)
            return SimpleNamespace(returncode=code, stdout=output, stderr='Error: insufficient_store_space' if code == 1 else '')
        # Short of space, cache retention is never enough here: garbage goes.
        def make_room(required, collect):
            room.append((required, collect))
            return collect
        with patch.object(update.subprocess, 'run', side_effect=verifier), \
                patch.object(update, 'make_room', side_effect=make_room):
            try:
                return update.verified_cache(), commands, room
            except subprocess.CalledProcessError:
                return None, commands, room

    def test_the_verifier_refuses_for_disk_space_only_after_room_was_made(self):
        # Enough room: nothing is freed.
        self.assertEqual(self.verify((0, '/private/cache\n')), (Path('/private/cache'), [[]], []))
        # Short of space: make the room the verifier names, then it passes.
        self.assertEqual(self.verify((75, '100\n'), (0, '/private/cache\n')),
                         (Path('/private/cache'), [[], []], [(100, True)]))
        # Still short after making room twice: the last run may end the attempt.
        # The store's garbage went the first time and is not collected again.
        self.assertEqual(self.verify((75, '100\n'), (75, '300\n'), (1, '')),
                         (None, [[], [], ['--space-freed']], [(100, True), (300, False)]))


    def download_room(self, free_after, staged=False):
        """What root does with the service's request for room when making
        room leaves `free_after` bytes free; whether the request is gone."""
        release = {'release_id': '0.2.31', 'source_revision': 'r', 'system_toplevel': '/candidate',
                   'system_closure': {'sha256': 'c' * 64}}
        ask = {'attempt_id': '11111111-1111-4111-8111-111111111111', 'release': release, 'required_available_bytes': 100}
        free, made, statuses = [40], [], []
        def make_room(required):
            made.append(required)
            free[0] = free_after
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            room, request = Path(directory) / 'room.json', Path(directory) / 'request.json'
            room.write_text(json.dumps(ask))
            if staged:
                request.write_text('{}')
            none = Path(directory) / 'none'
            for name, value in (('ROOM', room), ('REQUEST', request), ('PENDING', none), ('PREPARE', none),
                                ('COMMIT', none), ('ROLLBACK', none), ('maintenance_lock', nullcontext),
                                ('load', lambda path, **kw: json.loads(path.read_text())),
                                ('remove', lambda path: path.unlink(missing_ok=True)), ('make_room', make_room),
                                ('current', lambda: {'system_generation': '1'}),
                                ('emit_status', lambda identity, *status: statuses.append((identity['target_release'], *status)))):
                stack.enter_context(patch.object(update, name, value))
            stack.enter_context(patch.object(update.shutil, 'disk_usage', side_effect=lambda path: SimpleNamespace(free=free[0])))
            update.make_download_room()
            return made, statuses, room.exists()

    def test_a_download_that_does_not_fit_gets_room_or_ends_with_the_reason(self):
        # The service's next try finds room: nothing to report.
        self.assertEqual(self.download_room(free_after=100), ([100], [], False))
        # Still short: the attempt ends with the reason, as it would later.
        self.assertEqual(self.download_room(free_after=99),
                         ([100], [('0.2.31', 'failed', 'verification_failed', 'insufficient_store_space', '1')], False))
        # A staged update goes first; preparing it makes its own room.
        self.assertEqual(self.download_room(free_after=99, staged=True), ([], [], False))

    def test_a_boot_partition_that_filled_up_before_the_switch_is_named(self):
        prepared = {'attempt_id': '11111111-1111-4111-8111-111111111111', 'cache_path': '/cache',
                    'system_toplevel': '/candidate', 'retire_generations': []}
        with tempfile.TemporaryDirectory() as roots, patch.object(update, 'ROOTS', Path(roots)), \
                patch.object(update, 'verify_store_closure'), patch.object(update, 'cleanup'), \
                patch.object(update, 'current', return_value={'system_generation': '1'}), \
                patch.object(update.shutil, 'disk_usage', return_value=SimpleNamespace(free=255 * 1024 ** 2)), \
                patch.object(update, 'emit_status') as emit:
            with self.assertRaises(update.BootPartitionFull):
                update.activate(prepared)
        self.assertEqual(emit.call_args.args[1:], ('failed', 'verification_failed', 'insufficient_esp_space', '1'))


class NetworkPolicy(unittest.TestCase):
    def config(self):
        return {'network': {'version': 2, 'renderer': 'networkd', 'ethernets': {'tiaris-nest': {
            'set-name': 'enp1s0', 'match': {'macaddress': '02:00:00:00:00:42'}, 'dhcp4': False, 'dhcp6': False,
            'addresses': ['192.0.2.42/24'], 'routes': [{'to': 'default', 'via': '192.0.2.1'}],
            'nameservers': {'addresses': ['192.0.2.53']}}}}}

    def test_static_and_dhcp_emit_one_exact_networkd_match(self):
        value = self.config()
        name, output = network.render(value)
        self.assertEqual(name, 'enp1s0')
        self.assertIn(b'Address=192.0.2.42/24\nGateway=192.0.2.1\nDNS=192.0.2.53\n', output)
        interface = value['network']['ethernets']['tiaris-nest']
        interface['dhcp4'] = True
        name, output = network.render(value)
        self.assertIn(b'DHCP=ipv4\n', output)
        self.assertNotIn(b'\nAddress=', output)

    def test_rejects_multicast_mac_and_config_injection(self):
        for key, value in [('set-name', 'eth0\n[Network]'), ('set-name', 'lo'), ('dhcp4', 'true')]:
            config = self.config()
            config['network']['ethernets']['tiaris-nest'][key] = value
            with self.assertRaises(ValueError):
                network.render(config)
        config = self.config()
        config['network']['ethernets']['tiaris-nest']['match']['macaddress'] = '01:00:00:00:00:01'
        with self.assertRaises(ValueError):
            network.render(config)

    def test_atomic_firewall_enforces_default_deny_allowlist_and_ssh_boundary(self):
        rules = firewall.render('192.0.2.0/24\n2001:db8::/32\n', True)
        self.assertTrue(rules.startswith('delete table inet tiaris_nest\n'))
        self.assertIn('type filter hook input priority -10; policy drop;', rules)
        self.assertIn('ct helper tftp4 {', rules)
        self.assertIn('iifname "lo" accept', rules)
        self.assertIn('ct state invalid drop', rules)
        self.assertIn('ct state established,related accept', rules)
        self.assertIn('tcp dport 80 accept', rules)
        self.assertIn('udp dport { 67, 68, 4011 } accept', rules)
        self.assertIn('meta nfproto ipv4 udp dport 69 ct helper set "tftp4" accept', rules)
        self.assertIn('udp dport 123 accept', rules)
        self.assertIn('udp dport { 3478, 61000-61040 } accept', rules)
        self.assertIn('ip saddr { 192.0.2.0/24 } tcp dport 22 accept', rules)
        self.assertIn('ip6 saddr { 2001:db8::/32 } tcp dport 22 accept', rules)
        self.assertTrue(rules.endswith('tcp dport 22 drop\n}\n}\n'))
        with self.assertRaises(ValueError):
            firewall.render('192.0.2.0/24; accept', False)


class PermissionLayout(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.uid, self.gid = os.getuid(), os.getgid()

    def strict_umask(self):
        class Umask:
            def __enter__(_self):
                _self.previous = os.umask(0o077)

            def __exit__(_self, *_args):
                os.umask(_self.previous)

        return Umask()

    def test_the_running_nest_names_its_own_boot_entry_for_the_next_start(self):
        # B26: with the Nest ISO still attached a virtual machine starts the
        # installer again; BootNext keeps the next start on the installed disk.
        import boot_next
        efivars = self.root / 'efivars'
        self.assertFalse(boot_next.start_from_this_disk_next_time(efivars))  # no UEFI variables: start as before
        efivars.mkdir()
        (efivars / ('BootCurrent-' + boot_next.GLOBAL)).write_bytes(b'\x06\x00\x00\x00\x03\x00')
        self.assertTrue(boot_next.start_from_this_disk_next_time(efivars))
        self.assertEqual((efivars / ('BootNext-' + boot_next.GLOBAL)).read_bytes(), b'\x07\x00\x00\x00\x03\x00')

    def test_first_boot_private_parent_and_public_leaves_ignore_service_umask(self):
        cache = self.root / 'cache'
        with self.strict_umask():
            first_boot.prepare_cache_directories(
                cache, self.uid, self.gid, self.uid, self.gid)
        self.assertEqual(cache.stat().st_mode & 0o777, 0o755)
        agent = cache / 'agent'
        self.assertEqual((agent.stat().st_uid, agent.stat().st_gid, agent.stat().st_mode & 0o777),
                         (self.uid, self.gid, 0o700))
        for name in ('home', 'cache', 'config', 'state', 'tmp'):
            child = agent / name
            self.assertEqual((child.stat().st_uid, child.stat().st_gid, child.stat().st_mode & 0o777),
                             (self.uid, self.gid, 0o700))
        self.assertEqual((cache / 'www').stat().st_mode & 0o777, 0o755)
        # nginx (another user) sends the cache members: it enters the cache root.
        self.assertEqual((cache / 'www/cache').stat().st_mode & 0o777, 0o755)
        for name in ('build', 'build-outputs'):
            self.assertEqual((cache / name).stat().st_mode & 0o777, 0o750)
        self.assertEqual((cache / 'vulnix').stat().st_mode & 0o777, 0o700)
        self.assertEqual((cache / 'tftp').stat().st_mode & 0o777, 0o755)

    def test_netplan_activate_skips_reconfigure_only_when_file_matches_and_selected(self):
        runtime = self.root / 'run'
        target = runtime / 'systemd/network/10-tiaris-nest.network'
        target.parent.mkdir(parents=True)
        body = b'[Match]\nName=eth0\nMACAddress=52:54:00:12:01:01\n\n[Network]\nIPv6AcceptRA=no\nLinkLocalAddressing=no\nDHCP=ipv4\n'
        target.write_bytes(body)
        target.chmod(0o640)
        with patch.object(network.os, 'fstat') as mock_fstat:
            real_stat = target.stat()
            fake_meta = type('Meta', (), {
                'st_mode': (real_stat.st_mode & ~0o777) | 0o640,
                'st_uid': 0,
                'st_gid': 42,
                'st_nlink': 1,
            })()
            mock_fstat.return_value = fake_meta
            self.assertTrue(network.target_matches(target, body, 42))
            self.assertFalse(network.target_matches(target, body + b'extra', 42))
            self.assertFalse(network.target_matches(target, body, 99))
        selected = subprocess.CompletedProcess(['networkctl'], 0, stdout=f'  Network File: {target}\n', stderr='')
        unselected = subprocess.CompletedProcess(['networkctl'], 0, stdout='  Network File: /etc/systemd/network/other.network\n', stderr='')
        with patch.object(network.subprocess, 'run', return_value=selected):
            self.assertTrue(network.profile_selected('eth0', target))
        with patch.object(network.subprocess, 'run', return_value=unselected):
            self.assertFalse(network.profile_selected('eth0', target))

    def test_public_runtime_and_source_directories_repair_only_owned_ordinary_paths(self):
        runtime = self.root / 'run'
        source = self.root / 'source'
        source.mkdir()
        with self.strict_umask():
            runtime.mkdir()
            network.prepare_runtime_directory(runtime, self.uid, self.gid)
            destination = self.root / 'public-source'
            source_copy.copy_source(source, destination, owner=self.uid)
        for path in (runtime, runtime / 'systemd', runtime / 'systemd/network', destination):
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        unsafe = self.root / 'unsafe-run'
        unsafe.mkdir()
        (unsafe / 'systemd').symlink_to(runtime / 'systemd', target_is_directory=True)
        with self.assertRaises(ValueError):
            network.prepare_runtime_directory(unsafe, self.uid, self.gid)
        linked = self.root / 'linked-source'
        linked.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(ValueError):
            source_copy.copy_source(source, linked, owner=self.uid)

class Recovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.paths = {}
        for name in ('PENDING', 'PREPARE', 'COMMIT', 'ROLLBACK', 'INSTALLED', 'KNOWN'):
            path = self.directory / name
            self.paths[name] = path
            self.enterContext(patch.object(update, name, path))
        self.enterContext(patch.object(update, 'load', lambda path, **kw: json.loads(path.read_text())))
        self.enterContext(patch.object(update, 'save', lambda path, value: path.write_bytes(state.canonical(value))))
        self.enterContext(patch.object(update, 'remove', lambda path: path.unlink(missing_ok=True)))
        self.receipt = {'schema': 'tiaris.nest.pending-system-generation.v3',
            'attempt_id': '11111111-1111-4111-8111-111111111111', 'system_toplevel': '/candidate',
            'source_toplevel': '/source', 'candidate_generation': '2', 'source_generation': '1',
            'candidate_loader_entry': 'nixos-generation-2.conf', 'source_loader_entry': 'nixos-generation-1.conf',
            'source_installed': {'old': 'receipt'}, 'source_known_good': {'generations': [{'system_generation': '1'}]}}
        self.booted = {'system_toplevel': '/source', 'system_generation': '1'}
        self.enterContext(patch.object(update, 'current', lambda: self.booted))
        self.actions = {}
        for name in ('restore_source', 'prune_candidate', 'cleanup', 'emit_status', 'set_default'):
            self.actions[name] = self.enterContext(patch.object(update, name))
        self.enterContext(patch.object(update, 'terminal_matches', return_value=False))
        self.enterContext(patch.object(update, 'ROOTS', self.directory / 'roots'))

    def test_source_fallback_restores_receipt_and_known_history(self):
        self.paths['PENDING'].write_bytes(state.canonical(self.receipt))
        update.recover_boot()
        self.assertEqual(json.loads(self.paths['INSTALLED'].read_text()), self.receipt['source_installed'])
        self.assertEqual(json.loads(self.paths['KNOWN'].read_text()), self.receipt['source_known_good'])
        self.assertFalse(self.paths['PENDING'].exists())
        self.assertEqual(self.actions['emit_status'].call_args.args[1:], ('rolled_back', 'boot_fallback', 'candidate_boot_failed', '1'))

    def test_unsealed_profile_creation_is_discovered_and_removed(self):
        receipt = dict(self.receipt)
        receipt.pop('candidate_generation')
        receipt.pop('candidate_loader_entry')
        self.paths['PREPARE'].write_bytes(state.canonical(receipt))
        self.paths['KNOWN'].write_text('{}')
        with patch.object(update, 'generation_for', return_value='2'):
            update.recover_boot()
        recovered = self.actions['prune_candidate'].call_args.args[0]
        self.assertEqual(recovered['candidate_generation'], '2')
        self.assertFalse(self.paths['PREPARE'].exists())

    def test_unsealed_candidate_and_unknown_boot_fail_closed(self):
        self.paths['PREPARE'].write_bytes(state.canonical(self.receipt))
        self.booted = {'system_toplevel': '/candidate', 'system_generation': '2'}
        with self.assertRaisesRegex(ValueError, 'unsealed candidate'):
            update.recover_boot()
        self.actions['prune_candidate'].assert_not_called()
        self.paths['PREPARE'].unlink()
        self.paths['PENDING'].write_bytes(state.canonical(self.receipt))
        self.booted = {'system_toplevel': '/unknown', 'system_generation': '8'}
        with self.assertRaisesRegex(ValueError, 'neither sealed candidate'):
            update.recover_boot()

    def test_durable_success_survives_late_cleanup_failure(self):
        self.paths['PENDING'].write_bytes(state.canonical(self.receipt))
        with patch.object(update, 'terminal_matches', return_value=True):
            update.recover_boot()
        self.actions['set_default'].assert_called_once_with('nixos-generation-2.conf')
        self.actions['restore_source'].assert_not_called()
        self.actions['emit_status'].assert_not_called()

    def test_cleanup_keeps_pending_authority_until_auxiliary_intents_are_gone(self):
        removed = []
        with patch.object(update, 'remove', side_effect=lambda path: removed.append(path)):
            update.clear_transaction(self.receipt)
        self.assertEqual(removed[-1], self.paths['PENDING'])
        self.assertEqual(set(removed[:-1]), {self.paths[key] for key in ('PREPARE', 'COMMIT', 'ROLLBACK')})


class SchemaRehearsal(unittest.TestCase):
    """A schema-changing candidate is rehearsed on a copy before anything is
    prepared (docs/sqlite-schema-evolution.md)."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.cache = self.directory / 'private/attempt/cache'
        self.cache.mkdir(parents=True)
        self.inventory = self.directory / 'sqlite-migrations.json'
        self.inventory.write_bytes(b'{"installed":true}\n')
        self.known = {'schema': 'tiaris.nest.known-good-system.v3', 'generations': [
            {'system_generation': '7', 'system_toplevel': '/nix/store/source', 'loader_entry': 'nixos-generation-7.conf'},
            {'system_generation': '6', 'system_toplevel': '/nix/store/evolving', 'loader_entry': 'nixos-generation-6.conf'},
            {'system_generation': '5', 'system_toplevel': '/nix/store/older', 'loader_entry': 'nixos-generation-5.conf'}]}
        self.saved = {}
        self.enterContext(patch.object(update, 'INVENTORY', self.inventory))
        self.enterContext(patch.object(update, 'KNOWN', self.directory / 'known'))
        self.enterContext(patch.object(update, 'ROOTS', self.directory / 'roots'))
        self.enterContext(patch.object(update, 'ENTRIES', self.directory / 'entries'))
        self.enterContext(patch.object(update, 'PROFILES', self.directory / 'profiles'))
        self.enterContext(patch.object(update, 'read', lambda path, **kw: path.read_bytes()))
        self.enterContext(patch.object(update, 'load', lambda path, **kw: copy.deepcopy(self.known)))
        self.enterContext(patch.object(update, 'save', lambda path, value: self.saved.__setitem__(path, value)))
        self.enterContext(patch.object(update, 'sync_dir'))
        self.enterContext(patch.object(update, 'current', lambda: {'system_generation': '7'}))
        self.calls = []
        def run(*arguments, **kwargs):
            self.calls.append([str(a) for a in arguments])
            if 'rehearse-appliance-database' in self.calls[-1]:
                (self.cache.parent / 'database-rehearsal.sqlite').write_bytes(b'copy')
            return ''
        self.enterContext(patch.object(update, 'run', side_effect=run))
        self.verified = {'system_toplevel': '/nix/store/candidate', 'sqlite_migrations_sha256':
                         hashlib.sha256(b'{"installed":true}\n').hexdigest()}

    def test_a_schema_neutral_update_is_not_rehearsed(self):
        self.assertFalse(update.schema_changes(self.verified))
        self.verified['sqlite_migrations_sha256'] = 'c' * 64
        self.assertTrue(update.schema_changes(self.verified))

    def test_candidate_migrates_a_copy_then_every_retained_release_must_open_it(self):
        opened = []
        def opens(binary, database):
            opened.append(str(binary))
            return str(binary) != '/nix/store/older/sw/bin/tiaris-nest'
        with patch.object(update, 'opens_rollback', side_effect=opens):
            retire = update.rehearse_database(self.verified, self.cache)
        rehearsal = str(self.cache.parent / 'database-rehearsal.sqlite')
        self.assertEqual(self.calls, [['/nix/store/candidate/sw/bin/tiaris-nest', 'rehearse-appliance-database',
            '--database', str(self.cache.parent / 'database-compatibility.sqlite'), '--output', rehearsal]])
        self.assertEqual(opened, [str(update.SOURCE_NEST), '/nix/store/evolving/sw/bin/tiaris-nest',
                                  '/nix/store/older/sw/bin/tiaris-nest'])
        self.assertEqual([row['system_generation'] for row in retire], ['5'])
        self.assertFalse(Path(rehearsal).exists())

    def test_a_failed_rehearsal_refuses_with_the_database_reason(self):
        def fails(*arguments, **kwargs):
            raise subprocess.CalledProcessError(1, arguments)
        with patch.object(update, 'run', side_effect=fails):
            with self.assertRaises(update.DatabaseIncompatible):
                update.rehearse_database(self.verified, self.cache)
        with patch.object(update, 'opens_rollback', return_value=False):
            with self.assertRaisesRegex(update.DatabaseIncompatible, 'running release'):
                update.rehearse_database(self.verified, self.cache)
        source = (RUNTIME / 'generation_update.py').read_text()
        self.assertIn("'rollback_database_incompatible' if isinstance(error, DatabaseIncompatible)", source)

    def test_retirement_prunes_first_and_never_touches_the_booted_generation(self):
        (self.directory / 'profiles').mkdir()
        (self.directory / 'profiles/system-5-link').symlink_to('/nix/store/older')
        (self.directory / 'entries').mkdir()
        (self.directory / 'entries/nixos-generation-5.conf').write_text('entry')
        (self.directory / 'roots').mkdir()
        (self.directory / 'roots/good-5').symlink_to('/nix/store/older')
        update.retire_generations([self.known['generations'][2]])
        self.assertEqual(self.calls, [['nix-env', '--profile', str(update.PROFILE), '--delete-generations', '5']])
        self.assertFalse((self.directory / 'entries/nixos-generation-5.conf').exists())
        self.assertFalse((self.directory / 'roots/good-5').is_symlink())
        self.assertEqual([row['system_generation'] for row in self.saved[self.directory / 'known']['generations']], ['7', '6'])
        # A repeat after a crash finds the profile gone and prunes nothing twice.
        (self.directory / 'profiles/system-5-link').unlink()
        self.calls.clear()
        update.retire_generations([self.known['generations'][2]])
        self.assertEqual(self.calls, [])
        with self.assertRaisesRegex(ValueError, 'booted'):
            update.retire_generations([self.known['generations'][0]])

    def test_opening_needs_a_release_that_knows_the_rollback_check(self):
        for code, expected in ((0, True), (2, False)):
            binary = self.directory / ('nest-' + str(code))
            binary.write_text('#!/bin/sh\nexit ' + str(code) + '\n')
            binary.chmod(0o700)
            self.assertIs(update.opens_rollback(binary, self.directory / 'db.sqlite'), expected)
        self.assertFalse(update.opens_rollback(self.directory / 'missing', self.directory / 'db.sqlite'))

    def test_rehearsal_happens_before_anything_is_prepared(self):
        stage = (RUNTIME / 'generation_update.py').read_text()
        stage = stage[stage.index('def prepare():'):]
        candidate_check = stage.index("'verify-appliance-database'")
        rehearsal = stage.index('rehearse_database(verified, cache) if schema_changes(verified)')
        retirement = stage.index("retire_generations(prepared['retire_generations'])")
        prepare = stage.index('save(PREPARE, receipt)')
        self.assertLess(candidate_check, rehearsal)
        self.assertLess(rehearsal, retirement)
        self.assertLess(retirement, prepare)


class BootAnchors(unittest.TestCase):
    def test_missing_corrupt_or_wrong_system_boot_payload_rejects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            boot, system = root / 'boot', root / 'system'
            (boot / 'loader/entries').mkdir(parents=True)
            (boot / 'EFI/nixos').mkdir(parents=True)
            system.mkdir()
            for name in ('kernel', 'initrd'):
                (system / name).write_bytes(name.encode() * 100)
                (boot / 'EFI/nixos' / name).write_bytes((system / name).read_bytes())
            entry = boot / 'loader/entries/nixos-generation-2.conf'
            valid = f'linux /EFI/nixos/kernel\ninitrd /EFI/nixos/initrd\noptions init={system}/init quiet\n'
            entry.write_text(valid)
            with patch.object(update, 'read', lambda path, **kw: path.read_bytes()):
                update.verify_boot_entry(entry.name, str(system), boot)
                (boot / 'EFI/nixos/kernel').write_bytes(b'corrupted')
                with self.assertRaisesRegex(ValueError, 'kernel differs'):
                    update.verify_boot_entry(entry.name, str(system), boot)
                (boot / 'EFI/nixos/kernel').write_bytes((system / 'kernel').read_bytes())
                (boot / 'EFI/nixos/initrd').unlink()
                with self.assertRaisesRegex(ValueError, 'missing or linked'):
                    update.verify_boot_entry(entry.name, str(system), boot)
                entry.write_text(valid.replace(str(system), '/different'))
                with self.assertRaisesRegex(ValueError, 'exact signed system'):
                    update.verify_boot_entry(entry.name, str(system), boot)

    def test_actual_kernel_mismatch_cannot_commit(self):
        expected = {'kernel': '6.18.38', 'nix': '2.34.7', 'systemd-boot': '260.2', 'tiaris-nest': '0.2.5'}
        with patch.object(update, 'observed_system_versions', return_value=expected):
            update.verify_observed_versions(expected)
        with patch.object(update, 'observed_system_versions', return_value={**expected, 'kernel': '6.18.37'}):
            with self.assertRaisesRegex(ValueError, 'kernel version differs'):
                update.verify_observed_versions(expected)


EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
TOPLEVEL = '/nix/store/0c7c9lr2kqyskkqm1ppa0w1bx8hlh8sm-nixos-system-nest'
GLIBC = '/nix/store/1c7c9lr2kqyskkqm1ppa0w1bx8hlh8sm-glibc-2.42'


class ReleaseOnlyClosure(unittest.TestCase):
    """Appliance updates keep release-key-only trust although Nix's daemon also
    trusts the Nest's own cache key for its self-substituter."""

    def release_cache(self, directory, hashes):
        cache = Path(directory) / 'cache'
        cache.mkdir()
        for path, nar_hash in hashes.items():
            narinfo = cache / (Path(path).name.split('-', 1)[0] + '.narinfo')
            narinfo.write_text(f'StorePath: {path}\nURL: nar/x.nar\nNarHash: {nar_hash}\nNarSize: 1\n')
            narinfo.chmod(0o600)
        return cache

    def test_nar_hashes_compare_in_every_encoding(self):
        raw = bytes.fromhex(EMPTY_SHA256)
        self.assertEqual(update.nar_hash_bytes('sha256:' + EMPTY_SHA256), raw)
        self.assertEqual(update.nar_hash_bytes('sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73'), raw)
        self.assertEqual(update.nar_hash_bytes('sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='), raw)
        for invalid in ('md5:' + EMPTY_SHA256[:32], 'sha256:' + 'e' * 52, 'sha256-AAAA'):
            with self.assertRaises(ValueError):
                update.nar_hash_bytes(invalid)

    def test_every_installed_member_must_be_the_release_content(self):
        good = 'sha256:' + EMPTY_SHA256
        other = 'sha256-' + '1' * 43 + '='
        with tempfile.TemporaryDirectory() as directory:
            cache = self.release_cache(directory, {TOPLEVEL: good, GLIBC: 'sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73'})
            listing = {TOPLEVEL: {'narHash': 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='},
                       GLIBC: {'narHash': 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='}}
            reads = lambda path, **kw: Path(path).read_bytes()
            with patch.object(update, 'read', reads), patch.object(update, 'run', return_value=json.dumps(listing)) as run:
                update.verify_store_closure(cache, TOPLEVEL)
                self.assertIn('path-info', run.call_args.args)
            # A member planted before the import (same store path, other
            # content, e.g. signed with the Nest's own cache key) is refused.
            planted = {**listing, GLIBC: {'narHash': other}}
            with patch.object(update, 'read', reads), patch.object(update, 'run', return_value=json.dumps(planted)):
                with self.assertRaisesRegex(ValueError, 'differs from the signed release'):
                    update.verify_store_closure(cache, TOPLEVEL)
            # A member the release does not name, and the legacy list format.
            extra = [{'path': TOPLEVEL, 'narHash': good}, {'path': '/nix/store/2c7c9lr2kqyskkqm1ppa0w1bx8hlh8sm-extra', 'narHash': good}]
            with patch.object(update, 'read', reads), patch.object(update, 'run', return_value=json.dumps(extra)):
                with self.assertRaisesRegex(ValueError, 'differs from the signed release'):
                    update.verify_store_closure(cache, TOPLEVEL)
            with patch.object(update, 'read', reads), patch.object(update, 'run', return_value=json.dumps({GLIBC: listing[GLIBC]})):
                with self.assertRaisesRegex(ValueError, 'toplevel'):
                    update.verify_store_closure(cache, TOPLEVEL)

    def test_import_checks_the_closure_before_running_it(self):
        source = (RUNTIME / 'generation_update.py').read_text()
        stage = source[source.index('def prepare():'):source.index('def contact_fresh(')]
        imported = stage.index("'copy', '--from'")
        rooted = stage.index("pin(verified['system_toplevel'], 'pending-' + attempt)")
        checked = stage.index("verify_store_closure(cache, verified['system_toplevel'])")
        executed = stage.index("'/sw/bin/tiaris-nest', 'verify-appliance-database'")
        self.assertLess(imported, rooted)
        self.assertLess(rooted, checked)
        self.assertLess(checked, executed)
        self.assertIn("'--option', 'substituters', ''", stage[imported - 200:imported + 200])

    def test_matching_legacy_list_and_basename_keyed_closures_are_accepted(self):
        good = 'sha256:' + EMPTY_SHA256
        with tempfile.TemporaryDirectory() as directory:
            cache = self.release_cache(directory, {TOPLEVEL: good, GLIBC: good})
            listings = [
                [{'path': TOPLEVEL, 'narHash': good}, {'path': GLIBC, 'narHash': good}],
                {Path(TOPLEVEL).name: {'narHash': good}, Path(GLIBC).name: {'narHash': good}},
            ]
            for listing in listings:
                with self.subTest(listing=listing), patch.object(update, 'read', lambda path, **kw: path.read_bytes()), \
                        patch.object(update, 'run', return_value=json.dumps(listing)):
                    update.verify_store_closure(cache, TOPLEVEL)

    def test_nix32_hash_decoder_matches_independent_encoder_and_rejects_overflow(self):
        for raw in (bytes(32), bytes([255]) * 32, bytes(range(32)), hashlib.sha256(b'nightly').digest()):
            number = int.from_bytes(raw, 'little')
            encoded = ''.join(update.NIX32[(number >> shift) & 31] for shift in range(255, -1, -5))
            self.assertEqual(update.nar_hash_bytes('sha256:' + encoded), raw)
        for invalid in ('sha256:' + 'z' * 52, 'sha256:' + '0' * 51 + 'e', 'sha256-' + base64.b64encode(bytes(31)).decode()):
            with self.assertRaises(ValueError):
                update.nar_hash_bytes(invalid)


class ContactBeforeTheRestart(unittest.TestCase):
    """Arming the candidate takes a while; the Nest restarts into it only
    while it still reaches Tiaris."""
    ATTEMPT = '11111111-1111-4111-8111-111111111111'

    def arm(self, *contact, pxe=True):
        """What `activate` does when the Nest's looks for Tiaris answer in
        this order, and the receipt it sealed."""
        contact = iter(contact)
        prepared = {'attempt_id': self.ATTEMPT, 'cache_path': '/cache', 'system_toplevel': '/candidate',
                    'retire_generations': []}
        calls = []
        def record(name, result=None):
            return lambda *args, **kwargs: calls.append((name, *args[1:2], *sorted(kwargs.items()))) or result
        source = {'system_generation': '1', 'system_toplevel': '/source', 'loader_entry': 'nixos-generation-1.conf'}
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            pending = Path(directory) / 'pending.json'
            for name, value in (('PENDING', pending), ('PREPARE', Path(directory) / 'prepare.json'),
                                ('ROOTS', Path(directory)), ('current', lambda: source), ('load', lambda path, **kw: {}),
                                ('generation_for', lambda toplevel: '2'), ('contact_fresh', lambda: next(contact)),
                                ('pxe_active', lambda: pxe), ('retire_generations', record('retire_generations')),
                                ('firmware_entry', lambda name: 'nixos-generation-2.conf' if name.endswith('OneShot') else source['loader_entry']),
                                ('save', lambda path, value: path.write_text(json.dumps(value))),
                                ('remove', lambda path: calls.append(('remove', path.name))),
                                ('restore_source', record('restore_source')), ('prune_candidate', record('prune_candidate')),
                                ('emit_status', lambda receipt, *status: calls.append(status)),
                                ('run', lambda *command, **kw: calls.append(command[:2]) if command[0] == 'systemctl' else None)):
                stack.enter_context(patch.object(update, name, value))
            for name in ('verify_store_closure', 'boot_space', 'set_default', 'verify_boot_entry'):
                stack.enter_context(patch.object(update, name))
            stack.enter_context(patch.object(update.os, 'sync'))
            update.activate(prepared)
            return calls, json.loads(pending.read_text()) if pending.exists() else None

    def test_a_link_that_died_while_arming_waits_with_what_it_prepared(self):
        calls, sealed = self.arm(True, True)
        self.assertEqual(calls, [('preparing', 'activating'), ('retire_generations',),
                                 ('rebooting', 'reboot_pending'), ('systemctl', '--no-block')])
        self.assertEqual(sealed['schema'], 'tiaris.nest.pending-system-generation.v3')
        # Gone before anything changed: no generation leaves the boot menu.
        calls, sealed = self.arm(False)
        self.assertIsNone(sealed)
        self.assertEqual(calls, [('preparing', 'activating'), ('preparing', 'no_manage_contact')])
        # Gone while arming. Nothing is sealed and nothing restarts: the
        # arming is undone, the prepared closure keeps its root and the
        # report says what it waits for.
        calls, sealed = self.arm(True, False)
        self.assertIsNone(sealed)
        self.assertEqual(calls, [('preparing', 'activating'), ('retire_generations',), ('restore_source',),
                                 ('prune_candidate', ('keep_prepared', True)), ('remove', 'prepare.json'),
                                 ('preparing', 'no_manage_contact')])

    def test_the_seal_says_whether_this_release_answered_network_starts(self):
        self.assertIs(self.arm(True, True, pxe=True)[1]['source_pxe_active'], True)
        self.assertIs(self.arm(True, True, pxe=False)[1]['source_pxe_active'], False)
        # What the supervisor said, and only when it said so just now.
        for status, expected in (({'status': 'active', 'checked_at': 1000}, True),
                                 ({'status': 'unavailable', 'checked_at': 1000}, False),
                                 ({'status': 'active', 'checked_at': 900}, False), (None, False)):
            def load(path, **kwargs):
                return {'schema': 'tiaris.nest.pxe-status.v1', **status}
            with patch.object(update, 'load', side_effect=load), \
                    patch.object(update, 'time', SimpleNamespace(time=lambda: 1010)):
                self.assertIs(update.pxe_active(), expected)


class CandidateHealth(unittest.TestCase):
    """What the candidate proves before it stays, and what a rollback says."""
    RELEASE = {'source_revision': 'r', 'nixpkgs_revision': 'n', 'manage_source_revision': 'm', 'release_id': '0.2.1',
               'base_os': 'nixos', 'base_os_version': '26.05', 'required_system_versions': {}}

    def outcome(self, healthy, reached, asked=None, **sealed):
        """The last status `commit` reports for a candidate whose own health
        and whose contact with Tiaris answer the checks in this order;
        `asked` collects whether PXE was asked of it."""
        asked = set() if asked is None else asked
        receipt = {**self.RELEASE, **sealed, 'release': self.RELEASE, 'attempt_id': '11111111-1111-4111-8111-111111111111',
                   'system_toplevel': '/candidate', 'candidate_generation': '2',
                   'candidate_loader_entry': 'nixos-generation-2.conf', 'system_closure_sha256': 'c' * 64,
                   'sqlite_migrations_sha256': hashlib.sha256(b'inventory').hexdigest()}
        seconds = itertools.count(0, 5)
        clock = SimpleNamespace(monotonic=lambda: next(seconds), sleep=lambda seconds: None)
        healthy, reached = itertools.cycle(healthy), itertools.cycle(reached)
        with tempfile.NamedTemporaryFile() as pending, contextlib.ExitStack() as stack:
            for name, value in (('PENDING', Path(pending.name)), ('time', clock), ('maintenance_lock', nullcontext),
                                ('load', lambda path, **kw: receipt), ('read', lambda path, **kw: b'inventory'),
                                ('current', lambda: {'system_toplevel': '/candidate', 'system_generation': '2'}),
                                ('local_health_ready', lambda pxe_required: (asked.add(pxe_required), next(healthy))[1]),
                                ('contact_fresh', lambda: next(reached)),
                                ('terminal_matches', lambda receipt: False), ('retain', lambda receipt, installed: [])):
                stack.enter_context(patch.object(update, name, value))
            for name in ('verify_observed_versions', 'verify_boot_entry', 'save', 'set_default', 'cleanup',
                         'clear_transaction', 'prune_obsolete', 'restore_source', 'run'):
                stack.enter_context(patch.object(update, name))
            stack.enter_context(patch.object(update.os, 'sync'))
            emit = stack.enter_context(patch.object(update, 'emit_status'))
            try:
                update.commit()
            except RuntimeError:
                pass
            return emit.call_args.args[1:]

    def test_a_candidate_that_only_lost_tiaris_goes_back_with_its_own_reason(self):
        self.assertEqual(self.outcome([True], [True]), ('succeeded', 'committed'))
        self.assertEqual(self.outcome([True], [False]), ('health_checking', 'rollback_pending', 'manage_contact_failed'))
        # Two healthy checks in a row are not three: its own health is the reason.
        self.assertEqual(self.outcome([True, True, False], [False]),
                         ('health_checking', 'rollback_pending', 'local_health_failed'))
        # Healthy at first, broken at the deadline: the last checks decide.
        self.assertEqual(self.outcome([True] * 3 + [False] * 60, [False]),
                         ('health_checking', 'rollback_pending', 'local_health_failed'))


    def test_a_candidate_answers_network_starts_only_if_the_release_before_it_did(self):
        # An update must not take PXE away; a Nest whose PXE is down must
        # still get the update. A seal from before this rule asks for PXE.
        for sealed, required in (({'source_pxe_active': True}, True), ({'source_pxe_active': False}, False), ({}, True)):
            asked = set()
            self.assertEqual(self.outcome([True], [True], asked, **sealed), ('succeeded', 'committed'))
            self.assertEqual(asked, {required})
        urls = []
        with patch.object(update.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
                patch.object(update, 'run', side_effect=lambda *command, **kw: urls.append(command[-1])):
            self.assertTrue(update.local_health_ready(True) and update.local_health_ready(False))
        self.assertEqual(urls, ['http://127.0.0.1:8080/healthz?tiaris_fresh=1',
                                'http://127.0.0.1:8080/healthz?tiaris_fresh=1&tiaris_without_pxe=1'])


class CandidateContactOrigin(unittest.TestCase):
    """The candidate accepts Management contact at its own origin for legacy state."""

    def bootstrap(self, directory):
        path = Path(directory) / 'bootstrap'
        path.write_text('#!/bin/sh\ntest "$1" = effective-manage-origin || exit 2\n'
                        'case "$2" in https://manage.tiaris.com|https://manage.cybex.net) '
                        'echo https://manage.tiaris.com ;; *) exit 1 ;; esac\n')
        path.chmod(0o755)
        return str(path)

    def ready(self, recorded, contacted):
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        files = {
            'manage-contact.json': {'schema': 'tiaris.nest.manage-contact.v1', 'boot_id': boot_id,
                                    'device_id': 'nest-1', 'public_key_fingerprint': 'f' * 64,
                                    'manage_origin': contacted, 'reported_at': now},
            'manage-state.json': {'device_id': 'nest-1', 'public_key_fingerprint': 'f' * 64},
            'provisioning-state.json': {'manage_origin': recorded},
        }
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(update, 'BOOTSTRAP', self.bootstrap(directory)), \
                patch.object(update, 'load', lambda path, **_: copy.deepcopy(files[Path(path).name])):
            return update.contact_fresh()

    def test_legacy_recorded_origin_accepts_contact_at_the_build_origin(self):
        self.assertTrue(self.ready('https://manage.cybex.net', 'https://manage.tiaris.com'))
        self.assertTrue(self.ready('https://manage.tiaris.com', 'https://manage.tiaris.com'))

    def test_contact_at_the_old_origin_or_unknown_state_is_refused(self):
        self.assertFalse(self.ready('https://manage.cybex.net', 'https://manage.cybex.net'))
        self.assertFalse(self.ready('https://dev.tiaris.com', 'https://dev.tiaris.com'))
        self.assertFalse(self.ready('https://dev.tiaris.com', 'https://manage.tiaris.com'))

    def test_unavailable_bootstrap_is_not_an_origin(self):
        with patch.object(update, 'BOOTSTRAP', '/bin/false'):
            self.assertIsNone(update.effective_manage_origin('https://manage.cybex.net'))
        self.assertIsNone(update.effective_manage_origin(None))


class SelfCacheTrust(unittest.TestCase):
    KEY = 'tiaris-nest-cache:' + 'A' * 42 + 'E='

    @unittest.skipUnless(shutil.which('nix-instantiate'), 'requires Nix for real module evaluation')
    def test_evaluated_module_substitutes_from_its_own_export_first(self):
        result = subprocess.run(
            ['nix-instantiate', '--eval', '--read-write-mode', '--strict', '--json', '--expr',
             'import ./nixos-appliance/tests/self-cache-evaluation.nix {}'],
            cwd=RUNTIME.parents[1], capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)
        checks = json.loads(result.stdout)
        self.assertEqual(set(checks), {
            'selfCacheFirst', 'includeIsOptional', 'ownKeyNotInStaticTrust', 'trustRunsAsRoot',
            'trustFollowsKeyChanges', 'exportLayoutOwnedByNest', 'recoveryMediaUnchanged'})
        self.assertTrue(all(value is True for value in checks.values()), checks)

    def paths(self, directory):
        agent = Path(directory) / 'agent-cache-public.pem'
        legacy = Path(directory) / 'legacy-cache-public.pem'
        include = Path(directory) / 'nix-self-cache.conf'
        return agent, legacy, include

    def test_writes_only_one_validated_trust_line_and_restarts_on_change(self):
        with tempfile.TemporaryDirectory() as directory:
            agent, legacy, include = self.paths(directory)
            restarts = []
            options = dict(include=include, paths=(agent, legacy), owner=os.getuid(), restart=lambda: restarts.append(1))
            # No key yet: an empty include, so the self-substituter is unused.
            self.assertTrue(trust.apply(**options))
            self.assertEqual(include.read_text(), '')
            agent.write_text(self.KEY + '\n')
            agent.chmod(0o600)
            self.assertTrue(trust.apply(**options))
            self.assertEqual(include.read_text(), 'extra-trusted-public-keys = ' + self.KEY + '\n')
            self.assertEqual(include.stat().st_mode & 0o777, 0o644)
            self.assertFalse(trust.apply(**options))
            self.assertEqual(len(restarts), 2)

    def test_the_software_cache_is_a_substituter_only_while_manage_gives_access(self):
        with tempfile.TemporaryDirectory() as directory:
            agent, legacy, include = self.paths(directory)
            netrc = Path(directory) / 'software-cache.netrc'
            options = dict(include=include, paths=(agent, legacy), owner=os.getuid(), restart=lambda: None, netrc=netrc)
            line = 'extra-substituters = https://cache.tiaris.com\n'
            trust.apply(**options)
            self.assertEqual(include.read_text(), '')
            netrc.write_text('machine cache.tiaris.com login nest password tsc1.dev.1.nest.AAA\n')
            netrc.chmod(0o600)
            self.assertTrue(trust.apply(**options))
            self.assertEqual(include.read_text(), line)
            # Another host, or anything beyond the one entry, adds nothing.
            for hostile in ('machine evil.example login nest password token\n',
                            'machine cache.tiaris.com login nest password token\nsubstituters = https://evil.example\n'):
                netrc.write_text(hostile)
                trust.apply(**options)
                self.assertEqual(include.read_text(), '', hostile)
            netrc.unlink()
            self.assertFalse(trust.apply(**options))
            self.assertEqual(include.read_text(), '')

    def test_the_service_user_cannot_add_other_nix_options(self):
        with tempfile.TemporaryDirectory() as directory:
            agent, legacy, include = self.paths(directory)
            options = dict(include=include, paths=(agent, legacy), owner=os.getuid(), restart=lambda: None)
            agent.write_text(self.KEY + '\n')
            agent.chmod(0o600)
            trust.apply(**options)
            for hostile in (self.KEY + '\ntrusted-users = tiaris-nest\n',
                            'other-key:' + 'A' * 42 + 'E=',
                            'tiaris-nest-cache:' + 'A' * 40 + '==',
                            self.KEY + ' post-build-hook = /tmp/x'):
                agent.write_text(hostile)
                with self.assertRaises(ValueError):
                    trust.apply(**options)
                self.assertEqual(include.read_text(), '', hostile)
            # A link, a group-writable file or a file of another owner is not read.
            agent.unlink()
            target = Path(directory) / 'elsewhere'
            target.write_text(self.KEY)
            target.chmod(0o600)
            agent.symlink_to(target)
            with self.assertRaises(ValueError):
                trust.apply(**options)
            agent.unlink()
            agent.write_text(self.KEY)
            agent.chmod(0o620)
            with self.assertRaises(ValueError):
                trust.apply(**options)
            agent.chmod(0o600)
            with self.assertRaises(ValueError):
                trust.apply(**{**options, 'owner': os.getuid() + 1})
            self.assertEqual(include.read_text(), '')

    def test_legacy_bridge_key_is_used_when_the_agent_key_is_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            agent, legacy, include = self.paths(directory)
            legacy.write_text(self.KEY)
            legacy.chmod(0o600)
            trust.apply(include=include, paths=(agent, legacy), owner=os.getuid(), restart=lambda: None)
            self.assertIn(self.KEY, include.read_text())

    def test_key_rotation_and_removal_revoke_previous_self_cache_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            agent, legacy, include = self.paths(directory)
            restarts = []
            options = dict(include=include, paths=(agent, legacy), owner=os.getuid(),
                           restart=lambda: restarts.append(1))
            agent.write_text(self.KEY)
            agent.chmod(0o600)
            trust.apply(**options)
            rotated = 'tiaris-nest-cache:' + base64.b64encode(bytes(range(32))).decode()
            agent.write_text(rotated)
            self.assertTrue(trust.apply(**options))
            self.assertEqual(include.read_text(), 'extra-trusted-public-keys = ' + rotated + '\n')
            self.assertNotIn(self.KEY, include.read_text())
            agent.unlink()
            self.assertTrue(trust.apply(**options))
            self.assertEqual(include.read_text(), '')
            self.assertEqual(len(restarts), 3)

    def test_invalid_primary_key_cannot_fall_back_to_valid_legacy_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            agent, legacy, include = self.paths(directory)
            for path in (agent, legacy):
                path.write_text(self.KEY)
                path.chmod(0o600)
            options = dict(include=include, paths=(agent, legacy), owner=os.getuid(), restart=lambda: None)
            trust.apply(**options)
            for invalid in (b'\xff\n', b'tiaris-nest-cache:invalid', b'A' * 513):
                agent.write_bytes(invalid)
                with self.assertRaises(ValueError):
                    trust.apply(**options)
                self.assertEqual(include.read_text(), '')


class ManageSourceAndExportTests(unittest.TestCase):
    def test_build_manage_source_archive_uses_pathspecs_manifest_when_present(self):
        script = RUNTIME.parent / 'build-manage-source-archive.sh'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / 'tiaris'
            repo.mkdir()
            git = ['git', '-C', str(repo), '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid']
            subprocess.run([*git, 'init', '-q'], check=True)
            required = [
                'agent/tiaris-agent/Cargo.toml',
                'agent/tiaris-agent/Cargo.lock',
                'agent/tiaris-agent/src/hardware_inventory.rs',
                'agent/tiaris-agent/src/installer_boot.rs',
                'agent/tiaris-agent/src/lib.rs',
                'agent/tiaris-agent/src/main.rs',
                'agent/tiaris-agent/src/managed_wifi.rs',
                'deploy/nixos/tiaris-agent-module.nix',
                'deploy/nixos/tiaris-apply-blueprint.sh',
                'deploy/nixos/tiaris-authd-packages.nix',
                'deploy/nixos/tiaris-authd.nix',
                'deploy/nixos/tiaris-blueprints.nix',
                'deploy/nixos/tiaris-himmelblau-packages.nix',
                'deploy/nixos/tiaris-himmelblau.nix',
                'deploy/nixos/tiaris-ldap.nix',
            ]
            for rel in [*required, 'deploy/nixos/tests/ignored.nix', 'web/src/ignored.tsx']:
                path = repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture\n')
            (repo / 'deploy/nixos/manage-source-paths.txt').write_text(
                '# comment\nagent/\ndeploy/nixos/\n:(exclude)deploy/nixos/tests/\n'
            )
            subprocess.run([*git, 'add', '-A'], check=True)
            subprocess.run([*git, 'commit', '-q', '-m', 'fixture'], check=True)
            rev = subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True).strip()
            out = root / 'out'
            archive = Path(subprocess.check_output([
                'bash', str(script), '--source-dir', str(repo), '--revision', rev, '--output-dir', str(out)
            ], text=True).strip())
            with archive.open('rb') as stream:
                embedded = subprocess.check_output(['git', 'get-tar-commit-id'], stdin=stream, text=True).strip()
            self.assertEqual(embedded, rev)
            entries = set(subprocess.check_output(['tar', '-tf', str(archive)], text=True).splitlines())
            self.assertIn('deploy/nixos/tiaris-blueprints.nix', entries)
            self.assertNotIn('deploy/nixos/tests/ignored.nix', entries)
            self.assertNotIn('web/src/ignored.tsx', entries)

    def test_export_cache_parallel_output_is_deterministic_and_bounded(self):
        loader = SourceFileLoader('export_cache', str(RUNTIME.parent / 'export-cache.py'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        export_cache = importlib.util.module_from_spec(spec)
        loader.exec_module(export_cache)
        self.assertGreaterEqual(export_cache.worker_count(), 1)
        self.assertLessEqual(export_cache.worker_count(), export_cache.MAX_WORKERS)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / 'bin'
            fake_bin.mkdir()
            (fake_bin / 'nix-store').write_text('#!/usr/bin/env sh\nprintf "nar:%s\\n" "$2"\n')
            (fake_bin / 'nix-store').chmod(0o755)
            graph = {
                'closure': [
                    {'path': f'/nix/store/{"a" * 32}-zeta', 'narHash': 'sha256:' + '0' * 52, 'narSize': 1024, 'references': []},
                    {'path': f'/nix/store/{"b" * 32}-alpha', 'narHash': 'sha256:' + '1' * 52, 'narSize': 2048, 'references': []},
                ]
            }
            metadata = {'manage_origin': 'https://example.invalid', 'release_id': '0.0.1'}
            graph_file, meta_file = root / 'graph.json', root / 'meta.json'
            graph_file.write_text(json.dumps(graph))
            meta_file.write_text(json.dumps(metadata))
            out_a, out_b = root / 'out-a', root / 'out-b'
            env = {**os.environ, 'PATH': f'{fake_bin}:{os.environ["PATH"]}', 'NIX_BUILD_CORES': '2'}
            subprocess.run([sys.executable, str(RUNTIME.parent / 'export-cache.py'), str(graph_file), str(meta_file), str(out_a)],
                           check=True, env=env)
            subprocess.run([sys.executable, str(RUNTIME.parent / 'export-cache.py'), str(graph_file), str(meta_file), str(out_b)],
                           check=True, env={**env, 'NIX_BUILD_CORES': '1'})
            self.assertEqual((out_a / 'manifest.json').read_bytes(), (out_b / 'manifest.json').read_bytes())
            manifest = json.loads((out_a / 'manifest.json').read_text())
            self.assertEqual([row['path'] for row in manifest['store_paths']],
                             sorted(row['path'] for row in graph['closure']))

    def test_disk_health_script_classifies_nvme_ata_and_unknown_smart(self):
        disk_health = script('tiaris-nest-disk-health')
        nvme_ok = {'smart_status': {'passed': True}, 'nvme_smart_health_information_log': {'critical_warning': 0, 'percentage_used': 12, 'temperature': 38}}
        self.assertEqual(disk_health.parse_smartctl_json(nvme_ok, 0), {'status': 'ok', 'wear_percent': 12, 'temperature_celsius': 38})
        nvme_warn = {'smart_status': {'passed': True}, 'nvme_smart_health_information_log': {'critical_warning': 0, 'percentage_used': 88, 'temperature': 45}}
        self.assertEqual(disk_health.parse_smartctl_json(nvme_warn, 0)['status'], 'warning')
        nvme_fail = {'smart_status': {'passed': True}, 'nvme_smart_health_information_log': {'critical_warning': 1, 'percentage_used': 50, 'temperature': 40}}
        self.assertEqual(disk_health.parse_smartctl_json(nvme_fail, 0)['status'], 'failing')
        ata_warn = {'smart_status': {'passed': True}, 'ata_smart_attributes': {'table': [{'id': 5, 'raw': {'value': 4}}, {'id': 194, 'raw': {'value': 36}}]}}
        parsed_ata = disk_health.parse_smartctl_json(ata_warn, 0)
        self.assertEqual(parsed_ata['status'], 'warning')
        self.assertEqual(parsed_ata['reallocated_sectors'], 4)
        self.assertEqual(parsed_ata['temperature_celsius'], 36)
        self.assertEqual(disk_health.parse_smartctl_json({'device': {'type': 'scsi'}}, 2), {'status': 'unknown'})
        self.assertEqual(disk_health.parse_nvme_smart_log_json({'critical_warning': 0, 'percent_used': 96, 'temperature': 315})['status'], 'failing')
        storage = disk_health.collect_storage({'root': '/'})
        self.assertIn('root', storage)
        self.assertGreater(storage['root']['total_bytes'], 0)


if __name__ == '__main__':
    unittest.main()
