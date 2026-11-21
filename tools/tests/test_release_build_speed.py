"""The release gates run beside the build, and the build parts run side by side.

The release workflow has one runner, so the gates run inside the build job. These
tests keep every gate command, keep the gates joined before anything is signed,
and run the real build script with fake tools to prove its parts fail closed.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/release.yml'
GATES = ROOT / 'release/beast/release-gates.sh'
GATE_DIRECTORY = '"$RUNNER_TEMP/tiaris-nest-release-gates"'


def job(body, name):
    start = body.index(f'\n  {name}:\n')
    following = re.search(r'\n  [a-z_-]+:\n', body[start + 1:])
    return body[start:start + 1 + following.start()] if following else body[start:]


def step(body, name):
    start = body.index(f'      - name: {name}\n')
    end = body.find('\n      - name:', start + 1)
    return body[start:] if end < 0 else body[start:end]


def run_script(text):
    lines = []
    for line in text.split('        run: |\n', 1)[1].splitlines():
        if line and not line.startswith('          '):
            break
        lines.append(line)
    return textwrap.dedent('\n'.join(lines) + '\n')


class ReleaseGateWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = WORKFLOW.read_text()
        cls.build = job(cls.body, 'release_build')
        cls.names = re.findall(r'^      - name: (.+)$', cls.build, re.MULTILINE)

    def test_the_release_has_no_serial_gate_jobs_and_the_build_waits_for_none(self):
        jobs = re.findall(r'^  ([a-z_-]+):$', self.body.split('\njobs:\n', 1)[1], re.MULTILINE)
        self.assertEqual(jobs, ['release_build', 'release_publish', 'release_public_closure', 'release_promote'])
        header = self.build.split('    steps:\n', 1)[0]
        self.assertNotIn('needs:', header)
        # Publication, its closure check and promotion all still follow the build.
        self.assertIn('    needs: [release_build]\n', job(self.body, 'release_publish'))
        self.assertIn('    needs: [release_build, release_publish]\n', job(self.body, 'release_public_closure'))
        self.assertIn('    needs: [release_build, release_public_closure]\n', job(self.body, 'release_promote'))

    def test_every_attempt_starts_the_gates_from_the_exact_tag_before_anything_else(self):
        self.assertEqual(self.names[:3], ['Checkout exact tag', 'Install pinned Rust toolchain for the release gates',
                                          'Start the release gates beside the build'])
        toolchain = step(self.build, 'Install pinned Rust toolchain for the release gates')
        self.assertIn('toolchain: 1.85.0', toolchain)
        self.assertIn('components: rustfmt, clippy', toolchain)
        start = step(self.build, 'Start the release gates beside the build')
        self.assertNotIn('    if:', start)
        self.assertIn('CARGO_TARGET_DIR: /home/john/.local/state/tiaris-nest-ci-target/release-gate', start)
        self.assertIn('bash release/beast/release-gates.sh start ' + GATE_DIRECTORY, start)
        # The gates see the environment the separate gate jobs had: none of the
        # build job's production inputs (the origin changes the compiled tests).
        job_environment = self.build.split('\n    env:\n', 1)[1].split('\n    steps:\n', 1)[0]
        for name in re.findall(r'^      ([A-Z_]+):', job_environment, re.MULTILINE):
            with self.subTest(name=name):
                self.assertIn(f'-u {name} ', start)

    def test_every_attempt_joins_the_gates_before_signing_sealing_or_upload(self):
        join = step(self.build, 'Require every release gate to pass')
        self.assertNotIn('    if:', join)
        self.assertIn('run: bash release/beast/release-gates.sh join ' + GATE_DIRECTORY, join)
        position = self.names.index('Require every release gate to pass')
        for later in ('Sign and self-verify release manifests', 'Seal exact signed files in the local candidate store',
                      'Upload only the bounded candidate receipt', 'Bind candidate artifact identity and provenance'):
            with self.subTest(step=later):
                self.assertGreater(self.names.index(later), position)
        # The reuse path restores a sealed candidate and still needs this attempt's gates.
        self.assertLess(self.names.index('Restore exact local bytes without rebuilding or signing'), position)
        self.assertLess(self.names.index('Build exact binaries, appliance media, and workstation runtime'), position)
        cleanup = run_script(step(self.build, 'Remove disposable workspace payloads'))
        self.assertIn('bash release/beast/release-gates.sh stop ' + GATE_DIRECTORY, cleanup)

    def test_the_artifact_lookup_waits_for_github_and_keeps_every_check(self):
        script = run_script(step(self.build, 'Bind candidate artifact identity and provenance'))
        self.assertIn('for attempt in $(seq 1 12); do', script)
        self.assertIn('exit 1', script)
        for check in ('test "$(jq -r \'.name\' "$metadata")" = "$TIARIS_NEST_RELEASE_ARTIFACT"',
                      'test "$(jq -r \'.expired\' "$metadata")" = "false"',
                      'test "$(jq -r \'.workflow_run.id\' "$metadata")" = "$GITHUB_RUN_ID"',
                      'test "${api_digest#sha256:}" = "$action_digest"'):
            with self.subTest(check=check):
                self.assertIn(check, script)
                self.assertGreater(script.index(check), script.index('done\n'))

    def test_the_gates_keep_every_check_of_the_former_gate_jobs(self):
        script = GATES.read_text()
        self.assertEqual(re.search(r'^GATES=\((.*)\)$', script, re.MULTILINE).group(1), 'contracts rust nix')
        for command in (
                'command -v cc', 'command -v dnsmasq', 'command -v rg', 'command -v shellcheck',
                'bash -n "$helper"',
                'shellcheck release/beast/*.sh nixos-appliance/*.sh "${appliance[@]}"',
                'python3 -m py_compile nixos-appliance/*.py tools/pack-system-closure.py tools/system_closure.py',
                'python3 -B -m unittest discover -s nixos-appliance/tests -v',
                'python3 -B -m unittest discover -s tools/tests -v',
                'cargo fmt --all --check', 'cargo test --locked',
                'cargo clippy --all-targets --all-features -- -D warnings',
                'cargo audit --version', 'grep -q "nothing to print" "$tree"',
                'if [ "$(date -u +%F)" \\> 2027-02-01 ]; then',
                'cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0459',
                'nix-instantiate --version',
                'nix-instantiate --parse release/workstation-netboot.nix >/dev/null',
                'nix-instantiate --parse release/release-tools.nix >/dev/null',
                'for expression in nixos-appliance/*.nix; do nix-instantiate --parse "$expression" >/dev/null; done'):
            with self.subTest(command=command):
                self.assertIn(command, script)
        for gate in ('contracts', 'rust', 'nix'):
            self.assertIn(f'gate_{gate}() {{', script)
        contracts = script.split('gate_contracts() {', 1)[1].split('\n}\n', 1)[0]
        self.assertIn('  gate_bash_syntax\n  gate_shellcheck\n', contracts)
        rust = script.split('gate_rust() {', 1)[1].split('\n}\n', 1)[0]
        self.assertIn('  gate_expiry\n  cargo audit --ignore', rust)

    def test_the_expiry_gate_needs_only_date_and_fails_after_the_review_date(self):
        with tempfile.TemporaryDirectory() as temporary:
            for today, expected in (('2027-02-01', 0), ('2027-02-02', 1)):
                with self.subTest(today=today):
                    fake = Path(temporary) / 'date'
                    fake.write_text(f'#!/bin/sh\necho {today}\n')
                    fake.chmod(0o755)
                    result = subprocess.run(['bash', str(GATES), 'expiry'], capture_output=True, text=True,
                                            env={'PATH': f'{temporary}:/usr/bin:/bin'}, timeout=30)
                    self.assertEqual(result.returncode, expected, result.stderr)


@unittest.skipUnless(shutil.which('git') and shutil.which('setsid') and shutil.which('ps'),
                     'git, setsid and ps are required')
class ReleaseGateRunTests(unittest.TestCase):
    """The real start/join/stop against a checkout whose gates are fakes."""

    def setUp(self):
        temporary = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.checkout = temporary / 'checkout'
        self.gates = temporary / 'gates'
        script = self.checkout / 'release/beast/release-gates.sh'
        script.parent.mkdir(parents=True)
        # The real start/join/stop, with the gates replaced by commands from the
        # fixture's environment: start runs the copy inside the clean checkout.
        real = GATES.read_text()
        fake = real.replace('  contracts | rust | nix | bash-syntax | shellcheck | expiry)\n'
                            '    [ "$#" -eq 1 ] || { echo "usage: $0 GATE" >&2; exit 2; }\n'
                            '    "gate_${1//-/_}"\n',
                            '  contracts | rust | nix)\n'
                            '    [ "$#" -eq 1 ] || exit 2\n'
                            '    printf "%s\\n" "$PWD" > "$FAKE_RECORD/$1.cwd"\n'
                            '    eval "$(printenv "FAKE_$1")"\n')
        self.assertNotEqual(fake, real)
        script.write_text(fake)
        self.git('init', '-q', str(self.checkout))
        self.git('-C', str(self.checkout), 'add', '.')
        self.git('-C', str(self.checkout), '-c', 'user.name=Fixture', '-c', 'user.email=f@example.invalid',
                 'commit', '-qm', 'fixture')
        self.record = temporary / 'record'
        self.record.mkdir()

    @staticmethod
    def git(*arguments):
        subprocess.run(['git', *arguments], check=True, capture_output=True)

    def gate(self, action, **gates):
        environment = {**os.environ, 'FAKE_RECORD': str(self.record),
                       'FAKE_contracts': 'echo contracts-ran', 'FAKE_rust': 'echo rust-ran',
                       'FAKE_nix': 'echo nix-ran', **{'FAKE_' + key: value for key, value in gates.items()}}
        return subprocess.run(['bash', str(self.checkout / 'release/beast/release-gates.sh'), action,
                               str(self.gates)], cwd=self.checkout, env=environment,
                              capture_output=True, text=True, timeout=60)

    def test_passing_gates_join_and_run_in_a_clean_checkout_of_head(self):
        # The rust gate waits for a file written only after start returned: a
        # start that waited for its gates would never return.
        result = self.gate('start', rust='until [ -e "$FAKE_RECORD/go" ]; do sleep 0.1; done; echo rust-ran')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.gates / 'rust.status').exists())
        (self.record / 'go').touch()
        joined = self.gate('join')
        self.assertEqual(joined.returncode, 0, joined.stdout + joined.stderr)
        for gate in ('contracts', 'rust', 'nix'):
            self.assertIn(f'{gate}-ran', joined.stdout)
            self.assertIn(f'Release gate {gate} passed', joined.stdout)
            self.assertEqual((self.record / f'{gate}.cwd').read_text().strip(), str(self.gates / 'source'))
        stopped = self.gate('stop')
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        self.assertFalse(self.gates.exists())
        worktrees = subprocess.run(['git', '-C', str(self.checkout), 'worktree', 'list'],
                                   capture_output=True, text=True, check=True).stdout
        self.assertEqual(len(worktrees.splitlines()), 1)

    def test_any_failing_gate_fails_the_join_after_every_gate_has_ended(self):
        self.assertEqual(self.gate('start', nix='echo broken >&2; exit 7').returncode, 0)
        joined = self.gate('join')
        self.assertNotEqual(joined.returncode, 0)
        self.assertIn('::error::Release gate nix failed (7)', joined.stdout)
        self.assertIn('broken', joined.stdout)
        self.assertIn('Release gate contracts passed', joined.stdout)
        self.gate('stop')

    def test_a_gate_killed_without_a_result_fails_the_join(self):
        self.assertEqual(self.gate('start', contracts='sleep 300').returncode, 0)
        pid = int((self.gates / 'contracts.pid').read_text())
        os.killpg(pid, 9)
        joined = self.gate('join')
        self.assertNotEqual(joined.returncode, 0)
        self.assertIn('::error::Release gate contracts failed (ended without a result)', joined.stdout)
        self.gate('stop')

    def wait_until_session_ends(self, pid):
        for _ in range(300):
            if subprocess.run(['ps', '-o', 'pid=', '-g', str(pid)], capture_output=True, text=True).stdout.strip() == '':
                return
            time.sleep(0.1)
        self.fail(f'release gate session {pid} is still running')

    def test_stop_ends_running_gates_and_removes_them(self):
        self.assertEqual(self.gate('start', rust='sleep 300').returncode, 0)
        pid = int((self.gates / 'rust.pid').read_text())
        self.assertEqual(self.gate('stop').returncode, 0)
        self.wait_until_session_ends(pid)
        self.assertFalse(self.gates.exists())

    def test_a_leftover_from_an_earlier_job_is_ended_and_replaced(self):
        self.assertEqual(self.gate('start', rust='sleep 300').returncode, 0)
        leftover = int((self.gates / 'rust.pid').read_text())
        again = self.gate('start')
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn('Replacing leftover release gates', again.stdout)
        self.wait_until_session_ends(leftover)
        joined = self.gate('join')
        self.assertEqual(joined.returncode, 0, joined.stdout + joined.stderr)
        self.assertIn('rust-ran', joined.stdout)
        self.gate('stop')


# Each build part announces itself, then waits until every expected part has
# started: parts run one after another would never get past this barrier.
BARRIER = '''
beside() {
  touch "$FAKE_ROOT/started-$1"
  for _ in $(seq 1 600); do
    [ "$(find "$FAKE_ROOT" -maxdepth 1 -name 'started-*' | wc -l)" -ge "$FAKE_PARTS" ] && return 0
    sleep 0.1
  done
  echo "build part $1 never ran beside the others" >&2
  exit 3
}
'''

FAKE_TOOL = '''#!/usr/bin/env bash
set -euo pipefail
name="$(basename "$0")"
''' + BARRIER + '''
printf '%s %s\\n' "$name" "$*" >> "$FAKE_LOG"
case "$name" in
  cargo) exit 0 ;;
  git)
    case "$*" in
      *"show -s --format=%ct HEAD"*) echo 1700000000 ;;
      *"rev-parse HEAD"*) echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
    esac ;;
  nix-build)
    beside "workstation runtime"
    [ -z "${FAKE_RUNTIME_FAIL:-}" ] || exit 9
    echo 'built workstation runtime'
    tree="$FAKE_ROOT/runtime-output"
    mkdir -p "$tree"
    for component in manifest.json bzImage initrd nix-store.squashfs; do
      printf '%s\\n' "$component" > "$tree/$component"
    done
    ln -sfn "$tree" result-workstation-netboot ;;
  nix-shell)
    case "$*" in
      *"| zstd "*) printf '%s\\n' "${@: -1}" > "$FAKE_ROOT/archive-command"; touch "dist/$BUILD_BUNDLE" ;;
    esac ;;
esac
'''

FAKE_PART = '''#!/usr/bin/env bash
set -euo pipefail
name="$(basename "$0")"
''' + BARRIER + '''
printf '%s start\\n' "$name" >> "$FAKE_LOG"
beside "$name"
if [ "${FAKE_FAIL_PART:-}" = "$name" ]; then echo "$name broke" >&2; exit 4; fi
output=""
while [ "$#" -gt 0 ]; do
  case "$1" in --output-dir | --unsigned-output-dir) output="$2"; shift ;; esac
  shift
done
mkdir -p "$output"
if [ "$name" = build-template.sh ]; then
  touch "$output/tiaris-nest-appliance-template-$BUILD_VERSION-x86_64-linux.iso" \\
    "$output/tiaris-nest-appliance-template-$BUILD_VERSION-x86_64-linux.json" \\
    "$output/tiaris-usb-installer.img" "$output/tiaris-usb-installer.json"
fi
printf '%s end\\n' "$name" >> "$FAKE_LOG"
'''


@unittest.skipUnless(shutil.which('sed'), 'sed is required')
class ReleaseBuildScriptTests(unittest.TestCase):
    """The workflow's own container build script, run against fake build tools."""

    @classmethod
    def setUpClass(cls):
        build = step(job(WORKFLOW.read_text(), 'release_build'),
                     'Build exact binaries, appliance media, and workstation runtime')
        cls.script = run_script(build).split("<<'BUILD'\n", 1)[1].split('\nBUILD\n', 1)[0]

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.work = self.root / 'work'
        tools = self.root / 'bin'
        for directory in (self.work / 'target/release', self.work / 'nixos-appliance', self.work / 'tools',
                          self.root / 'scratch', tools):
            directory.mkdir(parents=True)
        for name in ('cargo', 'git', 'nix-build', 'nix-shell'):
            (tools / name).write_text(FAKE_TOOL)
            (tools / name).chmod(0o755)
        for name in ('build-closure.sh', 'build-template.sh'):
            (self.work / 'nixos-appliance' / name).write_text(FAKE_PART)
            (self.work / 'nixos-appliance' / name).chmod(0o755)
        (self.work / 'target/release/tiaris-nest').write_text('#!/bin/sh\necho "tiaris-nest 0.2.151"\n')
        (self.work / 'target/release/tiaris-nest-bootstrap').write_text(
            '#!/bin/sh\necho https://manage.tiaris.com\n')
        for binary in ('tiaris-nest', 'tiaris-nest-bootstrap'):
            (self.work / 'target/release' / binary).chmod(0o755)
        (self.work / 'tools/nest-release.py').write_text(
            'import os, sys\nopen(os.environ["FAKE_LOG"], "a").write("inspect " + " ".join(sys.argv[1:]) + "\\n")\n')
        self.log = self.root / 'log'
        self.environment = {
            **os.environ, 'PATH': f'{tools}{os.pathsep}{os.environ["PATH"]}', 'FAKE_LOG': str(self.log),
            'FAKE_ROOT': str(self.root), 'RUNNER_TEMP': str(self.root / 'scratch'),
            'GITHUB_REF_NAME': 'v0.2.151', 'BUILD_VERSION': '0.2.151',
            'BUILD_BUNDLE': 'tiaris-workstation-netboot-1.0.190-aaaaaaaaaaaa-x86_64-linux.tar.zst',
            'BUILD_RUNTIME': '1.0.190', 'BUILD_MANAGE_REVISION': 'b' * 40, 'BUILD_NIXPKGS_REVISION': 'c' * 40,
            'BUILD_HAS_PREDECESSOR': 'true', 'BUILD_REUSE_RUNTIME': 'false',
            'TIARIS_NEST_BUILD_MANAGE_ORIGIN': 'https://manage.tiaris.com',
            'TIARIS_NEST_UPDATE_TRUSTED_PUBLIC_KEY': 'release-key',
            'TIARIS_NEST_PROVISIONING_PUBLIC_KEYS': 'provisioning-key'}

    def build(self, **changes):
        for marker in self.root.glob('started-*'):
            marker.unlink()
        environment = {**self.environment, 'FAKE_PARTS': '2' if changes.get('BUILD_REUSE_RUNTIME') == 'true' else '3',
                       **changes}
        return subprocess.run(['bash', '-c', self.script], cwd=self.work, env=environment,
                              capture_output=True, text=True, timeout=120)

    def test_parts_run_side_by_side_and_produce_every_output(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        log = self.log.read_text()
        self.assertLess(log.index('build-template.sh start'), log.index('build-closure.sh end'))
        self.assertIn('inspect inspect-workstation-netboot', log)
        self.assertTrue((self.work / 'dist/tiaris-nest-appliance-template-0.2.151-x86_64-linux.iso').is_file())
        self.assertTrue((self.root / 'scratch/tiaris-nest-appliance-template-metadata.json').is_file())
        # The stick is a release asset beside the ISO; its build record stays outside dist.
        self.assertTrue((self.work / 'dist/tiaris-usb-installer-0.2.151.img').is_file())
        self.assertTrue((self.root / 'scratch/tiaris-usb-installer-record.json').is_file())
        self.assertTrue((self.work / 'dist' / self.environment['BUILD_BUNDLE']).is_file())
        for component in ('manifest.json', 'bzImage', 'initrd', 'nix-store.squashfs'):
            self.assertTrue((self.root / 'scratch/tiaris-workstation-netboot-tree' / component).is_file())
        self.assertIn('[workstation runtime] built workstation runtime', result.stdout)

    def test_the_runtime_archive_is_exactly_the_reproducible_zstd_3_stream(self):
        self.assertEqual(self.build().returncode, 0)
        command = (self.root / 'archive-command').read_text()
        self.assertIn('tar --format=ustar --sort=name --numeric-owner --owner=0 --group=0 --mode=u=rw,go=r '
                      '--mtime=@1700000000 ', command)
        self.assertIn('-cf - bzImage initrd manifest.json nix-store.squashfs | '
                      'zstd -3 --threads=1 --no-progress --no-dictID -o ', command)
        self.assertEqual(self.script.count('| zstd '), 1)

    def test_a_reused_runtime_is_never_rebuilt(self):
        (self.work / 'dist').mkdir()
        (self.work / 'dist' / self.environment['BUILD_BUNDLE']).write_text('published bytes\n')
        result = self.build(BUILD_REUSE_RUNTIME='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('nix-build', self.log.read_text())
        self.assertEqual((self.work / 'dist' / self.environment['BUILD_BUNDLE']).read_text(), 'published bytes\n')

    def test_every_failing_part_fails_the_build(self):
        for changes, part in (({'FAKE_RUNTIME_FAIL': '1'}, 'workstation runtime'),
                              ({'FAKE_FAIL_PART': 'build-closure.sh'}, 'Nest system'),
                              ({'FAKE_FAIL_PART': 'build-template.sh'}, 'setup media')):
            with self.subTest(part=part):
                shutil.rmtree(self.work / 'dist', ignore_errors=True)
                for leftover in ('tiaris-nest-unsigned-closure', 'tiaris-nest-template'):
                    shutil.rmtree(self.root / 'scratch' / leftover, ignore_errors=True)
                result = self.build(**changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Release build part failed: ' + part, result.stderr)


if __name__ == '__main__':
    unittest.main()
