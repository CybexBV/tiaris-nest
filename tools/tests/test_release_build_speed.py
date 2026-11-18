"""The release build parts run side by side.

These tests run the workflow's own build script with fake tools to prove its
parts overlap, keep the exact runtime archive and fail closed.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/release.yml'


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
    "$output/tiaris-nest-appliance-template-$BUILD_VERSION-x86_64-linux.json"
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
