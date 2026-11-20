"""Real Nix regression for signed appliance seeds in an isolated dry run.

Only runs in the disposable CI guest: its daemon owns the temporary build and
the test key never leaves TemporaryDirectory.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid


@unittest.skipUnless(os.environ.get('CI') == 'true', 'requires disposable Nix CI guest')
class SignedSeedCacheTests(unittest.TestCase):
    def run_command(self, *args):
        return subprocess.run(args, check=True, text=True, capture_output=True, timeout=600).stdout

    def test_seed_publication_replaces_damaged_cached_nars(self):
        result = subprocess.run(
            ['cargo', 'test', '--locked', '--test', 'cache_seeds_nix', '--', '--ignored', '--nocapture'],
            text=True, capture_output=True, timeout=600,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_only_signed_daemon_outputs_satisfy_an_isolated_dry_run(self):
        pin = json.loads(self.run_command(
            'nix-instantiate', '--eval', '--strict', '--json', 'release/nixpkgs.nix'))
        with tempfile.TemporaryDirectory(prefix='signed-seed-contract-') as temporary:
            root = Path(temporary)
            fixture = root / 'fixture'
            fixture.mkdir()
            nonce = uuid.uuid4().hex
            (fixture / 'flake.nix').write_text('''{
              outputs = { self }: let
                nixpkgs = builtins.fetchTarball %s;
                pkgs = import nixpkgs { system = "x86_64-linux"; };
              in { packages.x86_64-linux.seed =
                pkgs.runCommand "dry-run-seed-%s" { }
                  "printf '%%s' '%s' > $out"; };
            }''' % ('{ url = %s; sha256 = %s; }' %
                     (json.dumps(pin['url']), json.dumps(pin['sha256'])), nonce, nonce))
            installable = f'{fixture}#seed'
            built = json.loads(self.run_command('nix', '--extra-experimental-features',
                'nix-command flakes', 'build', '--no-link', '--json', installable))[0]
            seed = built['outputs']['out']
            secret = self.run_command('nix', '--extra-experimental-features', 'nix-command',
                'key', 'generate-secret', '--key-name', 'tiaris-nest-appliance-1')
            key = root / 'key'
            key.write_text(secret)
            key.chmod(0o600)
            public = subprocess.run(['nix', '--extra-experimental-features', 'nix-command',
                'key', 'convert-secret-to-public'], input=secret, text=True,
                capture_output=True, check=True, timeout=30).stdout.strip()

            def dry_run():
                return subprocess.run(['cargo', 'test', '--locked',
                    'isolated_dry_run_leaves_nothing_unadmitted', '--', '--ignored', '--nocapture'],
                    env={**os.environ, 'TIARIS_DRY_RUN_INSTALLABLE': installable,
                         'TIARIS_DRY_RUN_RELEASE_KEY': public.split(':', 1)[1]},
                    text=True, capture_output=True, timeout=600)

            # A daemon build is marked ultimate locally, but that must not
            # grant an unsigned path trust in the isolated verification store.
            unsigned = dry_run()
            self.assertNotEqual(unsigned.returncode, 0, unsigned.stdout + unsigned.stderr)
            self.assertIn(f'dry-run-seed-{nonce}', unsigned.stdout + unsigned.stderr)
            self.run_command('sudo', '-n', 'nix', '--extra-experimental-features',
                'nix-command', 'store', 'sign', '--key-file', str(key), seed)
            signed = dry_run()
            self.assertEqual(signed.returncode, 0, signed.stdout + signed.stderr)
