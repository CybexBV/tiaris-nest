"""Real Nix regression for signed appliance seeds.

Only runs in the disposable CI guest: its daemon owns the temporary build and
the test key never leaves the test's temporary directory.
"""
import os
import subprocess
import unittest


@unittest.skipUnless(os.environ.get('CI') == 'true', 'requires disposable Nix CI guest')
class SignedSeedCacheTests(unittest.TestCase):
    def test_seed_publication_replaces_damaged_cached_nars(self):
        result = subprocess.run(
            ['cargo', 'test', '--locked', '--test', 'cache_seeds_nix', '--', '--ignored', '--nocapture'],
            text=True, capture_output=True, timeout=600,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
