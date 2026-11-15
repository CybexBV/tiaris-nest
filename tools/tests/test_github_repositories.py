"""A renamed GitHub repository is still the same repository, before and after the rename.

`CybexHQ/james` becomes `CybexHQ/tiaris-nest` and `CybexHQ/development` becomes
`CybexHQ/tiaris`. Signed, immutable releases keep the old-name URLs they were
published with, while GitHub's API and `GITHUB_REPOSITORY` report the new name.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / 'tools/github_repositories.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


R = load('github_repositories_under_test', TOOL)
P = load('rename_release_predecessor', ROOT / 'nixos-appliance/qualification/release_predecessor.py')
OLD, NEW = 'CybexHQ/james', 'CybexHQ/tiaris-nest'
OLD_TIARIS, NEW_TIARIS = 'CybexHQ/development', 'CybexHQ/tiaris'
UNRELATED = ('CybexHQ/manage', 'CybexHQ/james-extra', 'other/james', 'cybexhq/james', 'CybexHQ', '', None)


class NamesTests(unittest.TestCase):
    def test_both_names_of_each_repository_are_the_same_repository(self):
        for old, new in ((OLD, NEW), (OLD_TIARIS, NEW_TIARIS)):
            for left, right in ((old, new), (new, old), (old, old), (new, new)):
                with self.subTest(left=left, right=right):
                    self.assertTrue(R.same_repository(left, right))

    def test_unrelated_repositories_and_the_other_repository_are_rejected(self):
        for name in (*UNRELATED, OLD_TIARIS, NEW_TIARIS):
            with self.subTest(name=name):
                self.assertFalse(R.same_repository(OLD, name))
                self.assertFalse(R.same_repository(NEW, name))
        self.assertTrue(R.same_repository('other/nest', 'other/nest'))
        self.assertFalse(R.same_repository('other/nest', 'other/nest2'))

    def test_current_names_are_unchanged_until_the_rename(self):
        # Built URLs and records keep the current names; nothing may require
        # the new repositories to exist yet.
        self.assertEqual((R.NEST, R.TIARIS), (OLD, OLD_TIARIS))
        data = json.loads((ROOT / 'release/github-repositories.json').read_text())
        for role in ('nest', 'tiaris'):
            self.assertIn(data[role]['current'], data[role]['names'])
        self.assertEqual(set(R.NEST_NAMES), {OLD, NEW})
        self.assertEqual(set(R.TIARIS_NAMES), {OLD_TIARIS, NEW_TIARIS})

    def test_old_name_signed_url_matches_the_url_derived_from_the_new_name(self):
        signed = f'https://github.com/{OLD}/releases/download/v0.2.99/tiaris-nest-release.json'
        derived = f'https://github.com/{NEW}/releases/download/v0.2.99/tiaris-nest-release.json'
        self.assertTrue(R.same_url(signed, derived))
        self.assertTrue(R.same_url(derived, signed))
        for other in (f'https://github.com/{NEW}/releases/download/v0.2.98/tiaris-nest-release.json',
                      f'https://github.com/{NEW_TIARIS}/releases/download/v0.2.99/tiaris-nest-release.json',
                      'https://github.com/CybexHQ/manage/releases/download/v0.2.99/tiaris-nest-release.json',
                      'https://github.com.evil/CybexHQ/tiaris-nest/releases/download/v0.2.99/tiaris-nest-release.json',
                      'http://github.com/CybexHQ/tiaris-nest/releases/download/v0.2.99/tiaris-nest-release.json',
                      f'https://github.com/{NEW}', None):
            with self.subTest(other=other):
                self.assertFalse(R.same_url(signed, other))

    def test_url_spelling_and_git_remotes(self):
        url = f'https://github.com/{OLD}/releases/download/v1/x'
        self.assertEqual(R.spelled(url, NEW), f'https://github.com/{NEW}/releases/download/v1/x')
        self.assertEqual(R.spelled(url, OLD), url)
        self.assertEqual(R.spelled(url, 'CybexHQ/manage'), url)
        remotes = R.git_remotes(OLD_TIARIS)
        for name in (OLD_TIARIS, NEW_TIARIS):
            self.assertLessEqual({f'https://github.com/{name}', f'https://github.com/{name}.git',
                                  f'git@github.com:{name}.git'}, remotes)
        self.assertNotIn('https://github.com/CybexHQ/manage', remotes)

    def test_command_line_for_workflow_shell(self):
        def run(*arguments):
            return subprocess.run([sys.executable, '-I', '-B', str(TOOL), *arguments],
                                  capture_output=True, text=True)
        self.assertEqual(run('same', 'tiaris', NEW_TIARIS).returncode, 0)
        self.assertEqual(run('same', 'tiaris', OLD_TIARIS).returncode, 0)
        self.assertEqual(run('same', 'tiaris', 'CybexHQ/manage').returncode, 1)
        self.assertEqual(run('same', NEW, OLD).returncode, 0)
        self.assertEqual(run('same', 'nest', OLD_TIARIS).returncode, 1)
        result = run('url', NEW, f'https://github.com/{OLD}/releases/download/v1/b.tar.zst')
        self.assertEqual(result.stdout.strip(), f'https://github.com/{NEW}/releases/download/v1/b.tar.zst')
        result = run('url', NEW, 'https://github.com/other/x/releases/download/v1/b.tar.zst')
        self.assertEqual(result.stdout.strip(), 'https://github.com/other/x/releases/download/v1/b.tar.zst')
        self.assertEqual(run('bogus').returncode, 2)

    def test_workflow_and_nix_read_the_shared_names(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertIn('python3 -B tools/github_repositories.py same tiaris "$repository"', workflow)
        self.assertIn('tools/github_repositories.py url "$GITHUB_REPOSITORY" "$url"', workflow)
        expression = (ROOT / 'release/workstation-netboot.nix').read_text()
        self.assertIn('builtins.readFile ./github-repositories.json', expression)
        self.assertIn('assert builtins.elem sourcePin.repository tiarisNames;', expression)


class SignedReleaseTests(unittest.TestCase):
    """Real signed fixtures published under the old name, checked under the new one."""
    RECOVERY = ROOT / 'tools/tests/fixtures/tiaris-recovery'

    def setUp(self):
        self.authorization = self.RECOVERY / 'authorization.json'
        self.anchor = json.loads(self.authorization.read_bytes())

    def pair(self, directory):
        (directory / P.MANIFEST).write_bytes((self.RECOVERY / 'github-manifest.json').read_bytes())
        (directory / P.COMPATIBILITY).write_bytes((self.RECOVERY / 'github-compatibility.json').read_bytes())

    def test_signed_old_name_manifest_url_verifies_under_the_new_name(self):
        key, tag = self.anchor['published']['public_key'], self.anchor['published']['tag_name']
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.pair(directory)
            for name in (OLD, NEW):
                P.verify_pair(directory, key, f'https://github.com/{name}/releases/download/{tag}/' + P.MANIFEST)
            for name in ('CybexHQ/manage', NEW_TIARIS, 'other/james'):
                with self.subTest(name=name), self.assertRaises(P.release.ReleaseError):
                    P.verify_pair(directory, key, f'https://github.com/{name}/releases/download/{tag}/' + P.MANIFEST)

    def test_historical_authorization_signed_for_the_old_name_admits_the_new_name(self):
        previous = self.anchor['published'] | {'id': self.anchor['published']['github_release_id']}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.pair(directory)
            for name in (OLD, NEW):
                self.assertEqual(P.historical_authority(self.authorization, self.anchor['public_key'], previous,
                                 directory, self.anchor['successor_version'], name),
                                 self.anchor['published']['public_key'])
            with self.assertRaises(ValueError):
                P.historical_authority(self.authorization, self.anchor['public_key'], previous, directory,
                                       self.anchor['successor_version'], NEW_TIARIS)

    def test_namespace_transition_signed_for_the_old_name_resolves_when_the_api_reports_the_new_name(self):
        fixture = ROOT / 'tools/tests/fixtures/james-0.2.41'
        anchor = json.loads(P.TRANSITION.read_bytes())
        previous = {'id': anchor['published']['github_release_id'], **anchor['published']}
        def publication(name):
            return previous | {'draft': False, 'published_at': '1', 'assets': [
                {'name': asset, 'size': (fixture / asset).stat().st_size,
                 'browser_download_url': f'https://github.com/{name}/releases/download/v0.2.41/{asset}'}
                for asset in (P.transition.MANIFEST, P.transition.COMPATIBILITY)]}
        for repository, api_name, admitted in ((NEW, NEW, True), (OLD, NEW, True), (NEW, OLD, True),
                                               ('CybexHQ/other', 'CybexHQ/other', False)):
            def github(_repository, path):
                return [publication(api_name)] if path.startswith('releases?') else {'sha': previous['target_commitish']}
            with self.subTest(repository=repository, api=api_name), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(P, 'github', side_effect=github):
                directory = Path(temporary)
                for path in fixture.iterdir():
                    (directory / path.name).write_bytes(path.read_bytes())
                if admitted:
                    result = P.resolve(repository, anchor['successor_version'], anchor['public_key'], directory)
                    self.assertEqual(result['update_contract'], 'reinstall-only')
                else:
                    with self.assertRaises(ValueError):
                        P.resolve(repository, anchor['successor_version'], anchor['public_key'], directory)

    def test_published_asset_urls_bind_the_repository_under_either_name(self):
        manifest = {"version": "0.2.78", "appliance_release_v1": {"schema": "tiaris.nest.appliance-release.v3",
                    "source_revision": "7" * 40, "manage_source_revision": "8" * 40,
                    "system_closure": {"sha256": "9" * 64}, "system_toplevel": "/nix/store/x"}}
        for api_name, admitted in ((NEW, True), (OLD, True), ('CybexHQ/manage', False)):
            release = {"id": 7, "tag_name": "v0.2.78", "draft": False, "prerelease": False,
                       "published_at": "1", "target_commitish": "7" * 40, "assets": [
                           {"name": name, "size": 2, "digest": "sha256:" + "a" * 64,
                            "browser_download_url": f"https://github.com/{api_name}/releases/download/v0.2.78/{name}"}
                           for name in (P.MANIFEST, P.COMPATIBILITY)]}
            def github(_repository, path, release=release):
                return [release] if path.startswith("releases") else {"sha": "7" * 40}
            with self.subTest(api=api_name), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(P, "github", side_effect=github), \
                    mock.patch.object(P, "fetch", side_effect=lambda url, path, *_a: path.write_bytes(b"{}")), \
                    mock.patch.object(P, "verify_pair", return_value=manifest):
                if admitted:
                    self.assertEqual(P.resolve(NEW, "0.2.79", "k", Path(temporary))["release_id"], "0.2.78")
                else:
                    with self.assertRaisesRegex(ValueError, 'bind repository'):
                        P.resolve(NEW, "0.2.79", "k", Path(temporary))

    def test_production_origin_transition_record_under_the_new_name_binds_old_name_signed_url(self):
        release = P.release
        record = {'repository': NEW, 'predecessor': {'nest_release_version': '0.2.99', 'tag_name': 'v0.2.99',
                  'compatibility_sha256': '', 'manifest_sha256': 'b' * 64}}
        body = b'previous compatibility'
        record['predecessor']['compatibility_sha256'] = hashlib.sha256(body).hexdigest()
        def payload(name):
            return {'nest_release_version': '0.2.99', 'release_manifest': {
                'sha256': 'b' * 64, 'url': f'https://github.com/{name}/releases/download/v0.2.99/tiaris-nest-release.json'}}
        self.assertTrue(release._production_origin_transition_binds(record, payload(OLD), body))
        self.assertTrue(release._production_origin_transition_binds(record, payload(NEW), body))
        self.assertFalse(release._production_origin_transition_binds(record, payload('CybexHQ/manage'), body))


class ReleaseToolTests(unittest.TestCase):
    def test_vm_qualification_admits_a_release_published_before_the_rename(self):
        target = load('rename_vm_qualification_target', ROOT / 'tools/vm-qualification-target.py')
        fixture = load('rename_vm_fixture', ROOT / 'tools/tests/test_vm_qualification_target.py').fixture
        # GitHub answers the new name's API paths with the release published under the old name.
        data = {path.replace(OLD, NEW): value for path, value in fixture().items()}
        self.assertEqual(target.resolve(NEW, 'v0.2.80', lambda path: data[path], 'refs/tags/v0.2.80')['run'], '42')
        other = {path.replace(OLD, 'CybexHQ/other'): value for path, value in fixture().items()}
        with self.assertRaisesRegex(ValueError, 'exact release workflow run'):
            target.resolve('CybexHQ/other', 'v0.2.80', lambda path: other[path], 'refs/tags/v0.2.80')

    def test_publication_retry_finds_its_release_named_under_the_old_name(self):
        publication = load('rename_release_publication', ROOT / 'tools/release-publication.py')
        env = {'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_RUN_ID': '42', 'GITHUB_SHA': 'a' * 40,
               'GITHUB_REF_NAME': 'v0.2.2', 'TIARIS_NEST_RELEASE_VERSION': '0.2.2',
               'TIARIS_NEST_RELEASE_ARTIFACT_ID': '9', 'TIARIS_NEST_RELEASE_ARTIFACT_DIGEST': 'f' * 64}
        body = '\n'.join((f'Tiaris-Release-Workflow: https://github.com/{OLD}/actions/runs/42',
                          'Tiaris-Candidate-Artifact-ID: 9', 'Tiaris-Candidate-Artifact-SHA256: ' + 'f' * 64,
                          'Tiaris-VM-Qualification: nightly', 'Tiaris-Public-Closure: required'))
        release = {'id': 123, 'tag_name': 'v0.2.2', 'name': 'Tiaris Nest v0.2.2', 'body': body,
                   'target_commitish': 'a' * 40, 'prerelease': True, 'draft': True, 'immutable': False}
        def api(path, pages=False):
            return [[release]] if pages else {'sha': 'a' * 40}
        for repository, admitted in ((NEW, True), (OLD, True), ('CybexHQ/other', False)):
            with self.subTest(repository=repository), \
                    mock.patch.dict(os.environ, env | {'GITHUB_REPOSITORY': repository}), \
                    mock.patch.object(publication, 'api', side_effect=api):
                if admitted:
                    self.assertIsNone(publication.inspect())
                else:
                    with self.assertRaisesRegex(ValueError, 'does not belong'):
                        publication.inspect()

    def test_coordinated_pin_admits_either_tiaris_name_and_writes_the_current_one(self):
        module = runpy.run_path(str(ROOT / 'tools/coordinated-release.py'))
        for name, admitted in ((OLD_TIARIS, True), (NEW_TIARIS, True), ('CybexHQ/manage', False), (NEW, False)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'release').mkdir()
                (root / 'release/coordinated.json').write_text(json.dumps({
                    'schema': 'tiaris.coordinated-release.v2', 'appliance_family': 'nixos',
                    'manage_revision': 'a' * 40}))
                (root / 'release/workstation-netboot-source.json').write_text(json.dumps({
                    'repository': name, 'revision': 'a' * 40, 'runtime_version': '1.0.1'}))
                if admitted:
                    self.assertTrue(module['validate'](root))
                else:
                    with self.assertRaises(ValueError):
                        module['validate'](root)

    def test_local_candidate_receipt_sealed_under_the_old_name_is_the_same_repository(self):
        candidate = load('rename_local_candidate', ROOT / 'tools/local-candidate.py')
        expected = candidate.identity('42', 'a' * 40, 'v0.2.2')
        self.assertEqual(expected['repository'], OLD)
        files = {'a': {'size': 1, 'sha256': '0' * 64}, 'b': {'size': 1, 'sha256': '1' * 64}}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'candidate.json'
            for name, admitted in ((OLD, True), (NEW, True), ('CybexHQ/other', False)):
                path.write_text(json.dumps(expected | {'repository': name, 'files': files}))
                with self.subTest(name=name):
                    if admitted:
                        self.assertEqual(candidate.receipt(path, expected)['repository'], name)
                    else:
                        with self.assertRaises(ValueError):
                            candidate.receipt(path, expected)

    def test_fixture_source_and_image_admit_either_tiaris_name(self):
        config = load('rename_isolated_manage_config', ROOT / 'nixos-appliance/qualification/isolated_manage_config.py')
        resources = load('rename_isolated_manage_resources',
                         ROOT / 'nixos-appliance/qualification/isolated_manage_resources.py')
        self.assertEqual(config.SOURCE, 'https://github.com/' + OLD_TIARIS)
        for remote in (f'https://github.com/{NEW_TIARIS}', f'git@github.com:{NEW_TIARIS}.git',
                       f'https://github.com/{OLD_TIARIS}.git'):
            self.assertIn(remote, config.SOURCE_REMOTES)
        self.assertNotIn('https://github.com/CybexHQ/manage', config.SOURCE_REMOTES)
        for source, admitted in ((f'https://github.com/{NEW_TIARIS}', True), (config.SOURCE, True),
                                 ('https://github.com/CybexHQ/manage', False), (f'https://github.com/{NEW}', False)):
            image = {'Id': 'sha256:' + 'a' * 64, 'Config': {'Labels': {
                'org.opencontainers.image.revision': 'a' * 40, 'org.opencontainers.image.source': source,
                'net.tiaris.manage.nest-compatibility-projection-sha256': 'c' * 64}}}
            docker = resources.Docker(lambda args, image=image: json.dumps([image]).encode(), 'owner', 'fixture')
            with self.subTest(source=source):
                if admitted:
                    self.assertEqual(docker.image(image['Id'], 'app', 'a' * 40, 'c' * 64), image['Id'])
                else:
                    with self.assertRaises(ValueError):
                        docker.image(image['Id'], 'app', 'a' * 40, 'c' * 64)


class BuildCheckoutTests(unittest.TestCase):
    def test_release_build_admits_its_checkout_under_either_name_only(self):
        build = runpy.run_path(str(ROOT / 'nixos-appliance/build.py'))
        cases = [(OLD, OLD, True), (OLD, NEW, True), (OLD_TIARIS, OLD_TIARIS, True), (OLD_TIARIS, NEW_TIARIS, True),
                 (OLD, OLD_TIARIS, False), (OLD_TIARIS, NEW, False), (OLD, 'other/james', False), (OLD, 'CybexHQ/manage', False)]
        for expected, origin_name, admitted in cases:
            with self.subTest(expected=expected, origin=origin_name), tempfile.TemporaryDirectory() as temporary:
                checkout = Path(temporary).resolve()
                git = lambda *arguments: subprocess.run(['git', '-C', str(checkout), *arguments], check=True,
                                                        capture_output=True, text=True).stdout.strip()
                git('init', '-q')
                git('-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '--allow-empty', '-m', 'x')
                git('remote', 'add', 'origin', 'https://github.com/' + origin_name + '.git')
                revision = git('rev-parse', 'HEAD')
                if admitted:
                    build['clean_checkout'](checkout, revision, expected)
                else:
                    with self.assertRaisesRegex(ValueError, 'origin differs'):
                        build['clean_checkout'](checkout, revision, expected)


if __name__ == '__main__':
    unittest.main()
