"""The USB installer stick is a signed part of a Nest release manifest."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
TOOL = REPOSITORY / "tools" / "nest-release.py"
PUBLISHED = REPOSITORY / "tools/tests/fixtures/production-origin/v0.2.99/tiaris-nest-release.json"
VERSION = "0.2.160"
REVISION = "a" * 40
URL = f"https://github.com/CybexHQ/tiaris-nest/releases/download/v{VERSION}/tiaris-usb-installer-{VERSION}.img"


class UsbInstallerImageTests(unittest.TestCase):
    def setUp(self):
        self.api = runpy.run_path(str(TOOL))
        self.error = self.api["ReleaseError"]
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.image = self.directory / f"tiaris-usb-installer-{VERSION}.img"
        self.image.write_bytes(b"generic stick image\n" * 64)
        self.record = self.directory / "tiaris-usb-installer.json"
        self.write_record()

    def tearDown(self):
        self.temporary.cleanup()

    def write_record(self, **changes):
        body = self.image.read_bytes()
        record = {"schema": "tiaris.usb-installer.image.v1", "image": "tiaris-usb-installer.img",
                  "protocol": 2, "size_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                  "source_revision": REVISION, **changes}
        self.record.write_text(json.dumps(record))

    def arguments(self, **changes):
        values = {"usb_installer_image": str(self.image), "usb_installer_image_url": URL,
                  "usb_installer_image_record": str(self.record), **changes}
        return argparse.Namespace(**values)

    def inputs(self, **changes):
        return self.api["_usb_installer_image_inputs"](self.arguments(**changes), VERSION)

    def test_the_descriptor_names_the_exact_image_and_its_tiaris_revision(self):
        descriptor, protected = self.inputs()
        body = self.image.read_bytes()
        self.assertEqual(descriptor, {
            "version": VERSION, "url": URL, "size_bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(), "manage_source_revision": REVISION})
        self.assertEqual([path for path, _ in protected], [self.image, self.record])
        self.assertEqual(
            self.api["_usb_installer_image_message"](descriptor),
            ("TIARIS-NEST-USB-INSTALLER-IMAGE-V1\n" f"{VERSION}\n{REVISION}\n{len(body)}\n"
             f"{hashlib.sha256(body).hexdigest()}\n{URL}\n").encode())

    def test_a_release_without_stick_arguments_names_no_stick(self):
        self.assertIsNone(self.inputs(usb_installer_image=None, usb_installer_image_url=None,
                                      usb_installer_image_record=None))
        self.assertIsNone(self.api["_usb_installer_image_inputs"](argparse.Namespace(), VERSION))

    def test_incomplete_or_mismatched_inputs_are_refused(self):
        for changes in ({"usb_installer_image_url": None}, {"usb_installer_image_record": None},
                        {"usb_installer_image": None},
                        {"usb_installer_image_url": URL.replace(".img", ".iso")},
                        {"usb_installer_image_url": URL.replace(VERSION + ".img", "0.2.159.img")}):
            with self.subTest(changes=changes), self.assertRaises(self.error):
                self.inputs(**changes)
        other = self.directory / "tiaris-usb-installer.img"
        other.write_bytes(self.image.read_bytes())
        with self.assertRaisesRegex(self.error, "must be named"):
            self.inputs(usb_installer_image=str(other))
        for changes in ({"size_bytes": 1}, {"sha256": "0" * 64}, {"schema": "other"},
                        {"image": "other.img"}, {"source_revision": "main"}, {"protocol": True}):
            with self.subTest(record=changes):
                self.write_record(**changes)
                with self.assertRaises(self.error):
                    self.inputs()

    def test_a_stick_this_nest_would_turn_away_is_never_signed(self):
        minimum = self.api["_minimum_stick_protocol"]()
        self.assertGreaterEqual(minimum, 2)
        self.write_record(protocol=minimum)
        self.inputs()
        self.write_record(protocol=minimum - 1)
        with self.assertRaisesRegex(self.error, "pin a Tiaris revision with a current stick"):
            self.inputs()
        unreadable = self.directory / "usb_installer.rs"
        unreadable.write_text("pub const MINIMUM_STICK_PROTOCOL: u32 = two;\n")
        with self.assertRaisesRegex(self.error, "unreadable"):
            self.api["_minimum_stick_protocol"](unreadable)

    def signed(self, descriptor):
        key = self.directory / "key.pem"
        if not key.exists():
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)],
                           check=True, capture_output=True)
            key.chmod(0o600)
        fd = os.open(key, os.O_RDONLY)
        try:
            public_der = self.api["_public_der"](fd)
            signature = self.api["_sign"](fd, self.api["_usb_installer_image_message"](descriptor))
        finally:
            os.close(fd)
        return {**descriptor, "signature": base64.b64encode(signature).decode()}, public_der

    def test_a_signed_descriptor_validates_and_binds_version_name_and_revision(self):
        descriptor, _ = self.inputs()
        signed, public_der = self.signed(descriptor)
        validate = self.api["_validate_usb_installer_image"]
        unsigned, signature = validate(signed, VERSION, REVISION)
        self.assertEqual(unsigned, descriptor)
        self.api["_self_verify"](public_der, signature, self.api["_usb_installer_image_message"](unsigned))
        with self.assertRaises(self.error):
            self.api["_self_verify"](public_der, signature, self.api["_usb_installer_image_message"](
                {**unsigned, "sha256": "0" * 64}))
        for changed, version, revision in (
                (signed, "0.2.161", REVISION), (signed, VERSION, "b" * 40),
                ({**signed, "extra": 1}, VERSION, REVISION),
                ({key: value for key, value in signed.items() if key != "sha256"}, VERSION, REVISION),
                ({**signed, "size_bytes": 0}, VERSION, REVISION),
                ({**signed, "size_bytes": 2 * 1024 ** 3}, VERSION, REVISION),
                ({**signed, "sha256": "A" * 64}, VERSION, REVISION),
                ({**signed, "url": URL.replace(".img", ".iso")}, VERSION, REVISION),
                ({**signed, "signature": "AAAA"}, VERSION, REVISION)):
            with self.subTest(changed=changed, version=version), self.assertRaises(self.error):
                validate(changed, version, revision)

    def test_a_nixos_manifest_may_name_the_stick_and_its_signature_is_checked(self):
        manifest = json.loads(PUBLISHED.read_text())
        identities = self.api["_release_manifest_artifact_identities"]
        version, before, messages = identities(manifest)
        revision = manifest["appliance_release_v1"]["manage_source_revision"]
        url = (f"https://github.com/CybexHQ/tiaris-nest/releases/download/v{version}/"
               f"tiaris-usb-installer-{version}.img")
        signed, public_der = self.signed({"version": version, "url": url, "size_bytes": 1280,
                                          "sha256": "c" * 64, "manage_source_revision": revision})
        _, after, with_stick = identities({**manifest, "usb_installer_image_v1": signed})
        # The compatibility asset keeps its artifact set; the manifest it binds names the stick.
        self.assertEqual(after, before)
        self.assertEqual(len(with_stick), len(messages) + 1)
        self.api["_verify_signed_messages"](public_der, with_stick[-1:])
        with self.assertRaisesRegex(self.error, "pinned Tiaris revision"):
            identities({**manifest, "usb_installer_image_v1": {**signed, "manage_source_revision": "b" * 40}})
        with self.assertRaises(self.error):
            identities({**manifest, "usb_installer_image_v2": signed})

    def test_a_legacy_ubuntu_manifest_cannot_name_a_stick(self):
        manifest = json.loads((REPOSITORY / "tools/tests/fixtures/recovery/github-manifest.json").read_text())
        with self.assertRaisesRegex(self.error, "exact supported set"):
            self.api["_release_manifest_artifact_identities"]({**manifest, "usb_installer_image_v1": {}})

    def test_verification_wants_the_image_exactly_when_the_manifest_names_one(self):
        verify = self.api["_verify_usb_installer_image_bytes"]
        descriptor, _ = self.inputs()
        manifest = {"usb_installer_image_v1": descriptor}
        verify(manifest, VERSION, str(self.image))
        verify({}, VERSION, None)
        with self.assertRaisesRegex(self.error, "exactly when"):
            verify(manifest, VERSION, None)
        with self.assertRaisesRegex(self.error, "exactly when"):
            verify({}, VERSION, str(self.image))
        with self.assertRaisesRegex(self.error, "filename"):
            verify(manifest, "0.2.161", str(self.image))
        self.image.write_bytes(self.image.read_bytes() + b"x")
        with self.assertRaisesRegex(self.error, "bytes differ"):
            verify(manifest, VERSION, str(self.image))


if __name__ == "__main__":
    unittest.main()
