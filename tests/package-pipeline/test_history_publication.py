import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/package-pipeline/publish-history.py"
SPEC = importlib.util.spec_from_file_location("history_publisher", SCRIPT)
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)

PACKAGE = "noctalia-greeter-t4t3z0r"
FILE = PACKAGE + "-1.7.0-1-x86_64.pkg.tar.zst"
SIGNATURE = FILE + ".sig"


class HistoryPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.staging = self.root / "archive-output"
        self.staging.mkdir()

        (self.staging / FILE).write_bytes(b"valid-test-package")
        (self.staging / SIGNATURE).write_bytes(b"valid-test-signature")

        self.remote = {}
        self.operations = []
        self.fail_view = False
        self.fail_upload = False
        self.corrupt_download = False

    def fake_run(self, *args):
        if args[0] == sys.executable:
            return json.dumps({
                "archive_required": True,
                "history_release": "arch-history-" + PACKAGE,
                "file": FILE,
                "signature": SIGNATURE,
                "verified": True,
            })

        self.assertEqual(args[:2], ("gh", "release"))
        operation = args[2]
        self.operations.append(operation)

        if operation == "view":
            if self.fail_view:
                raise subprocess.CalledProcessError(1, args)
            return json.dumps(sorted(self.remote))

        if operation == "upload":
            if self.fail_upload:
                raise subprocess.CalledProcessError(1, args)
            asset = Path(args[4])
            self.remote[asset.name] = asset.read_bytes()
            return ""

        if operation == "download":
            name = args[args.index("--pattern") + 1]
            directory = Path(args[args.index("--dir") + 1])
            if name not in self.remote:
                raise subprocess.CalledProcessError(1, args)
            content = self.remote[name]
            if self.corrupt_download:
                content = b"corrupted-download"
            (directory / name).write_bytes(content)
            return ""

        self.fail("Unexpected GitHub operation: " + operation)

    def execute(self, publish=True):
        argv = [
            "publish-history.py",
            "--package", PACKAGE,
            "--fingerprint", "A" * 40,
            "--staging", str(self.staging),
        ]
        if publish:
            argv.append("--publish")

        output = io.StringIO()

        with (
            patch.object(sys, "argv", argv),
            patch.object(publisher, "run", side_effect=self.fake_run),
            patch.dict(os.environ, {
                "GH_TOKEN": "disposable-test-token",
                "GH_REPO": "example/disposable",
            }),
            contextlib.redirect_stdout(output),
        ):
            publisher.main()

        return json.loads(output.getvalue())

    def test_successful_upload_and_verification(self):
        result = self.execute()
        self.assertTrue(result["verified"])
        self.assertEqual(set(self.remote), {FILE, SIGNATURE})
        self.assertEqual(self.operations.count("upload"), 2)

    def test_existing_matching_archive_is_idempotent(self):
        self.remote = {
            FILE: (self.staging / FILE).read_bytes(),
            SIGNATURE: (self.staging / SIGNATURE).read_bytes(),
        }
        result = self.execute()
        self.assertTrue(result["verified"])
        self.assertNotIn("upload", self.operations)

    def test_partial_upload_resumes(self):
        self.remote[FILE] = (self.staging / FILE).read_bytes()
        result = self.execute()
        self.assertTrue(result["verified"])
        self.assertEqual(self.operations.count("upload"), 1)
        self.assertEqual(set(self.remote), {FILE, SIGNATURE})

    def test_conflicting_archive_blocks_upload(self):
        self.remote[FILE] = b"conflicting-existing-package"
        with self.assertRaisesRegex(ValueError, "Conflicting archived asset"):
            self.execute()
        self.assertNotIn("upload", self.operations)

    def test_missing_release_blocks_upload(self):
        self.fail_view = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertNotIn("upload", self.operations)

    def test_upload_failure_is_not_success(self):
        self.fail_upload = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertEqual(self.remote, {})

    def test_corrupted_download_blocks_verification(self):
        self.corrupt_download = True
        with self.assertRaisesRegex(ValueError, "Archive verification failed"):
            self.execute()

    def test_dry_run_never_contacts_github(self):
        result = self.execute(publish=False)
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["published"])
        self.assertEqual(self.operations, [])


if __name__ == "__main__":
    unittest.main()
