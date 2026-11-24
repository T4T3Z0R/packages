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
        self.wrong_signer = False
        self.inject_unexpected_asset = False

    def fake_run(self, *args):
        if args[0] == sys.executable:
            return json.dumps({
                "archive_required": True,
                "history_release": "arch-history-" + PACKAGE,
                "file": FILE,
                "signature": SIGNATURE,
                "verified": True,
            })

        if args[0] == "gpg":
            signer = "B" * 40 if self.wrong_signer else "A" * 40
            return "[GNUPG:] VALIDSIG " + signer + " 0 0 0 0 0 0 0 0\\n"

        self.assertEqual(args[:2], ("gh", "release"))
        self.assertIn("--repo", args)
        self.assertEqual(
            args[args.index("--repo") + 1],
            "example/disposable",
        )
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
            if self.inject_unexpected_asset:
                self.remote["unexpected.json"] = b"surprise"
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

    def test_unauthorized_downloaded_signer_rejected(self):
        self.wrong_signer = True

        with self.assertRaisesRegex(
            ValueError, "Archived signature has unauthorized signer"
        ):
            self.execute()

        self.assertEqual(set(self.remote), {FILE, SIGNATURE})

    def test_orphaned_older_package_blocks_upload(self):
        old = PACKAGE + "-1.6.0-1-x86_64.pkg.tar.zst"
        self.remote[old] = b"older-package"

        with self.assertRaisesRegex(
            ValueError, "Incomplete historical package pair"
        ):
            self.execute()

        self.assertNotIn("upload", self.operations)

    def test_orphaned_older_signature_blocks_upload(self):
        old = PACKAGE + "-1.6.0-1-x86_64.pkg.tar.zst"
        self.remote[old + ".sig"] = b"older-signature"

        with self.assertRaisesRegex(
            ValueError, "Incomplete historical package pair"
        ):
            self.execute()

        self.assertNotIn("upload", self.operations)

    def test_unexpected_history_metadata_blocks_upload(self):
        self.remote["unexpected.json"] = b"metadata"

        with self.assertRaisesRegex(
            ValueError, "Unexpected history release asset"
        ):
            self.execute()

        self.assertNotIn("upload", self.operations)

    def test_complete_older_pair_is_allowed(self):
        old = PACKAGE + "-1.6.0-1-x86_64.pkg.tar.zst"
        self.remote[old] = b"older-package"
        self.remote[old + ".sig"] = b"older-signature"

        result = self.execute()

        self.assertTrue(result["verified"])
        self.assertEqual(self.operations.count("upload"), 2)
        self.assertIn(old, self.remote)
        self.assertIn(old + ".sig", self.remote)

    def test_unexpected_asset_after_upload_rejected(self):
        self.inject_unexpected_asset = True

        with self.assertRaisesRegex(
            ValueError, "Unexpected history release asset"
        ):
            self.execute()

        self.assertEqual(self.operations.count("upload"), 2)

    def test_dry_run_never_contacts_github(self):
        result = self.execute(publish=False)
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["published"])
        self.assertEqual(self.operations, [])


class HistoryMetadataTests(unittest.TestCase):
    def setUp(self):
        self.remote = {
            FILE: b"fixture-package",
            SIGNATURE: b"fixture-signature",
        }

        self.operations = []
        self.fingerprint = "A" * 40
        self.key_fingerprint = self.fingerprint
        self.signer = self.fingerprint

        self.metadata = (
            f"pkgname = {PACKAGE}\n"
            "pkgver = 1:1.7.0-1\n"
            "arch = x86_64\n"
        )

        self.views = 0
        self.change_inventory = False
        self.fail_download = False
        self.fail_signature = False

    def fake_run(self, *args):
        if args[0] == "gpg":
            if "--show-keys" in args:
                return "fpr:::::::::" + self.key_fingerprint + ":"

            self.operations.append("verify")

            if self.fail_signature:
                raise subprocess.CalledProcessError(1, args)

            return "[GNUPG:] VALIDSIG " + self.signer

        if args[0] == "bsdtar":
            self.operations.append("metadata")
            return self.metadata

        self.assertEqual(args[:2], ("gh", "release"))

        operation = args[2]
        self.operations.append(operation)

        if operation == "view":
            self.views += 1

            if self.change_inventory and self.views > 1:
                return "[]"

            return json.dumps(sorted(self.remote))

        if operation == "download":
            if self.fail_download:
                raise subprocess.CalledProcessError(1, args)

            name = args[args.index("--pattern") + 1]
            directory = Path(args[args.index("--dir") + 1])

            (directory / name).write_bytes(self.remote[name])
            return ""

        self.fail("Unexpected remote operation: " + operation)

    def collect(self):
        with (
            patch.object(
                publisher, "run", side_effect=self.fake_run
            ),
            patch.dict(os.environ, {
                "GH_REPO": "example/disposable",
            }),
        ):
            return publisher.collect_history_metadata(
                PACKAGE,
                self.fingerprint,
                ROOT / "arch/keys/t4t3z0r-package-signing.asc",
            )

    def test_verified_metadata_preserves_epoch(self):
        import hashlib

        result = self.collect()

        self.assertEqual(
            result["versions"], {FILE: "1:1.7.0-1"}
        )
        self.assertEqual(
            result["names"], sorted(self.remote)
        )

        self.assertEqual(
            result["sha256"],
            {
                name: hashlib.sha256(content).hexdigest()
                for name, content in self.remote.items()
            },
        )

        self.assertEqual(
            self.operations,
            [
                "view", "download", "download",
                "verify", "metadata", "view",
            ],
        )

    def test_empty_history(self):
        self.remote.clear()
        result = self.collect()

        self.assertEqual(result["names"], [])
        self.assertEqual(result["versions"], {})
        self.assertEqual(result["sha256"], {})

    def test_incomplete_pair_rejected(self):
        del self.remote[SIGNATURE]

        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.collect()

        self.assertNotIn("download", self.operations)

    def test_unexpected_asset_rejected(self):
        self.remote["unexpected.txt"] = b"unexpected"

        with self.assertRaisesRegex(ValueError, "Unexpected"):
            self.collect()

        self.assertNotIn("download", self.operations)

    def test_untrusted_fingerprint_rejected(self):
        self.key_fingerprint = "B" * 40

        with self.assertRaisesRegex(ValueError, "repository key"):
            self.collect()

        self.assertEqual(self.operations, [])

    def test_wrong_signer_rejected_before_metadata(self):
        self.signer = "B" * 40

        with self.assertRaisesRegex(ValueError, "unauthorized"):
            self.collect()

        self.assertNotIn("metadata", self.operations)

    def test_invalid_signature_rejected(self):
        self.fail_signature = True

        with self.assertRaises(subprocess.CalledProcessError):
            self.collect()

        self.assertNotIn("metadata", self.operations)

    def test_download_failure_rejected(self):
        self.fail_download = True

        with self.assertRaises(subprocess.CalledProcessError):
            self.collect()

        self.assertNotIn("metadata", self.operations)

    def test_metadata_identity_mismatch_rejected(self):
        self.metadata = self.metadata.replace(PACKAGE, "wrong")

        with self.assertRaisesRegex(ValueError, "disagrees"):
            self.collect()

    def test_metadata_version_mismatch_rejected(self):
        self.metadata = self.metadata.replace("1.7.0", "9.0")

        with self.assertRaisesRegex(ValueError, "disagrees"):
            self.collect()

    def test_metadata_architecture_mismatch_rejected(self):
        self.metadata = self.metadata.replace("x86_64", "any")

        with self.assertRaisesRegex(ValueError, "disagrees"):
            self.collect()

    def test_duplicate_metadata_field_rejected(self):
        self.metadata += f"pkgname = {PACKAGE}\n"

        with self.assertRaisesRegex(ValueError, "metadata field"):
            self.collect()

    def test_missing_metadata_field_rejected(self):
        self.metadata = self.metadata.replace(
            "arch = x86_64", ""
        )

        with self.assertRaisesRegex(ValueError, "metadata field"):
            self.collect()

    def test_inventory_change_rejected(self):
        self.change_inventory = True

        with self.assertRaisesRegex(ValueError, "inventory changed"):
            self.collect()


    def verified_plan(self, package=PACKAGE, protected=FILE):
        with (
            patch.object(
                publisher, "run", side_effect=self.fake_run
            ),
            patch.dict(os.environ, {
                "GH_REPO": "example/disposable",
            }),
        ):
            return publisher.plan_verified_history(
                package,
                self.fingerprint,
                protected,
            )

    def test_combined_verified_pruning_plan(self):
        plan = self.verified_plan()

        self.assertTrue(plan["dry_run"])
        self.assertEqual(plan["package"], PACKAGE)
        self.assertEqual(plan["protected"], FILE)
        self.assertEqual(plan["previous_versions_to_keep"], 3)
        self.assertEqual(plan["prune"], [])

        self.assertEqual(plan["keep"], [
            {"package": FILE, "signature": SIGNATURE}
        ])

        self.assertEqual(
            plan["verified_metadata"]["versions"],
            {FILE: "1:1.7.0-1"},
        )

        self.assertEqual(
            self.operations,
            [
                "view", "download", "download",
                "verify", "metadata", "view",
            ],
        )

    def test_combined_missing_protected_rejected(self):
        with self.assertRaisesRegex(ValueError, "Protected"):
            self.verified_plan(
                protected=PACKAGE + "-9.0-1-x86_64.pkg.tar.zst"
            )

    def test_combined_zero_retention_rejected(self):
        with self.assertRaisesRegex(ValueError, "positive"):
            self.verified_plan(package="broot")

        self.assertEqual(self.operations, [])

    def test_combined_invalid_signature_blocks_planner(self):
        self.fail_signature = True

        with self.assertRaises(subprocess.CalledProcessError):
            self.verified_plan()

        self.assertNotIn("metadata", self.operations)

    def test_pruning_cli_requires_protected(self):
        self.assert_cli_rejected(["--plan-pruning"])

    def test_publication_and_pruning_cli_are_exclusive(self):
        self.assert_cli_rejected([
            "--publish", "--plan-pruning",
            "--protected", FILE,
        ])

    def test_protected_without_pruning_rejected(self):
        self.assert_cli_rejected(["--protected", FILE])

    def assert_cli_rejected(self, flags):
        argv = [
            "publish-history.py",
            "--package", PACKAGE,
            "--fingerprint", self.fingerprint,
            *flags,
        ]

        with (
            patch.object(sys, "argv", argv),
            patch.object(publisher, "run") as command,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as result:
                publisher.main()

        self.assertEqual(result.exception.code, 2)
        command.assert_not_called()

    def test_pruning_cli_returns_verified_plan(self):
        argv = [
            "publish-history.py",
            "--package", PACKAGE,
            "--fingerprint", self.fingerprint,
            "--plan-pruning",
            "--protected", FILE,
        ]

        output = io.StringIO()

        with (
            patch.object(sys, "argv", argv),
            patch.object(
                publisher, "run", side_effect=self.fake_run
            ),
            patch.dict(os.environ, {
                "GH_REPO": "example/disposable",
            }),
            contextlib.redirect_stdout(output),
        ):
            publisher.main()

        plan = json.loads(output.getvalue())

        self.assertTrue(plan["dry_run"])
        self.assertEqual(plan["protected"], FILE)
        self.assertEqual(plan["prune"], [])
        self.assertIn("verified_metadata", plan)


if __name__ == "__main__":
    unittest.main()
