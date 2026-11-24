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
        self.replace_asset = False
        self.corrupt_content = False
        self.truncate_content = False

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

        if args[:2] == ("gh", "api"):
            import hashlib

            if args[2] == (
                "repos/example/disposable/releases/tags/"
                "arch-history-" + PACKAGE
            ):
                self.views += 1
                self.operations.append("view")

                return json.dumps({
                    "id": 100,
                    "tag_name": "arch-history-" + PACKAGE,
                    "draft": False,
                })

            self.assertEqual(args, (
                "gh", "api", "--paginate", "--slurp",
                "repos/example/disposable/releases/"
                "100/assets?per_page=100",
            ))

            assets = []

            if self.change_inventory and self.views > 1:
                return "[[]]"

            for index, (name, content) in enumerate(
                sorted(self.remote.items())
            ):
                asset_id = 200 + index

                if self.replace_asset and self.views > 1:
                    asset_id += 100

                assets.append({
                    "id": asset_id,
                    "name": name,
                    "size": len(content),
                    "digest": "sha256:" + hashlib.sha256(
                        content
                    ).hexdigest(),
                    "state": "uploaded",
                    "updated_at": "2026-11-20T22:23:07Z",
                })

            return json.dumps([assets])

        self.assertEqual(args[:2], ("gh", "release"))

        operation = args[2]
        self.operations.append(operation)

        if operation == "download":
            if self.fail_download:
                raise subprocess.CalledProcessError(1, args)

            name = args[args.index("--pattern") + 1]
            directory = Path(args[args.index("--dir") + 1])

            content = self.remote[name]

            if self.corrupt_content:
                content = bytes(
                    byte ^ 1 for byte in content
                )

            if self.truncate_content:
                content = content[:-1]

            (directory / name).write_bytes(content)
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

        with self.assertRaisesRegex(ValueError, "snapshot changed"):
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


    def test_collector_returns_stable_snapshot(self):
        result = self.collect()
        snapshot = result["snapshot"]

        self.assertEqual(snapshot["release_id"], 100)
        self.assertEqual(
            snapshot["repository"], "example/disposable"
        )

        self.assertEqual(
            set(snapshot["assets"]), set(self.remote)
        )

        for name, record in snapshot["assets"].items():
            self.assertEqual(
                record["sha256"], result["sha256"][name]
            )
            self.assertEqual(
                record["size"], len(self.remote[name])
            )

    def test_collector_rejects_same_name_replacement(self):
        self.replace_asset = True

        with self.assertRaisesRegex(
            ValueError, "snapshot changed"
        ):
            self.collect()

    def test_collector_rejects_same_size_corruption(self):
        self.corrupt_content = True

        with self.assertRaisesRegex(
            ValueError, "digest mismatch"
        ):
            self.collect()

        self.assertNotIn("verify", self.operations)
        self.assertNotIn("metadata", self.operations)

    def test_collector_rejects_truncated_download(self):
        self.truncate_content = True

        with self.assertRaisesRegex(
            ValueError, "size mismatch"
        ):
            self.collect()

        self.assertNotIn("verify", self.operations)
        self.assertNotIn("metadata", self.operations)

    def test_combined_plan_contains_stable_snapshot(self):
        plan = self.verified_plan()
        metadata = plan["verified_metadata"]

        self.assertEqual(
            metadata["snapshot"]["release_id"], 100
        )

        self.assertEqual(
            set(metadata["snapshot"]["assets"]),
            {FILE, SIGNATURE},
        )

        self.assertTrue(plan["dry_run"])
        self.assertEqual(plan["prune"], [])


class HistorySnapshotTests(unittest.TestCase):
    def setUp(self):
        import hashlib

        self.release = "arch-history-" + PACKAGE
        self.payload = b"fixture-package"

        self.document = {
            "id": 100,
            "tag_name": self.release,
            "draft": False,
        }

        self.asset = {
            "id": 200,
            "name": FILE,
            "size": len(self.payload),
            "digest": (
                "sha256:" +
                hashlib.sha256(self.payload).hexdigest()
            ),
            "state": "uploaded",
            "updated_at": "2026-11-20T22:23:07Z",
        }

        self.pages = [[self.asset]]
        self.operations = []

    def fake_run(self, *args):
        self.operations.append(args)

        if args == (
            "gh", "api",
            "repos/example/disposable/releases/tags/"
            + self.release,
        ):
            return json.dumps(self.document)

        if args == (
            "gh", "api", "--paginate", "--slurp",
            "repos/example/disposable/releases/"
            + str(self.document["id"])
            + "/assets?per_page=100",
        ):
            return json.dumps(self.pages)

        self.fail("Unexpected command: " + repr(args))

    def snapshot(self):
        with (
            patch.object(
                publisher, "run", side_effect=self.fake_run
            ),
            patch.dict(os.environ, {
                "GH_REPO": "example/disposable",
            }),
        ):
            return publisher.history_snapshot(self.release)

    def revalidate(self, expected):
        with (
            patch.object(
                publisher, "run", side_effect=self.fake_run
            ),
            patch.dict(os.environ, {
                "GH_REPO": "example/disposable",
            }),
        ):
            return publisher.require_unchanged_snapshot(expected)

    def test_snapshot_records_stable_identity(self):
        snapshot = self.snapshot()

        self.assertEqual(snapshot["release_id"], 100)
        self.assertEqual(
            snapshot["repository"], "example/disposable"
        )

        self.assertEqual(snapshot["assets"][FILE], {
            "id": 200,
            "size": len(self.payload),
            "sha256": self.asset["digest"][7:],
            "state": "uploaded",
            "updated_at": self.asset["updated_at"],
        })

        self.assertEqual(len(self.operations), 2)

    def test_empty_snapshot(self):
        self.pages = [[]]
        self.assertEqual(self.snapshot()["assets"], {})

    def test_paginated_snapshot(self):
        signature = dict(
            self.asset,
            id=201,
            name=SIGNATURE,
        )
        self.pages.append([signature])

        self.assertEqual(
            set(self.snapshot()["assets"]),
            {FILE, SIGNATURE},
        )

    def test_duplicate_name_rejected(self):
        self.pages.append([dict(self.asset, id=201)])

        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.snapshot()

    def test_duplicate_id_rejected(self):
        self.pages.append([
            dict(self.asset, name=SIGNATURE)
        ])

        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.snapshot()

    def test_invalid_release_identity_rejected(self):
        for field, value in (
            ("id", 0),
            ("id", True),
            ("tag_name", "arch-repo"),
            ("draft", True),
        ):
            with self.subTest(field=field, value=value):
                original = self.document[field]
                self.document[field] = value

                try:
                    with self.assertRaisesRegex(
                        ValueError, "release identity"
                    ):
                        self.snapshot()
                finally:
                    self.document[field] = original

    def test_invalid_asset_metadata_rejected(self):
        for field, value in (
            ("id", 0),
            ("id", True),
            ("size", 0),
            ("size", True),
            ("name", "../escape"),
            ("name", ".."),
            ("digest", None),
            ("digest", "sha256:invalid"),
            ("state", "starter"),
            ("updated_at", ""),
        ):
            with self.subTest(field=field, value=value):
                original = self.asset[field]
                self.asset[field] = value

                try:
                    with self.assertRaisesRegex(
                        ValueError, "asset metadata"
                    ):
                        self.snapshot()
                finally:
                    self.asset[field] = original

    def test_invalid_pagination_rejected(self):
        for pages in ([], {}, [None]):
            with self.subTest(pages=pages):
                self.pages = pages

                with self.assertRaises(ValueError):
                    self.snapshot()

    def test_unchanged_snapshot_accepted(self):
        expected = self.snapshot()
        self.assertEqual(
            self.revalidate(expected), expected
        )

    def test_same_name_replacement_rejected(self):
        expected = self.snapshot()
        self.asset["id"] = 201

        with self.assertRaisesRegex(ValueError, "snapshot changed"):
            self.revalidate(expected)

    def test_release_replacement_rejected(self):
        expected = self.snapshot()
        self.document["id"] = 101

        with self.assertRaisesRegex(ValueError, "snapshot changed"):
            self.revalidate(expected)

    def test_modified_asset_rejected(self):
        for field, value in (
            ("size", 999),
            ("digest", "sha256:" + "b" * 64),
            ("updated_at", "2026-11-21T00:00:00Z"),
        ):
            with self.subTest(field=field):
                expected = self.snapshot()
                original = self.asset[field]
                self.asset[field] = value

                try:
                    with self.assertRaisesRegex(
                        ValueError, "snapshot changed"
                    ):
                        self.revalidate(expected)
                finally:
                    self.asset[field] = original

    def test_removed_asset_rejected(self):
        expected = self.snapshot()
        self.pages = [[]]

        with self.assertRaisesRegex(ValueError, "snapshot changed"):
            self.revalidate(expected)

    def test_added_asset_rejected(self):
        expected = self.snapshot()

        self.pages.append([
            dict(self.asset, id=201, name=SIGNATURE)
        ])

        with self.assertRaisesRegex(ValueError, "snapshot changed"):
            self.revalidate(expected)

    def test_downloaded_content_verified(self):
        record = self.snapshot()["assets"][FILE]

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / FILE
            path.write_bytes(self.payload)

            self.assertEqual(
                publisher.verify_snapshot_asset(path, record),
                record["sha256"],
            )

    def test_downloaded_size_mismatch_rejected(self):
        record = self.snapshot()["assets"][FILE]

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / FILE
            path.write_bytes(b"wrong-size")

            with self.assertRaisesRegex(ValueError, "size mismatch"):
                publisher.verify_snapshot_asset(path, record)

    def test_same_size_corruption_rejected(self):
        record = self.snapshot()["assets"][FILE]

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / FILE
            path.write_bytes(b"x" * len(self.payload))

            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                publisher.verify_snapshot_asset(path, record)


if __name__ == "__main__":
    unittest.main()
