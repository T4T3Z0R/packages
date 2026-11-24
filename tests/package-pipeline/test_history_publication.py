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

    def test_apply_pruning_requires_protected(self):
        self.assert_cli_rejected(["--apply-pruning"])

    def test_apply_and_plan_pruning_are_exclusive(self):
        self.assert_cli_rejected([
            "--apply-pruning", "--plan-pruning",
            "--protected", FILE,
        ])

    def test_apply_and_publish_are_exclusive(self):
        self.assert_cli_rejected([
            "--apply-pruning", "--publish",
            "--protected", FILE,
        ])

    def test_apply_pruning_requires_remote_environment(self):
        argv = [
            "publish-history.py",
            "--package", PACKAGE,
            "--fingerprint", self.fingerprint,
            "--apply-pruning",
            "--protected", FILE,
        ]

        for environment in (
            {},
            {"GH_TOKEN": "fixture-token"},
            {"GH_REPO": "example/disposable"},
        ):
            with self.subTest(environment=environment):
                with (
                    patch.object(sys, "argv", argv),
                    patch.dict(os.environ, environment, clear=True),
                    patch.object(
                        publisher, "prune_verified_history"
                    ) as execute,
                    patch.object(publisher, "run") as command,
                ):
                    with self.assertRaisesRegex(
                        ValueError, "GH_TOKEN and GH_REPO"
                    ):
                        publisher.main()

                execute.assert_not_called()
                command.assert_not_called()

    def test_apply_pruning_cli_invokes_orchestrator(self):
        argv = [
            "publish-history.py",
            "--package", PACKAGE,
            "--fingerprint", self.fingerprint,
            "--apply-pruning",
            "--protected", FILE,
        ]

        expected = {
            "state": "complete",
            "deleted": 2,
            "recovered": False,
        }

        output = io.StringIO()

        with (
            patch.object(sys, "argv", argv),
            patch.dict(os.environ, {
                "GH_TOKEN": "fixture-token",
                "GH_REPO": "example/disposable",
            }),
            patch.object(
                publisher, "prune_verified_history",
                return_value=expected,
            ) as execute,
            patch.object(publisher, "run") as command,
            contextlib.redirect_stdout(output),
        ):
            publisher.main()

        execute.assert_called_once_with(
            PACKAGE, self.fingerprint, FILE
        )
        command.assert_not_called()
        self.assertEqual(
            json.loads(output.getvalue()), expected
        )

    def test_apply_pruning_failure_propagates(self):
        argv = [
            "publish-history.py",
            "--package", PACKAGE,
            "--fingerprint", self.fingerprint,
            "--apply-pruning",
            "--protected", FILE,
        ]

        output = io.StringIO()

        with (
            patch.object(sys, "argv", argv),
            patch.dict(os.environ, {
                "GH_TOKEN": "fixture-token",
                "GH_REPO": "example/disposable",
            }),
            patch.object(
                publisher, "prune_verified_history",
                side_effect=ValueError("pruning failed"),
            ),
            contextlib.redirect_stdout(output),
        ):
            with self.assertRaisesRegex(
                ValueError, "pruning failed"
            ):
                publisher.main()

        self.assertEqual(output.getvalue(), "")


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


class PruningTransactionTests(unittest.TestCase):
    def setUp(self):
        import copy

        self.copy = copy.deepcopy
        self.protected = FILE
        self.old = PACKAGE + "-1.6.0-1-x86_64.pkg.tar.zst"
        self.older = PACKAGE + "-1.5.0-1-x86_64.pkg.tar.zst"

        names = [
            name
            for package in (
                self.protected, self.old, self.older
            )
            for name in (package, package + ".sig")
        ]

        assets = {
            name: {
                "id": 200 + index,
                "size": 100,
                "sha256": "a" * 64,
                "state": "uploaded",
                "updated_at": "2026-11-20T22:23:07Z",
            }
            for index, name in enumerate(names)
        }

        release = "arch-history-" + PACKAGE

        self.snapshot = {
            "repository": "example/disposable",
            "release": release,
            "release_id": 100,
            "assets": assets,
        }

        self.plan = {
            "package": PACKAGE,
            "history_release": release,
            "protected": self.protected,
            "previous_versions_to_keep": 1,
            "dry_run": True,
            "keep": [self.pair(self.protected)],
            "prune": [
                self.pair(self.older), self.pair(self.old)
            ],
            "verified_metadata": {
                "package": PACKAGE,
                "release": release,
                "snapshot": self.snapshot,
                "names": names,
                "versions": {
                    self.protected: "1.7.0-1",
                    self.old: "1.6.0-1",
                    self.older: "1.5.0-1",
                },
                "sha256": {
                    name: record["sha256"]
                    for name, record in assets.items()
                },
            },
        }

    def pair(self, name):
        return {
            "package": name,
            "signature": name + ".sig",
        }

    def journal(self):
        return publisher.prepare_pruning_transaction(
            self.plan
        )

    def fixture_vercmp(self, args, **kwargs):
        self.assertEqual(args[0], "vercmp")

        def key(version):
            return tuple(
                int(part)
                for part in version.replace("-", ".").split(".")
            )

        left, right = map(key, args[1:])
        result = (left > right) - (left < right)

        return subprocess.CompletedProcess(
            args, 0, stdout=str(result), stderr=""
        )

    def state(self, journal=None, actual=None):
        with patch.object(
            subprocess, "run", side_effect=self.fixture_vercmp
        ):
            return publisher.pruning_transaction_state(
                self.journal() if journal is None else journal,
                self.snapshot if actual is None else actual,
            )

    def test_prepared_transaction(self):
        journal = self.journal()

        self.assertEqual(self.state(journal)["state"], "prepared")
        self.assertEqual(
            [target["name"] for target in journal["delete"]],
            [
                self.older, self.older + ".sig",
                self.old, self.old + ".sig",
            ],
        )

        self.assertEqual(
            self.state(journal)["remaining"],
            journal["delete"],
        )

    def test_every_interruption_boundary(self):
        journal = self.journal()

        for count in range(1, 5):
            with self.subTest(count=count):
                actual = self.copy(self.snapshot)

                for target in journal["delete"][:count]:
                    del actual["assets"][target["name"]]

                result = self.state(journal, actual)

                self.assertEqual(result["completed"], count)
                self.assertEqual(
                    result["remaining"],
                    journal["delete"][count:],
                )
                self.assertEqual(
                    result["state"],
                    "complete" if count == 4 else "interrupted",
                )

    def test_retained_asset_missing_rejected(self):
        actual = self.copy(self.snapshot)
        del actual["assets"][self.protected]

        with self.assertRaisesRegex(ValueError, "Retained"):
            self.state(actual=actual)

    def test_out_of_sequence_deletion_rejected(self):
        actual = self.copy(self.snapshot)
        del actual["assets"][self.older + ".sig"]

        with self.assertRaisesRegex(ValueError, "sequence"):
            self.state(actual=actual)

    def test_asset_replacement_rejected(self):
        actual = self.copy(self.snapshot)
        actual["assets"][self.old]["id"] = 999

        with self.assertRaisesRegex(ValueError, "asset change"):
            self.state(actual=actual)

    def test_asset_addition_rejected(self):
        actual = self.copy(self.snapshot)
        actual["assets"]["unexpected"] = {}

        with self.assertRaisesRegex(ValueError, "asset change"):
            self.state(actual=actual)

    def test_release_replacement_rejected(self):
        actual = self.copy(self.snapshot)
        actual["release_id"] = 999

        with self.assertRaisesRegex(ValueError, "identity changed"):
            self.state(actual=actual)

    def test_tampered_target_id_rejected(self):
        journal = self.journal()
        journal["delete"][0]["id"] = 999

        with self.assertRaisesRegex(ValueError, "asset identity"):
            self.state(journal)

    def test_overlapping_partition_rejected(self):
        self.plan["prune"].append(self.pair(self.protected))

        with self.assertRaisesRegex(ValueError, "partition"):
            self.journal()

    def test_protected_pair_cannot_be_pruned(self):
        self.plan["keep"] = [self.pair(self.old)]
        self.plan["prune"] = [
            self.pair(self.protected), self.pair(self.older)
        ]

        with self.assertRaisesRegex(ValueError, "Protected"):
            self.journal()

    def test_invalid_retention_count_rejected(self):
        self.plan["previous_versions_to_keep"] = 2

        with self.assertRaisesRegex(ValueError, "pair count"):
            self.journal()

    def test_inconsistent_verified_hash_rejected(self):
        self.plan["verified_metadata"]["sha256"][FILE] = "bad"

        with self.assertRaisesRegex(ValueError, "Inconsistent"):
            self.journal()

    def test_journal_snapshot_is_independent(self):
        journal = self.journal()
        self.snapshot["assets"][FILE]["id"] = 999

        self.assertNotEqual(
            journal["snapshot"]["assets"][FILE]["id"],
            999,
        )

    def test_empty_deletion_sequence_is_complete(self):
        self.plan["keep"].extend(
            reversed(self.plan["prune"])
        )
        self.plan["prune"] = []
        self.plan["previous_versions_to_keep"] = 3

        journal = self.journal()
        self.assertEqual(self.state(journal)["state"], "complete")
        self.assertEqual(self.state(journal)["remaining"], [])


    def test_recovery_invalid_retention_count_rejected(self):
        journal = self.journal()
        journal["retain"] = 2

        with self.assertRaisesRegex(ValueError, "pair count"):
            self.state(journal)

    def test_recovery_invalid_pair_order_rejected(self):
        journal = self.journal()
        journal["delete"].reverse()

        with self.assertRaisesRegex(ValueError, "pair ordering"):
            self.state(journal)

    def test_recovery_wrong_package_rejected(self):
        journal = self.journal()
        journal["package"] = "wrong-package"

        with self.assertRaisesRegex(ValueError, "package identity"):
            self.state(journal)

    def test_recovery_duplicate_original_id_rejected(self):
        journal = self.journal()
        assets = journal["snapshot"]["assets"]
        assets[SIGNATURE]["id"] = assets[FILE]["id"]

        with self.assertRaisesRegex(ValueError, "asset identities"):
            self.state(journal)

    def test_recovery_incomplete_retained_pair_rejected(self):
        journal = self.journal()

        journal["keep"][1], journal["delete"][1]["name"] = (
            journal["delete"][1]["name"],
            journal["keep"][1],
        )

        with self.assertRaisesRegex(ValueError, "partition"):
            self.state(journal)


    def test_journal_preserves_verified_versions(self):
        journal = self.journal()

        self.assertEqual(
            journal["versions"],
            self.plan["verified_metadata"]["versions"],
        )

        self.plan["verified_metadata"]["versions"][FILE] = "bad"

        self.assertEqual(
            journal["versions"][FILE], "1.7.0-1"
        )

    def test_recovery_wrong_retained_version_rejected(self):
        self.plan["previous_versions_to_keep"] = 2
        self.plan["keep"] = [
            self.pair(self.protected), self.pair(self.older)
        ]
        self.plan["prune"] = [self.pair(self.old)]

        with self.assertRaisesRegex(
            ValueError, "retention decision mismatch"
        ):
            self.state()

    def test_recovery_wrong_deletion_order_rejected(self):
        journal = self.journal()
        targets = journal["delete"]

        journal["delete"] = targets[2:] + targets[:2]

        with self.assertRaisesRegex(
            ValueError, "retention decision mismatch"
        ):
            self.state(journal)

    def test_recovery_missing_version_metadata_rejected(self):
        journal = self.journal()
        del journal["versions"][self.old]

        with self.assertRaisesRegex(ValueError, "inventory"):
            self.state(journal)

    def test_recovery_conflicting_version_metadata_rejected(self):
        journal = self.journal()
        journal["versions"][self.old] = "9.0-1"

        with self.assertRaisesRegex(ValueError, "disagrees"):
            self.state(journal)

    def test_recovery_version_comparison_failure_blocks(self):
        journal = self.journal()

        with patch.object(
            subprocess,
            "run",
            side_effect=subprocess.CalledProcessError(
                1, ["vercmp"]
            ),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                publisher.pruning_transaction_state(
                    journal, self.snapshot
                )


    def test_journal_canonical_round_trip(self):
        journal = self.journal()

        payload = publisher.encode_pruning_journal(journal)

        self.assertEqual(
            publisher.decode_pruning_journal(payload),
            journal,
        )

    def test_journal_encoding_is_deterministic(self):
        journal = self.journal()
        reordered = dict(reversed(list(journal.items())))

        self.assertEqual(
            publisher.encode_pruning_journal(journal),
            publisher.encode_pruning_journal(reordered),
        )

    def test_journal_duplicate_fields_rejected(self):
        payload = b'{"package":"one","package":"two"}'

        with self.assertRaisesRegex(ValueError, "Duplicate"):
            publisher.decode_pruning_journal(payload)

    def test_journal_noncanonical_content_rejected(self):
        payload = json.dumps(
            self.journal(), indent=2
        ).encode("ascii")

        with self.assertRaisesRegex(ValueError, "Noncanonical"):
            publisher.decode_pruning_journal(payload)

    def test_journal_missing_field_rejected(self):
        journal = self.journal()
        del journal["versions"]

        with self.assertRaisesRegex(ValueError, "journal fields"):
            publisher.decode_pruning_journal(
                publisher.encode_pruning_journal(journal)
            )

    def test_journal_extra_field_rejected(self):
        journal = self.journal()
        journal["unexpected"] = True

        with self.assertRaisesRegex(ValueError, "journal fields"):
            publisher.decode_pruning_journal(
                publisher.encode_pruning_journal(journal)
            )

    def test_journal_invalid_schema_rejected(self):
        for version in (0, 2, True):
            with self.subTest(version=version):
                journal = self.journal()
                journal["schema_version"] = version

                with self.assertRaisesRegex(
                    ValueError, "Unsupported"
                ):
                    publisher.decode_pruning_journal(
                        publisher.encode_pruning_journal(journal)
                    )


    def journal_remote(self, journal):
        import hashlib

        payload = publisher.encode_pruning_journal(journal)
        remote = self.copy(self.snapshot)

        remote["assets"][publisher.JOURNAL_NAME] = {
            "id": 999,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "state": "uploaded",
            "updated_at": "2026-11-23T22:00:00Z",
        }

        return remote, payload

    def test_missing_remote_journal_returns_none(self):
        with patch.object(
            publisher, "history_snapshot",
            return_value=self.snapshot,
        ):
            self.assertIsNone(
                publisher.load_pruning_journal(
                    self.snapshot["release"]
                )
            )

    def test_remote_journal_loads_verified_state(self):
        journal = self.journal()
        remote, payload = self.journal_remote(journal)

        def fetch(release, name, directory):
            path = directory / name
            path.write_bytes(payload)
            return path

        with (
            patch.object(
                publisher, "history_snapshot",
                return_value=remote,
            ),
            patch.object(
                publisher, "download", side_effect=fetch
            ),
            patch.object(
                subprocess, "run",
                side_effect=self.fixture_vercmp,
            ),
        ):
            result = publisher.load_pruning_journal(
                remote["release"]
            )

        self.assertEqual(result["journal"], journal)
        self.assertEqual(result["state"]["state"], "prepared")
        self.assertEqual(result["journal_asset"]["id"], 999)

    def test_remote_journal_recovers_interrupted_pair(self):
        journal = self.journal()
        remote, payload = self.journal_remote(journal)

        del remote["assets"][journal["delete"][0]["name"]]

        def fetch(release, name, directory):
            path = directory / name
            path.write_bytes(payload)
            return path

        with (
            patch.object(
                publisher, "history_snapshot",
                return_value=remote,
            ),
            patch.object(
                publisher, "download", side_effect=fetch
            ),
            patch.object(
                subprocess, "run",
                side_effect=self.fixture_vercmp,
            ),
        ):
            result = publisher.load_pruning_journal(
                remote["release"]
            )

        self.assertEqual(
            result["state"]["state"], "interrupted"
        )
        self.assertEqual(result["state"]["completed"], 1)

    def test_corrupted_remote_journal_rejected(self):
        journal = self.journal()
        remote, payload = self.journal_remote(journal)

        def fetch(release, name, directory):
            path = directory / name
            path.write_bytes(b"x" * len(payload))
            return path

        with (
            patch.object(
                publisher, "history_snapshot",
                return_value=remote,
            ),
            patch.object(
                publisher, "download", side_effect=fetch
            ),
        ):
            with self.assertRaisesRegex(
                ValueError, "digest mismatch"
            ):
                publisher.load_pruning_journal(
                    remote["release"]
                )

    def test_remote_journal_persisted_without_clobber(self):
        journal = self.journal()
        remote, payload = self.journal_remote(journal)

        def upload(*args):
            self.assertEqual(
                args[:4],
                ("gh", "release", "upload", remote["release"]),
            )
            self.assertNotIn("--clobber", args)
            self.assertEqual(Path(args[4]).read_bytes(), payload)
            return ""

        def fetch(release, name, directory):
            path = directory / name
            path.write_bytes(payload)
            return path

        with (
            patch.object(
                publisher, "history_snapshot",
                side_effect=[self.snapshot, remote, remote],
            ),
            patch.object(
                publisher, "run", side_effect=upload
            ) as command,
            patch.object(
                publisher, "download", side_effect=fetch
            ),
            patch.object(
                subprocess, "run",
                side_effect=self.fixture_vercmp,
            ),
        ):
            result = publisher.persist_pruning_journal(journal)

        command.assert_called_once()
        self.assertEqual(result["journal"], journal)
        self.assertEqual(result["state"]["state"], "prepared")

    def test_existing_remote_journal_blocks_upload(self):
        journal = self.journal()
        remote, payload = self.journal_remote(journal)

        with (
            patch.object(
                publisher, "history_snapshot",
                return_value=remote,
            ),
            patch.object(publisher, "run") as command,
        ):
            with self.assertRaisesRegex(
                ValueError, "snapshot changed"
            ):
                publisher.persist_pruning_journal(journal)

        command.assert_not_called()

    def test_failed_journal_upload_blocks_transaction(self):
        journal = self.journal()

        with (
            patch.object(
                publisher, "history_snapshot",
                return_value=self.snapshot,
            ),
            patch.object(
                publisher, "run",
                side_effect=subprocess.CalledProcessError(
                    1, ["gh", "release", "upload"]
                ),
            ),
            patch.object(
                publisher, "load_pruning_journal"
            ) as load,
            patch.object(
                subprocess, "run",
                side_effect=self.fixture_vercmp,
            ),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                publisher.persist_pruning_journal(journal)

        load.assert_not_called()

    def test_missing_journal_after_upload_blocks(self):
        journal = self.journal()

        with (
            patch.object(
                publisher, "history_snapshot",
                return_value=self.snapshot,
            ),
            patch.object(publisher, "run", return_value=""),
            patch.object(
                publisher, "load_pruning_journal",
                return_value=None,
            ),
            patch.object(
                subprocess, "run",
                side_effect=self.fixture_vercmp,
            ),
        ):
            with self.assertRaisesRegex(
                ValueError, "journal missing"
            ):
                publisher.persist_pruning_journal(journal)


    def execute_remote(
        self,
        journal,
        completed=0,
        fail_at=None,
        apply_before_failure=False,
        no_progress=False,
        policy=None,
        replace_journal=False,
        remove_retained=False,
    ):
        remote, payload = self.journal_remote(journal)

        for target in journal["delete"][:completed]:
            del remote["assets"][target["name"]]

        operations = []
        self.execution_remote = remote
        self.execution_operations = operations

        def snapshot(release):
            self.assertEqual(release, remote["release"])
            return self.copy(remote)

        def fetch(release, name, directory):
            path = directory / name
            path.write_bytes(payload)
            return path

        def command(*args):
            self.assertEqual(
                args[:4],
                ("gh", "api", "--method", "DELETE"),
            )

            asset_id = int(args[4].rsplit("/", 1)[1])

            self.assertEqual(
                args[4],
                "repos/example/disposable/releases/assets/"
                + str(asset_id),
            )

            names = [
                name for name, record
                in remote["assets"].items()
                if record["id"] == asset_id
            ]

            self.assertEqual(len(names), 1)

            name = names[0]
            operations.append(name)

            failing = fail_at == len(operations)

            if failing and not apply_before_failure:
                raise subprocess.CalledProcessError(1, args)

            if not no_progress:
                del remote["assets"][name]

            if replace_journal and len(operations) == 1:
                remote["assets"][publisher.JOURNAL_NAME]["id"] = 998

            if remove_retained and len(operations) == 1:
                del remote["assets"][FILE]

            if failing:
                raise subprocess.CalledProcessError(1, args)

            return ""

        with (
            patch.object(
                publisher, "history_snapshot",
                side_effect=snapshot,
            ),
            patch.object(
                publisher, "download", side_effect=fetch
            ),
            patch.object(
                publisher, "run", side_effect=command
            ),
            patch.object(
                publisher, "current_retention_count",
                return_value=(
                    journal["retain"] if policy is None
                    else policy
                ),
            ),
            patch.object(
                subprocess, "run",
                side_effect=self.fixture_vercmp,
            ),
        ):
            return publisher.execute_pruning_transaction(
                remote["release"]
            )

    def test_executor_deletes_only_authorized_assets(self):
        journal = self.journal()
        result = self.execute_remote(journal)

        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["deleted"], 4)

        self.assertEqual(
            self.execution_operations,
            [
                target["name"]
                for target in journal["delete"]
            ] + [publisher.JOURNAL_NAME],
        )

        self.assertEqual(
            set(self.execution_remote["assets"]),
            set(journal["keep"]),
        )

    def test_executor_resumes_every_interruption_boundary(self):
        journal = self.journal()

        for count in range(5):
            with self.subTest(count=count):
                result = self.execute_remote(
                    journal, completed=count
                )

                self.assertEqual(result["state"], "complete")
                self.assertEqual(result["deleted"], 4 - count)

                self.assertEqual(
                    self.execution_operations,
                    [
                        target["name"]
                        for target in journal["delete"][count:]
                    ] + [publisher.JOURNAL_NAME],
                )

    def test_executor_failed_delete_preserves_journal(self):
        journal = self.journal()

        with self.assertRaises(subprocess.CalledProcessError):
            self.execute_remote(journal, fail_at=2)

        assets = self.execution_remote["assets"]

        self.assertIn(publisher.JOURNAL_NAME, assets)
        self.assertNotIn(journal["delete"][0]["name"], assets)
        self.assertIn(journal["delete"][1]["name"], assets)

    def test_executor_lost_response_preserves_recovery(self):
        journal = self.journal()

        with self.assertRaises(subprocess.CalledProcessError):
            self.execute_remote(
                journal,
                fail_at=1,
                apply_before_failure=True,
            )

        assets = self.execution_remote["assets"]

        self.assertIn(publisher.JOURNAL_NAME, assets)
        self.assertNotIn(journal["delete"][0]["name"], assets)

        result = self.execute_remote(journal, completed=1)
        self.assertEqual(result["deleted"], 3)

    def test_executor_no_progress_blocks(self):
        with self.assertRaisesRegex(ValueError, "deletion progress"):
            self.execute_remote(
                self.journal(), no_progress=True
            )

        self.assertEqual(len(self.execution_operations), 1)

        self.assertIn(
            publisher.JOURNAL_NAME,
            self.execution_remote["assets"],
        )

    def test_executor_changed_policy_blocks(self):
        with self.assertRaisesRegex(ValueError, "policy changed"):
            self.execute_remote(self.journal(), policy=2)

        self.assertEqual(self.execution_operations, [])

    def test_executor_replaced_journal_blocks(self):
        with self.assertRaisesRegex(ValueError, "journal changed"):
            self.execute_remote(
                self.journal(), replace_journal=True
            )

        self.assertEqual(len(self.execution_operations), 1)

    def test_executor_missing_retained_asset_blocks(self):
        with self.assertRaisesRegex(ValueError, "Retained"):
            self.execute_remote(
                self.journal(), remove_retained=True
            )

        self.assertEqual(len(self.execution_operations), 1)

    def test_executor_failed_journal_cleanup_is_recoverable(self):
        journal = self.journal()

        with self.assertRaises(subprocess.CalledProcessError):
            self.execute_remote(journal, fail_at=5)

        self.assertEqual(
            set(self.execution_remote["assets"]),
            set(journal["keep"]) | {publisher.JOURNAL_NAME},
        )

        result = self.execute_remote(journal, completed=4)

        self.assertEqual(result["deleted"], 0)
        self.assertEqual(
            self.execution_operations,
            [publisher.JOURNAL_NAME],
        )

    def test_executor_without_journal_is_noop(self):
        with (
            patch.object(
                publisher, "history_snapshot",
                return_value=self.snapshot,
            ),
            patch.object(publisher, "run") as command,
        ):
            result = publisher.execute_pruning_transaction(
                self.snapshot["release"]
            )

        self.assertEqual(result["state"], "no_transaction")
        self.assertEqual(result["deleted"], 0)
        command.assert_not_called()


    def orchestrate(
        self,
        existing=None,
        planner_error=None,
        persistence_error=None,
        execution_state="complete",
        policy=None,
    ):
        from contextlib import ExitStack

        journal = self.journal()
        calls = []
        self.orchestration_calls = calls

        def load(release):
            self.assertEqual(release, self.snapshot["release"])
            calls.append("load")
            return existing

        def plan(package, fingerprint, protected):
            self.assertEqual(package, PACKAGE)
            self.assertEqual(protected, FILE)
            calls.append("plan")

            if planner_error is not None:
                raise planner_error

            return self.plan

        def persist(candidate):
            calls.append("persist")
            self.assertEqual(candidate, journal)

            if persistence_error is not None:
                raise persistence_error

            return {
                "journal": journal,
                "state": {"state": "prepared"},
            }

        def execute(release, expected=None):
            self.assertEqual(release, self.snapshot["release"])

            self.assertEqual(
                expected,
                existing if existing is not None else {
                    "journal": journal,
                    "state": {"state": "prepared"},
                },
            )

            calls.append("execute")

            return {
                "state": execution_state,
                "deleted": len(journal["delete"]),
            }

        def unchanged(snapshot):
            self.assertEqual(snapshot, journal["snapshot"])
            calls.append("verify")
            return snapshot

        with ExitStack() as stack:
            for name, callback in (
                ("load_pruning_journal", load),
                ("plan_verified_history", plan),
                ("persist_pruning_journal", persist),
                ("execute_pruning_transaction", execute),
                ("require_unchanged_snapshot", unchanged),
            ):
                stack.enter_context(
                    patch.object(
                        publisher, name, side_effect=callback
                    )
                )

            stack.enter_context(
                patch.object(
                    publisher,
                    "current_retention_count",
                    return_value=(
                        journal["retain"] if policy is None
                        else policy
                    ),
                )
            )

            stack.enter_context(
                patch.object(
                    subprocess, "run",
                    side_effect=self.fixture_vercmp,
                )
            )

            return publisher.prune_verified_history(
                PACKAGE, "A" * 40, FILE
            )

    def test_orchestration_persists_before_execution(self):
        result = self.orchestrate()

        self.assertEqual(result["state"], "complete")
        self.assertFalse(result["recovered"])

        self.assertEqual(
            self.orchestration_calls,
            ["load", "plan", "persist", "execute"],
        )

    def test_orchestration_recovery_never_replans(self):
        result = self.orchestrate(existing={"journal": self.journal()})

        self.assertTrue(result["recovered"])

        self.assertEqual(
            self.orchestration_calls,
            ["load", "execute"],
        )

    def test_orchestration_within_limit_is_read_only(self):
        self.plan["keep"].extend(
            reversed(self.plan["prune"])
        )
        self.plan["prune"] = []
        self.plan["previous_versions_to_keep"] = 3

        result = self.orchestrate()

        self.assertEqual(result["state"], "within_limit")
        self.assertEqual(result["deleted"], 0)

        self.assertEqual(
            self.orchestration_calls,
            ["load", "plan", "verify"],
        )

    def test_orchestration_planner_failure_blocks(self):
        with self.assertRaisesRegex(ValueError, "verification"):
            self.orchestrate(
                planner_error=ValueError("verification failed")
            )

        self.assertEqual(
            self.orchestration_calls,
            ["load", "plan"],
        )

    def test_orchestration_persistence_failure_blocks(self):
        with self.assertRaisesRegex(ValueError, "persistence"):
            self.orchestrate(
                persistence_error=ValueError("persistence failed")
            )

        self.assertEqual(
            self.orchestration_calls,
            ["load", "plan", "persist"],
        )

    def test_orchestration_policy_change_blocks_persistence(self):
        with self.assertRaisesRegex(ValueError, "policy changed"):
            self.orchestrate(policy=2)

        self.assertEqual(
            self.orchestration_calls,
            ["load", "plan"],
        )

    def test_orchestration_missing_transaction_blocks_success(self):
        with self.assertRaisesRegex(
            ValueError, "New transaction not completed"
        ):
            self.orchestrate(
                execution_state="no_transaction"
            )

    def test_orchestration_incomplete_recovery_blocks_success(self):
        with self.assertRaisesRegex(
            ValueError, "Existing transaction not completed"
        ):
            self.orchestrate(
                existing={"journal": self.journal()},
                execution_state="no_transaction",
            )

        self.assertEqual(
            self.orchestration_calls,
            ["load", "execute"],
        )


    def test_executor_initial_journal_replacement_blocks(self):
        journal = self.journal()

        authorized = {
            "journal": journal,
            "journal_asset": {"id": 999},
            "state": self.state(journal),
        }

        replacement = self.copy(authorized)
        replacement["journal_asset"]["id"] = 998

        with (
            patch.object(
                publisher, "load_pruning_journal",
                return_value=replacement,
            ),
            patch.object(publisher, "run") as command,
        ):
            with self.assertRaisesRegex(
                ValueError, "Authorized pruning journal changed"
            ):
                publisher.execute_pruning_transaction(
                    self.snapshot["release"],
                    expected=authorized,
                )

        command.assert_not_called()

    def test_executor_initial_progress_change_blocks(self):
        journal = self.journal()

        authorized = {
            "journal": journal,
            "journal_asset": {"id": 999},
            "state": self.state(journal),
        }

        actual = self.copy(self.snapshot)
        del actual["assets"][journal["delete"][0]["name"]]

        changed = self.copy(authorized)
        changed["state"] = self.state(journal, actual)

        with (
            patch.object(
                publisher, "load_pruning_journal",
                return_value=changed,
            ),
            patch.object(publisher, "run") as command,
        ):
            with self.assertRaisesRegex(
                ValueError, "Authorized pruning journal changed"
            ):
                publisher.execute_pruning_transaction(
                    self.snapshot["release"],
                    expected=authorized,
                )

        command.assert_not_called()

    def test_executor_initial_journal_disappearance_blocks(self):
        authorized = {
            "journal": self.journal(),
            "journal_asset": {"id": 999},
            "state": {"state": "prepared"},
        }

        with (
            patch.object(
                publisher, "load_pruning_journal",
                return_value=None,
            ),
            patch.object(publisher, "run") as command,
        ):
            with self.assertRaisesRegex(
                ValueError, "Authorized pruning journal changed"
            ):
                publisher.execute_pruning_transaction(
                    self.snapshot["release"],
                    expected=authorized,
                )

        command.assert_not_called()


    def recover_archive(
        self,
        pending=True,
        missing=False,
        result="complete",
        journal_remains=False,
        failure=None,
    ):
        release = self.snapshot["release"]
        journal = self.journal()
        names = set(journal["keep"])

        initial = names.copy()

        if pending:
            initial.add(publisher.JOURNAL_NAME)

        final = initial.copy() if journal_remains else names

        authorization = {
            "journal": journal,
            "journal_asset": {"id": 999},
            "state": {"state": "interrupted"},
        }

        calls = []
        self.archive_recovery_calls = calls

        def inventory(tag):
            self.assertEqual(tag, release)
            calls.append("inventory")
            return initial if calls.count("inventory") == 1 else final

        def load(tag):
            self.assertEqual(tag, release)
            calls.append("load")
            return None if missing else authorization

        def execute(tag, expected=None):
            self.assertEqual(tag, release)
            self.assertEqual(expected, authorization)
            calls.append("execute")

            if failure is not None:
                raise failure

            return {"state": result}

        with (
            patch.object(
                publisher, "inventory", side_effect=inventory
            ),
            patch.object(
                publisher, "load_pruning_journal",
                side_effect=load,
            ),
            patch.object(
                publisher, "execute_pruning_transaction",
                side_effect=execute,
            ),
        ):
            return publisher.recover_before_archive(release)

    def test_archive_without_journal_preserves_normal_path(self):
        result = self.recover_archive(pending=False)

        self.assertEqual(result, set(self.journal()["keep"]))
        self.assertEqual(
            self.archive_recovery_calls,
            ["inventory"],
        )

    def test_archive_recovers_pending_transaction(self):
        result = self.recover_archive()

        self.assertEqual(result, set(self.journal()["keep"]))
        self.assertEqual(
            self.archive_recovery_calls,
            ["inventory", "load", "execute", "inventory"],
        )

    def test_archive_missing_pending_journal_blocks(self):
        with self.assertRaisesRegex(ValueError, "disappeared"):
            self.recover_archive(missing=True)

        self.assertEqual(
            self.archive_recovery_calls,
            ["inventory", "load"],
        )

    def test_archive_incomplete_recovery_blocks(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.recover_archive(result="no_transaction")

        self.assertEqual(
            self.archive_recovery_calls,
            ["inventory", "load", "execute"],
        )

    def test_archive_remaining_journal_blocks(self):
        with self.assertRaisesRegex(ValueError, "journal remains"):
            self.recover_archive(journal_remains=True)

    def test_archive_recovery_failure_blocks(self):
        with self.assertRaisesRegex(ValueError, "recovery failed"):
            self.recover_archive(
                failure=ValueError("recovery failed")
            )

        self.assertEqual(
            self.archive_recovery_calls,
            ["inventory", "load", "execute"],
        )


if __name__ == "__main__":
    unittest.main()
