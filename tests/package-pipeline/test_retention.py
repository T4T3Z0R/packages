import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLANNER = ROOT / "scripts/package-pipeline/plan-retention.py"

GREETER = "noctalia-greeter-t4t3z0r"
OLD = GREETER + "-1.7.0-1-x86_64.pkg.tar.zst"
NEW = GREETER + "-1.7.0-2-x86_64.pkg.tar.zst"


class RetentionPlannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.inventory = Path(self.temp.name) / "inventory.json"

    def plan(self, names, package=GREETER, candidate=NEW):
        self.inventory.write_text(json.dumps(names))
        return subprocess.run(
            [
                "python3", str(PLANNER),
                "--inventory", str(self.inventory),
                "--package", package,
                "--candidate", candidate,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_greeter_update_requires_archive(self):
        result = self.plan([OLD, OLD + ".sig"])
        self.assertEqual(result.returncode, 0, result.stderr)

        plan = json.loads(result.stdout)
        self.assertEqual(plan["displaced"], OLD)
        self.assertEqual(plan["previous_versions_to_keep"], 3)
        self.assertTrue(plan["archive_required"])
        self.assertTrue(plan["dry_run"])

    def test_same_version_requires_no_archive(self):
        result = self.plan([OLD, OLD + ".sig"], candidate=OLD)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["archive_required"])

    def test_first_publication_requires_no_archive(self):
        result = self.plan([])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(json.loads(result.stdout)["displaced"])

    def test_missing_signature_rejected(self):
        result = self.plan([OLD])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("lacks signature", result.stderr)

    def test_duplicate_assets_rejected(self):
        result = self.plan([OLD, OLD])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Duplicate release assets", result.stderr)

    def test_multiple_active_versions_rejected(self):
        result = self.plan([OLD, OLD + ".sig", NEW, NEW + ".sig"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Multiple active versions", result.stderr)

    def test_similarly_named_package_is_not_displaced(self):
        other = (
            GREETER + "-extra-1.7.0-1-x86_64.pkg.tar.zst"
        )
        result = self.plan([other, other + ".sig"])

        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertIsNone(plan["current"])
        self.assertIsNone(plan["displaced"])
        self.assertFalse(plan["archive_required"])

    def test_unrelated_candidate_rejected(self):
        result = self.plan([], candidate="gameshell-1.0-1-any.pkg.tar.zst")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Candidate does not match", result.stderr)

    def test_debug_companion_retention(self):
        for package in (
            "keepassxc-debug",
            "syncthing-discosrv-debug",
            "syncthing-relaysrv-debug",
        ):
            with self.subTest(package=package):
                old = package + "-1.0-1-any.pkg.tar.zst"
                new = package + "-2.0-1-any.pkg.tar.zst"

                result = self.plan(
                    [old, old + ".sig"],
                    package=package,
                    candidate=new,
                )

                self.assertEqual(
                    result.returncode, 0, result.stderr
                )

                plan = json.loads(result.stdout)

                self.assertEqual(
                    plan["previous_versions_to_keep"], 3
                )
                self.assertEqual(
                    plan["history_release"],
                    "arch-history-" + package,
                )
                self.assertTrue(plan["archive_required"])

    def test_two_version_package_retention(self):
        for package in (
            "yazi", "yazi-debug", "broot", "broot-debug",
            "thunar", "thunar-debug",
        ):
            with self.subTest(package=package):
                old = package + "-1.0-1-any.pkg.tar.zst"
                new = package + "-2.0-1-any.pkg.tar.zst"

                result = self.plan(
                    [old, old + ".sig"],
                    package=package,
                    candidate=new,
                )

                self.assertEqual(
                    result.returncode, 0, result.stderr
                )

                plan = json.loads(result.stdout)

                self.assertEqual(
                    plan["previous_versions_to_keep"], 2
                )
                self.assertEqual(plan["displaced"], old)
                self.assertEqual(
                    plan["history_release"],
                    "arch-history-" + package,
                )
                self.assertTrue(plan["archive_required"])

    def test_no_retention_policy(self):
        candidate = "retention-test-unregistered-2.0-1-any.pkg.tar.zst"
        old = "retention-test-unregistered-1.0-1-any.pkg.tar.zst"
        result = self.plan(
            [old, old + ".sig"],
            package="retention-test-unregistered",
            candidate=candidate,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        plan = json.loads(result.stdout)
        self.assertEqual(plan["previous_versions_to_keep"], 0)
        self.assertFalse(plan["archive_required"])
        self.assertTrue(plan["delete_live_after_publication"])


class HistoryPruningTests(unittest.TestCase):
    def setUp(self):
        import runpy

        self.module = runpy.run_path(str(
            ROOT / "scripts/package-pipeline/"
            "plan-history-pruning.py"
        ))

        self.planner = self.module["plan_pruning"]

        self.versions = {
            self.filename(version): version + "-1"
            for version in ("2.6", "2.7", "2.8", "2.9", "2.10")
        }

        self.names = [
            asset
            for name in self.versions
            for asset in (name, name + ".sig")
        ]

    def filename(self, version):
        return (
            "ghostty-" + version + "-1-x86_64.pkg.tar.zst"
        )

    def numeric_compare(self, left, right):
        # Deliberately limited comparator for offline
        # fixtures. Native vercmp is tested separately.
        def key(value):
            return tuple(
                int(part)
                for part in value.replace("-", ".").split(".")
            )

        return (key(left) > key(right)) - (key(left) < key(right))

    def plan(self, **overrides):
        args = {
            "package": "ghostty",
            "names": self.names,
            "versions": self.versions,
            "protected": self.filename("2.7"),
            "retain": 3,
            "compare": self.numeric_compare,
        }

        args.update(overrides)
        return self.planner(**args)

    def test_pruning_preserves_protected_version(self):
        plan = self.plan()

        self.assertEqual(
            [pair["package"] for pair in plan["keep"]],
            [
                self.filename("2.10"),
                self.filename("2.9"),
                self.filename("2.7"),
            ],
        )

        self.assertEqual(
            [pair["package"] for pair in plan["prune"]],
            [
                self.filename("2.6"),
                self.filename("2.8"),
            ],
        )

        for pair in plan["prune"]:
            self.assertEqual(
                pair["signature"], pair["package"] + ".sig"
            )

        self.assertTrue(plan["dry_run"])

    def test_under_limit_prunes_nothing(self):
        plan = self.plan(retain=6)
        self.assertEqual(plan["prune"], [])
        self.assertEqual(len(plan["keep"]), 5)

    def test_exact_limit_prunes_nothing(self):
        self.assertEqual(self.plan(retain=5)["prune"], [])

    def test_single_slot_preserves_protected_version(self):
        plan = self.plan(retain=1)

        self.assertEqual(
            [pair["package"] for pair in plan["keep"]],
            [self.filename("2.7")],
        )

        self.assertEqual(len(plan["prune"]), 4)

    def test_missing_signature_rejected(self):
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.plan(names=self.names[:-1])

    def test_orphan_signature_rejected(self):
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.plan(names=self.names[1:])

    def test_duplicate_asset_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.plan(names=self.names + [self.names[0]])

    def test_unrelated_asset_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            self.plan(names=self.names + ["unrelated.txt"])

    def test_protected_version_missing_rejected(self):
        with self.assertRaisesRegex(ValueError, "Protected"):
            self.plan(protected=self.filename("9.0"))

    def test_zero_retention_rejected(self):
        with self.assertRaisesRegex(ValueError, "positive"):
            self.plan(retain=0)

    def test_missing_metadata_rejected(self):
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.plan(versions={})

    def test_conflicting_metadata_rejected(self):
        versions = dict(self.versions)
        versions[self.filename("2.10")] = "9.0-1"

        with self.assertRaisesRegex(ValueError, "disagrees"):
            self.plan(versions=versions)

    def test_ambiguous_versions_rejected(self):
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            self.plan(compare=lambda left, right: 0)

    def test_native_vercmp_ordering(self):
        import shutil

        if not shutil.which("vercmp"):
            self.skipTest("Native vercmp unavailable")

        compare = self.module["compare_versions"]

        self.assertGreater(compare("2.10-1", "2.9-1"), 0)
        self.assertGreater(compare("2.9-2", "2.9-1"), 0)
        self.assertGreater(compare("1:1.0-1", "9.0-1"), 0)

        plan = self.plan(compare=compare)
        self.assertEqual(
            plan["keep"][0]["package"],
            self.filename("2.10"),
        )

        versions = dict(self.versions)
        versions[self.filename("2.6")] = "1:2.6-1"

        plan = self.plan(compare=compare, versions=versions)

        self.assertEqual(
            plan["keep"][0]["package"],
            self.filename("2.6"),
        )


if __name__ == "__main__":
    unittest.main()
