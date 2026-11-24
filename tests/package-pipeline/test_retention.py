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

    def test_no_retention_policy(self):
        candidate = "broot-2.0-1-any.pkg.tar.zst"
        old = "broot-1.0-1-any.pkg.tar.zst"
        result = self.plan(
            [old, old + ".sig"],
            package="broot",
            candidate=candidate,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        plan = json.loads(result.stdout)
        self.assertEqual(plan["previous_versions_to_keep"], 0)
        self.assertFalse(plan["archive_required"])
        self.assertTrue(plan["delete_live_after_publication"])


if __name__ == "__main__":
    unittest.main()
