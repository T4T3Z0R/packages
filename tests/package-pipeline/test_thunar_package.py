"""Thunar package registration and lifecycle regression tests."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from fixed_recipe_selection import FIXED_PACKAGES
from merged_selection_validation import (
    THUNAR_BOOTSTRAP_BASE,
    THUNAR_BOOTSTRAP_CONFIG,
    changed_source,
)
from package_release_contract import CONTRACTS
from verify_source_contract import verify


class ThunarPackageTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )

        self.config = self.manifest["packages"]["thunar"]

    def bootstrap(self):
        before = copy.deepcopy(self.manifest)

        before["packages"] = {
            name: config
            for name, config in before["packages"].items()
            if name in THUNAR_BOOTSTRAP_BASE
        }

        after = copy.deepcopy(before)

        after["packages"]["thunar"] = dict(
            THUNAR_BOOTSTRAP_CONFIG
        )

        return before, after

    def test_current_source_contract(self):
        result = verify("thunar", self.config, ROOT)

        self.assertTrue(result["verified"])
        self.assertEqual(
            result["source_ref"], self.config["source_ref"]
        )

    def test_fixed_recipe_registration(self):
        self.assertIn("thunar", FIXED_PACKAGES)
        self.assertEqual(self.config["status"], "approved")
        self.assertIs(self.config["auto_publish"], False)

    def test_bootstrap_does_not_dispatch(self):
        before, after = self.bootstrap()

        self.assertEqual(len(before["packages"]), 10)
        self.assertEqual(len(after["packages"]), 11)

        self.assertIsNone(changed_source(before, after))

    def test_bootstrap_rejects_modified_registration(self):
        for field, value in (
            ("upstream", "other/thunar"),
            ("source_ref", "thunar-4.21.7"),
            ("release_policy", "stable-tag"),
            ("recipe", "arch/thunar/PKGBUILD.in"),
            ("license", "MIT"),
            ("status", "candidate"),
            ("auto_publish", True),
        ):
            with self.subTest(field=field):
                before, after = self.bootstrap()

                after["packages"]["thunar"][field] = value

                with self.assertRaises(ValueError):
                    changed_source(before, after)

    def test_bootstrap_rejects_unrelated_changes(self):
        for operation in ("change", "remove", "add"):
            with self.subTest(operation=operation):
                before, after = self.bootstrap()

                if operation == "change":
                    after["packages"]["broot"][
                        "source_ref"
                    ] = "v99.9.9"
                elif operation == "remove":
                    after["packages"].pop("broot")
                else:
                    after["packages"]["unexpected"] = dict(
                        THUNAR_BOOTSTRAP_CONFIG
                    )

                with self.assertRaises(ValueError):
                    changed_source(before, after)

    def test_future_source_change_recognized(self):
        before = copy.deepcopy(self.manifest)
        after = copy.deepcopy(before)

        candidate = "thunar-99.98.99"

        after["packages"]["thunar"]["source_ref"] = candidate

        result = changed_source(before, after)

        self.assertEqual(result[0], "thunar")
        self.assertEqual(result[2], candidate)

    def test_publisher_registration(self):
        spec = CONTRACTS["thunar"]

        self.assertEqual(spec.workflow, "publish-thunar.yml")
        self.assertEqual(spec.recipe_style, "fixed")

        workflow = (
            ROOT / ".github/workflows" / spec.workflow
        ).read_text()

        for marker in (
            "name: Build and validate unsigned Thunar",
            "makepkg --noconfirm --cleanbuild",
            "name: arch-repo-publish",
            "inputs.publish == true",
            "thunar-debug",
            "usr/bin/thunar",
            "usr/lib/libthunarx-3.so.0",
            "usr/lib/thunarx-3/thunar-uca.so",
            "usr/share/man/man1/Thunar.1.gz",
        ):
            self.assertIn(marker, workflow)

        for forbidden in (
            "--nocheck",
            "--skipinteg",
            "--skipchecksums",
            "--skippgpcheck",
            "gh release upload",
            "gh release delete-asset",
        ):
            self.assertNotIn(forbidden, workflow)

    def test_reconciliation_registration(self):
        workflow = (
            ROOT / ".github/workflows/"
            "reconcile-package-candidates.yml"
        ).read_text()

        self.assertIn("      - Publish Thunar\n", workflow)

    def test_retention_policy(self):
        policy = json.loads(
            (ROOT / "arch/packages/retention.json").read_text()
        )

        for package in ("thunar", "thunar-debug"):
            self.assertEqual(
                policy["previous_versions"][package], 2
            )

    def test_native_ci_registration(self):
        workflow = (
            ROOT / ".github/workflows/"
            "test-package-pipeline.yml"
        ).read_text()

        for marker in (
            "test_xfce_source.py",
            "test_thunar_package.py",
            "thunar_checksum(version)",
            "PASS: XFCE native version comparison",
            "scripts/package-pipeline/xfce_source.py",
        ):
            self.assertIn(marker, workflow)


if __name__ == "__main__":
    unittest.main()
