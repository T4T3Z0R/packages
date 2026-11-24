import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from package_release_contract import (
    CONTRACTS, SUPPORTED, TEMPLATE_PACKAGES,
    VALIDATION_JOBS, workflow_file,
)


class ReleaseContractTests(unittest.TestCase):
    def test_registry_matches_approved_manifest(self):
        manifest = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )
        approved = {
            name for name, config in manifest["packages"].items()
            if config["status"] == "approved"
        }
        self.assertEqual(approved, set(SUPPORTED))
        self.assertEqual(approved, set(CONTRACTS))
        self.assertEqual(approved, set(VALIDATION_JOBS))

    def test_registry_matches_workflows_and_recipes(self):
        manifest = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )
        for name, spec in CONTRACTS.items():
            with self.subTest(package=name):
                self.assertEqual(workflow_file(name), spec.workflow)
                workflow = (
                    ROOT / ".github/workflows" / spec.workflow
                ).read_text()
                self.assertIn(
                    f"name: {spec.validation_job}", workflow
                )
                self.assertIn(
                    f"PACKAGE_NAME: {name}", workflow
                )
                self.assertIn(
                    "name: arch-repo-publish", workflow
                )
                suffix = (
                    "PKGBUILD.in"
                    if name in TEMPLATE_PACKAGES
                    else "PKGBUILD"
                )
                self.assertEqual(
                    manifest["packages"][name]["recipe"],
                    f"arch/{name}/{suffix}",
                )

    def test_unknown_package_rejected(self):
        with self.assertRaises(ValueError):
            workflow_file("moonlight-qt")


if __name__ == "__main__":
    unittest.main()
