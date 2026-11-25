import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0, str(ROOT / "scripts/package-pipeline")
)

from fixed_recipe_metadata import archive_url
from fixed_recipe_selection import render_recipe
from merged_selection_validation import (
    changed_source,
    YAZI_BOOTSTRAP_ORIGINAL,
    YAZI_BOOTSTRAP_APPROVED,
)
from package_release_contract import CONTRACTS
from verify_source_contract import verify


class YaziPackageTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )
        self.config = self.manifest["packages"]["yazi"]
        self.recipe = (
            ROOT / self.config["recipe"]
        ).read_text()

    def test_current_source_contract(self):
        result = verify("yazi", self.config, ROOT)
        self.assertTrue(result["verified"])
        self.assertEqual(
            result["source_ref"], self.config["source_ref"]
        )

    def test_archive_url(self):
        self.assertEqual(
            archive_url("yazi", "99.9.9"),
            "https://github.com/sxyazi/yazi/archive/v99.9.9.tar.gz",
        )

    def test_reject_invalid_recipe_sources(self):
        checksum_line = next(
            line for line in self.recipe.splitlines()
            if line.startswith("sha256sums=")
        )

        invalid_recipes = (
            self.recipe.replace(
                checksum_line, "sha256sums=('SKIP')"
            ),
            self.recipe + "\n" + checksum_line + "\n",
            self.recipe.replace(
                "github.com/sxyazi/", "example.com/"
            ),
            self.recipe + '\nsource=("https://example.com/file")\n',
        )

        for source in invalid_recipes:
            with self.subTest(source=source[-100:]):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    recipe = root / self.config["recipe"]
                    recipe.parent.mkdir(parents=True)
                    recipe.write_text(source)

                    with self.assertRaises(ValueError):
                        verify("yazi", self.config, root)

    def test_reject_wrong_upstream(self):
        config = dict(self.config, upstream="other/yazi")
        with self.assertRaises(ValueError):
            verify("yazi", config, ROOT)

    def test_reject_unapproved_recipe(self):
        config = dict(self.config, status="candidate")
        with self.assertRaises(ValueError):
            verify("yazi", config, ROOT)

    def test_future_source_selection(self):
        candidate = "v99.9.9"

        metadata = {
            "package": "yazi",
            "candidate": candidate,
            "pkgver": "99.9.9",
            "sha256": "a" * 64,
        }

        rendered = render_recipe(
            "yazi", self.config, candidate,
            self.recipe, metadata,
            compare=lambda old, new: -1,
        )

        self.assertIn("pkgver=99.9.9\n", rendered)
        self.assertIn("pkgrel=1\n", rendered)
        self.assertIn(
            "sha256sums=('" + "a" * 64 + "')",
            rendered,
        )

        config = dict(self.config, source_ref=candidate)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recipe = root / config["recipe"]
            recipe.parent.mkdir(parents=True)
            recipe.write_text(rendered)

            self.assertTrue(
                verify("yazi", config, root)["verified"]
            )

    def bootstrap(self):
        before = copy.deepcopy(self.manifest)
        after = copy.deepcopy(self.manifest)

        before["packages"]["yazi"] = dict(
            YAZI_BOOTSTRAP_ORIGINAL
        )

        after["packages"]["yazi"] = dict(
            YAZI_BOOTSTRAP_APPROVED
        )

        return before, after

    def test_bootstrap_does_not_authorize_source_update(self):
        before, after = self.bootstrap()
        self.assertIsNone(changed_source(before, after))

    def test_bootstrap_rejects_modified_package(self):
        for field, value in (
            ("source_ref", "v99.9.9"),
            ("auto_publish", True),
            ("upstream", "other/yazi"),
            ("recipe", "arch/yazi/PKGBUILD.in"),
        ):
            with self.subTest(field=field):
                before, after = self.bootstrap()
                after["packages"]["yazi"][field] = value

                with self.assertRaises(ValueError):
                    changed_source(before, after)

    def test_bootstrap_rejects_unrelated_source_change(self):
        before, after = self.bootstrap()
        after["packages"]["ghostty"]["source_ref"] = (
            "v99.9.9"
        )

        with self.assertRaises(ValueError):
            changed_source(before, after)

    def test_future_source_change_recognized(self):
        before = copy.deepcopy(self.manifest)
        after = copy.deepcopy(before)

        candidate = "v99.9.9"
        after["packages"]["yazi"]["source_ref"] = candidate

        result = changed_source(before, after)

        self.assertEqual(result[0], "yazi")
        self.assertEqual(result[2], candidate)

    def test_publisher_registration(self):
        spec = CONTRACTS["yazi"]

        self.assertEqual(spec.workflow, "publish-yazi.yml")
        self.assertEqual(spec.recipe_style, "fixed")

        workflow = (
            ROOT / ".github/workflows" / spec.workflow
        ).read_text()

        self.assertIn(
            "name: Build and validate unsigned Yazi",
            workflow,
        )
        self.assertIn(
            "name: arch-repo-publish", workflow
        )
        self.assertIn("inputs.publish == true", workflow)
        self.assertIn("yazi-debug", workflow)

        reconcile = (
            ROOT / ".github/workflows/"
            "reconcile-package-candidates.yml"
        ).read_text()

        self.assertIn("      - Publish Yazi\n", reconcile)


if __name__ == "__main__":
    unittest.main()
