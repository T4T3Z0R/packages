import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from fixed_recipe_metadata import archive_url
from fixed_recipe_selection import render_recipe
from merged_selection_validation import (
    changed_source,
    BROOT_BOOTSTRAP_BASE,
    BROOT_BOOTSTRAP_CONFIG,
)
from package_release_contract import CONTRACTS
from verify_source_contract import verify


class BrootPackageTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )
        self.config = self.manifest["packages"]["broot"]
        self.recipe = (
            ROOT / self.config["recipe"]
        ).read_text()

    def test_current_source_contract(self):
        result = verify("broot", self.config, ROOT)
        self.assertTrue(result["verified"])
        self.assertEqual(
            result["source_ref"], self.config["source_ref"]
        )

    def test_archive_url(self):
        self.assertEqual(
            archive_url("broot", "99.9.9"),
            "https://github.com/Canop/broot/"
            "archive/v99.9.9/broot-v99.9.9.tar.gz",
        )

    def test_invalid_recipe_sources(self):
        checksum = next(
            line for line in self.recipe.splitlines()
            if line.startswith("sha256sums=")
        )

        cases = (
            self.recipe.replace(
                checksum, "sha256sums=('SKIP')"
            ),
            self.recipe + "\n" + checksum + "\n",
            self.recipe.replace(
                "github.com/Canop/", "example.com/"
            ),
            self.recipe + '\nsource=("https://example.com/file")\n',
            self.recipe.replace(
                "pkgname=broot\n", "pkgname=other\n"
            ),
        )

        for source in cases:
            with self.subTest(source=source[-100:]):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    path = root / self.config["recipe"]
                    path.parent.mkdir(parents=True)
                    path.write_text(source)

                    with self.assertRaises(ValueError):
                        verify("broot", self.config, root)

    def test_invalid_source_configuration(self):
        for field, value in (
            ("upstream", "other/broot"),
            ("release_policy", "stable-tag"),
            ("source_ref", "v99.9.9"),
            ("status", "candidate"),
        ):
            with self.subTest(field=field):
                config = dict(self.config)
                config[field] = value

                with self.assertRaises(ValueError):
                    verify("broot", config, ROOT)

    def test_future_source_selection(self):
        candidate = "v99.9.9"

        rendered = render_recipe(
            "broot",
            self.config,
            candidate,
            self.recipe,
            {
                "package": "broot",
                "candidate": candidate,
                "pkgver": "99.9.9",
                "sha256": "a" * 64,
            },
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
            path = root / config["recipe"]
            path.parent.mkdir(parents=True)
            path.write_text(rendered)

            self.assertTrue(
                verify("broot", config, root)["verified"]
            )

    def bootstrap(self):
        before = copy.deepcopy(self.manifest)

        before["packages"] = {
            name: config
            for name, config in before["packages"].items()
            if name in BROOT_BOOTSTRAP_BASE
        }

        after = copy.deepcopy(before)
        after["packages"]["broot"] = dict(
            BROOT_BOOTSTRAP_CONFIG
        )

        return before, after

    def test_bootstrap_does_not_dispatch(self):
        before, after = self.bootstrap()
        self.assertIsNone(changed_source(before, after))

    def test_bootstrap_rejects_modified_registration(self):
        for field, value in (
            ("upstream", "other/broot"),
            ("source_ref", "v99.9.9"),
            ("release_policy", "stable-tag"),
            ("recipe", "arch/broot/PKGBUILD.in"),
            ("status", "candidate"),
            ("auto_publish", True),
        ):
            with self.subTest(field=field):
                before, after = self.bootstrap()
                after["packages"]["broot"][field] = value

                with self.assertRaises(ValueError):
                    changed_source(before, after)

    def test_bootstrap_rejects_unrelated_changes(self):
        for operation in ("change", "remove", "add"):
            with self.subTest(operation=operation):
                before, after = self.bootstrap()

                if operation == "change":
                    after["packages"]["ghostty"][
                        "source_ref"
                    ] = "v99.9.9"
                elif operation == "remove":
                    after["packages"].pop("yazi")
                else:
                    after["packages"]["unexpected"] = dict(
                        BROOT_BOOTSTRAP_CONFIG
                    )

                with self.assertRaises(ValueError):
                    changed_source(before, after)

    def test_future_source_change_recognized(self):
        before = copy.deepcopy(self.manifest)
        after = copy.deepcopy(before)

        candidate = "v99.9.9"
        after["packages"]["broot"]["source_ref"] = candidate

        result = changed_source(before, after)

        self.assertEqual(result[0], "broot")
        self.assertEqual(result[2], candidate)

    def test_publisher_registration(self):
        spec = CONTRACTS["broot"]

        self.assertEqual(spec.workflow, "publish-broot.yml")
        self.assertEqual(spec.recipe_style, "fixed")

        workflow = (
            ROOT / ".github/workflows" / spec.workflow
        ).read_text()

        for marker in (
            "name: Build and validate unsigned Broot",
            "makepkg --noconfirm --cleanbuild",
            "name: arch-repo-publish",
            "inputs.publish == true",
            "broot-debug",
            "usr/bin/broot",
            "usr/share/man/man1/broot.1.gz",
            "usr/share/fonts/TTF/vscode.ttf",
        ):
            self.assertIn(marker, workflow)

        for forbidden in (
            "--nocheck",
            "--skipinteg",
            "--skippgpcheck",
            "gh release upload",
            "gh release delete-asset",
        ):
            self.assertNotIn(forbidden, workflow)

        reconcile = (
            ROOT / ".github/workflows/"
            "reconcile-package-candidates.yml"
        ).read_text()

        self.assertIn("      - Publish Broot\n", reconcile)

    def test_retention_policy(self):
        policy = json.loads(
            (ROOT / "arch/packages/retention.json").read_text()
        )

        for package in ("broot", "broot-debug"):
            self.assertEqual(
                policy["previous_versions"][package], 2
            )


if __name__ == "__main__":
    unittest.main()
