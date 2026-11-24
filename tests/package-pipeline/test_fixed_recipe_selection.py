"""Fixed recipe source-selection regression tests."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(
    0, str(ROOT / "scripts/package-pipeline")
)

from fixed_recipe_selection import render_recipe
from verify_source_contract import assignment

MANIFEST = json.loads(
    (ROOT / "arch/packages/manifest.json").read_text()
)["packages"]


class FixedRecipeTests(unittest.TestCase):

    def fixture(self, package):
        config = copy.deepcopy(MANIFEST[package])
        source = (ROOT / config["recipe"]).read_text()

        if package == "wezterm":
            candidate = "a" * 40
            metadata = {
                "package": package,
                "candidate": candidate,
                "pkgver": (
                    "20240203.110809.5046fc22"
                    ".r999.gaaaaaaaaa"
                ),
            }
        else:
            candidate = (
                "9.9.9" if package == "keepassxc"
                else "v9.9.9"
            )
            metadata = {
                "package": package,
                "candidate": candidate,
                "pkgver": "9.9.9",
                "sha256": "b" * 64,
            }

        return package, config, candidate, source, metadata

    def render(self, *args, **kwargs):
        kwargs.setdefault(
            "compare", lambda old, new: -1
        )
        return render_recipe(*args, **kwargs)

    def test_all_fixed_recipes(self):
        for package in (
            "ghostty", "keepassxc",
            "syncthing", "wezterm",
        ):
            with self.subTest(package=package):
                args = self.fixture(package)
                source, metadata = args[3:]

                result = self.render(*args)

                self.assertEqual(
                    assignment(result, "pkgver"),
                    metadata["pkgver"],
                )

                self.assertEqual(
                    assignment(result, "pkgrel"), "1"
                )

                # Reconstruct the original recipe by reversing
                # only explicitly authorized substitutions.
                restored = result.replace(
                    "pkgver=" + metadata["pkgver"],
                    "pkgver=" + assignment(
                        source, "pkgver"
                    ),
                    1,
                )

                restored = restored.replace(
                    "pkgrel=1",
                    "pkgrel=" + assignment(
                        source, "pkgrel"
                    ),
                    1,
                )

                if package == "wezterm":
                    restored = restored.replace(
                        "_commit=" + args[2],
                        "_commit=" + assignment(
                            source, "_commit"
                        ),
                        1,
                    )
                else:
                    import re

                    original = re.search(
                        r"^sha256sums=\('([0-9a-f]{64})'",
                        source,
                        re.MULTILINE,
                    ).group(1)

                    restored = restored.replace(
                        metadata["sha256"], original, 1
                    )

                self.assertEqual(restored, source)

    def test_invalid_checksum_rejected(self):
        args = self.fixture("ghostty")
        args[4]["sha256"] = "SKIP"

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_missing_checksum_rejected(self):
        args = self.fixture("syncthing")
        del args[4]["sha256"]

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_stale_metadata_rejected(self):
        args = self.fixture("ghostty")
        args[4]["candidate"] = "v8.8.8"

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_wrong_upstream_rejected(self):
        args = self.fixture("wezterm")
        args[1]["upstream"] = "other/wezterm"

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_wrong_recipe_rejected(self):
        args = self.fixture("ghostty")
        args[1]["recipe"] = "arch/wezterm/PKGBUILD"

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_automatic_publication_rejected(self):
        args = self.fixture("ghostty")
        args[1]["auto_publish"] = True

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_wrong_stable_version_rejected(self):
        args = self.fixture("keepassxc")
        args[4]["pkgver"] = "8.8.8"

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_wrong_wezterm_commit_suffix_rejected(self):
        args = self.fixture("wezterm")
        args[4]["pkgver"] = "20240203.r999.gbbbbbbbbb"

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_wezterm_stale_recipe_rejected(self):
        args = list(self.fixture("wezterm"))

        args[3] = args[3].replace(
            "_commit=" + args[1]["source_ref"],
            "_commit=" + ("c" * 40),
            1,
        )

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_nonincreasing_version_rejected(self):
        for comparison in (0, 1):
            with self.subTest(comparison=comparison):
                with self.assertRaises(ValueError):
                    self.render(
                        *self.fixture("wezterm"),
                        compare=lambda a, b: comparison,
                    )

    def test_duplicate_assignment_rejected(self):
        args = list(self.fixture("ghostty"))
        args[3] += "\npkgver=8.8.8\n"

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_duplicate_checksum_rejected(self):
        args = list(self.fixture("ghostty"))
        args[3] += (
            "\nsha256sums=('"
            + "c" * 64 + "')\n"
        )

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_unexpected_metadata_rejected(self):
        args = self.fixture("wezterm")
        args[4]["sha256"] = "b" * 64

        with self.assertRaises(ValueError):
            self.render(*args)

    def test_pinned_policy_rejected(self):
        args = self.fixture("ghostty")
        args[1]["release_policy"] = "pinned-tag"

        with self.assertRaises(ValueError):
            self.render(*args)


if __name__ == "__main__":
    unittest.main()
