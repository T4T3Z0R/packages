"""Offline tests for fixed-recipe source metadata."""

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(
    0, str(ROOT / "scripts/package-pipeline")
)

import fixed_recipe_metadata as metadata

MANIFEST = json.loads(
    (ROOT / "arch/packages/manifest.json").read_text()
)["packages"]


class MetadataTests(unittest.TestCase):

    def test_wezterm_version_matches_recipe(self):
        candidate = "89e01990a" + "b" * 31

        with patch.object(
            metadata, "run",
            side_effect=[
                "", "", "", candidate,
                "20240203-110809-5046fc22-999-g89e01990a",
            ],
        ) as run:
            version = metadata.wezterm_version(candidate)

        self.assertEqual(
            version,
            "20240203.110809.5046fc22.r999.g89e01990a",
        )

        self.assertEqual(run.call_count, 5)

    def test_wezterm_wrong_commit_rejected(self):
        with patch.object(
            metadata, "run",
            side_effect=["", "", "", "b" * 40],
        ):
            with self.assertRaisesRegex(
                ValueError, "commit mismatch"
            ):
                metadata.wezterm_version("a" * 40)

    def test_wezterm_wrong_description_rejected(self):
        with patch.object(
            metadata, "run",
            side_effect=[
                "", "", "", "a" * 40,
                "20240203-110809-5046fc22-999-gbbbbbbbbb",
            ],
        ):
            with self.assertRaisesRegex(
                ValueError, "commit mismatch"
            ):
                metadata.wezterm_version("a" * 40)

    def test_archive_urls_match_production_recipes(self):
        self.assertEqual(
            metadata.archive_url("ghostty", "9.9.9"),
            "https://github.com/ghostty-org/ghostty"
            "/archive/v9.9.9/ghostty-9.9.9.tar.gz",
        )

        self.assertEqual(
            metadata.archive_url("syncthing", "9.9.9"),
            "https://github.com/syncthing/syncthing"
            "/releases/download/v9.9.9/"
            "syncthing-source-v9.9.9.tar.gz",
        )

    def test_archive_checksum_hashes_downloaded_bytes(self):
        import hashlib

        payload = bytes([31, 139]) + b"fixture archive"

        def download(args, **kwargs):
            target = Path(
                args[args.index("--output") + 1]
            )
            target.write_bytes(payload)
            return ""

        with patch.object(
            metadata, "run", side_effect=download
        ):
            result = metadata.archive_checksum(
                "ghostty", "9.9.9"
            )

        self.assertEqual(
            result,
            hashlib.sha256(payload).hexdigest(),
        )

    def test_moonlight_archive_url(self):
        self.assertEqual(
            metadata.archive_url("moonlight-qt", "9.9.9"),
            "https://github.com/moonlight-stream/moonlight-qt"
            "/releases/download/v9.9.9/MoonlightSrc-9.9.9.tar.gz",
        )

    def test_moonlight_archive_sha512(self):
        import hashlib

        payload = bytes([31, 139]) + b"fixture archive"

        def download(args, **kwargs):
            target = Path(args[args.index("--output") + 1])
            target.write_bytes(payload)
            return ""

        with patch.object(metadata, "run", side_effect=download):
            result = metadata.archive_checksum(
                "moonlight-qt", "9.9.9"
            )

        self.assertEqual(result, hashlib.sha512(payload).hexdigest())

    def test_moonlight_metadata_resolution(self):
        with patch.object(
            metadata, "archive_checksum", return_value="a" * 128
        ) as archive:
            result = metadata.resolve(
                "moonlight-qt",
                "v9.9.9",
                MANIFEST["moonlight-qt"],
            )

        archive.assert_called_once_with("moonlight-qt", "9.9.9")
        self.assertEqual(result, {
            "package": "moonlight-qt",
            "candidate": "v9.9.9",
            "pkgver": "9.9.9",
            "sha512": "a" * 128,
        })

    def test_moonlight_sha256_metadata_rejected(self):
        with patch.object(
            metadata, "archive_checksum", return_value="a" * 64
        ):
            with self.assertRaises(ValueError):
                metadata.resolve(
                    "moonlight-qt",
                    "v9.9.9",
                    MANIFEST["moonlight-qt"],
                )

    def test_invalid_archive_rejected(self):
        def download(args, **kwargs):
            target = Path(
                args[args.index("--output") + 1]
            )
            target.write_bytes(b"not a gzip archive")
            return ""

        with patch.object(
            metadata, "run", side_effect=download
        ):
            with self.assertRaisesRegex(
                ValueError, "archive format"
            ):
                metadata.archive_checksum(
                    "syncthing", "9.9.9"
                )

    def test_native_checksum_output(self):
        digest = "a" * 64

        self.assertEqual(
            metadata.parse_native_checksum(
                "sha256sums=('" + digest + "')"
            ),
            digest,
        )

    def test_invalid_native_checksum_output(self):
        for output in (
            "",
            "sha256sums=('SKIP')",
            "sha256sums=('bad')",
            "sha256sums=('"
            + "a" * 64 + "')\n"
            "sha256sums=('"
            + "b" * 64 + "')",
        ):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    metadata.parse_native_checksum(output)

    def test_native_checksum_recipe_is_source_only(self):
        def generate(args, *, cwd=None):
            self.assertEqual(
                args,
                [
                    "makepkg", "--geninteg",
                    "--noconfirm",
                ],
            )

            recipe = (cwd / "PKGBUILD").read_text()

            self.assertIn(
                "#tag=${pkgver}?signed", recipe
            )

            self.assertIn("pkgver=9.9.9", recipe)

            for forbidden in (
                "prepare()", "build()",
                "check()", "package()",
            ):
                self.assertNotIn(forbidden, recipe)

            return "sha256sums=('" + "a" * 64 + "')"

        with (
            patch.object(
                metadata.os, "geteuid",
                return_value=1000,
            ),
            patch.object(
                metadata, "run",
                side_effect=generate,
            ),
        ):
            result = metadata.keepassxc_checksum(
                "9.9.9"
            )

        self.assertEqual(result, "a" * 64)

    def test_native_checksum_refuses_root(self):
        with patch.object(
            metadata.os, "geteuid",
            return_value=0,
        ):
            with self.assertRaisesRegex(
                ValueError, "unprivileged"
            ):
                metadata.keepassxc_checksum("9.9.9")

    def test_stable_package_resolution(self):
        for package, candidate in (
            ("ghostty", "v9.9.9"),
            ("syncthing", "v9.9.9"),
            ("keepassxc", "9.9.9"),
        ):
            with self.subTest(package=package):
                with (
                    patch.object(
                        metadata, "archive_checksum",
                        return_value="a" * 64,
                    ) as archive,
                    patch.object(
                        metadata, "keepassxc_checksum",
                        return_value="b" * 64,
                    ) as git,
                ):
                    result = metadata.resolve(
                        package,
                        candidate,
                        MANIFEST[package],
                    )

                self.assertEqual(
                    result["pkgver"], "9.9.9"
                )

                if package == "keepassxc":
                    git.assert_called_once_with(
                        "9.9.9"
                    )
                    archive.assert_not_called()
                else:
                    archive.assert_called_once_with(
                        package, "9.9.9"
                    )
                    git.assert_not_called()

    def test_wrong_upstream_rejected_before_network(self):
        config = copy.deepcopy(MANIFEST["ghostty"])
        config["upstream"] = "other/ghostty"

        with patch.object(metadata, "run") as run:
            with self.assertRaises(ValueError):
                metadata.resolve(
                    "ghostty", "v9.9.9", config
                )

            run.assert_not_called()

    def test_wrong_tag_format_rejected(self):
        with patch.object(
            metadata, "archive_checksum"
        ) as archive:
            with self.assertRaises(ValueError):
                metadata.resolve(
                    "ghostty",
                    "9.9.9",
                    MANIFEST["ghostty"],
                )

            archive.assert_not_called()


if __name__ == "__main__":
    unittest.main()
