"""Behavioral tests for generated package recipe metadata."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0, str(ROOT / "scripts/package-pipeline")
)

from generated_recipe_metadata import (
    noctalia_version,
    gameshell_version,
    render_recipe,
)


SOURCE_SHA = "23080f658aa845feeda54cf72cb842700c8bad8e"
GAME_SHA = "63ae30982cf28ec7de1a4de23b85d15eccc031d8"

DIGEST = "a" * 64

INVALID_VERSIONS = (
    "",
    "1.2.3;false",
    "1.2.3$(false)",
    "1.2.3`false`",
    "1.2.3&",
    "1.2.3/other",
    "1.2.3\\other",
    "1.2.3\nOTHER=value",
    "1.2.3\r",
    "1.2.3 ",
    "1.2.3'",
    '1.2.3"',
    "1.2.3:4",
    "1.2.3-4",
    "１.2.3",
)


class VersionTests(unittest.TestCase):

    def test_production_noctalia_version(self):
        self.assertEqual(
            noctalia_version("v5.6.0", SOURCE_SHA),
            "5.6.0.custom.23080f65",
        )

    def test_production_gameshell_version(self):
        self.assertEqual(
            gameshell_version("v0.6.0", 40, GAME_SHA),
            "0.6.0.r40.g63ae30982cf2",
        )

    def test_noctalia_historical_tag_formats(self):
        for tag, expected in (
            ("v5.0.0-beta1", "5.0.0_beta1"),
            ("v5.0.0-beta.10", "5.0.0_beta.10"),
            ("v1.0.6-1", "1.0.6_1"),
            ("v1.0.2-1", "1.0.2_1"),
        ):
            with self.subTest(tag=tag):
                self.assertEqual(
                    noctalia_version(tag, SOURCE_SHA),
                    expected + ".custom.23080f65",
                )

    def test_greeter_supported_tag_formats(self):
        from generated_recipe_metadata import greeter_version

        for tag, expected in (
            ("v1.7.1", "1.7.1"),
            ("v1.8.0-alpha1", "1.8.0_alpha1"),
            ("v1.8.0-beta.2", "1.8.0_beta.2"),
            ("v1.8.0-rc.1", "1.8.0_rc.1"),
        ):
            with self.subTest(tag=tag):
                self.assertEqual(
                    greeter_version(tag), expected
                )

    def test_reject_unsupported_tag_suffixes(self):
        from generated_recipe_metadata import greeter_version

        for tag in (
            "v1.2.3-unknown",
            "v1.2.3-beta",
            "v1.2.3-beta.",
            "v1.2.3-beta1;false",
            "v1.2.3-rc.1$(false)",
            "v1.2.3-beta1\nOTHER=value",
            "v1.2.3-beta1/other",
        ):
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    noctalia_version(tag, SOURCE_SHA)

                with self.assertRaises(ValueError):
                    greeter_version(tag)

    def test_greeter_reject_unsafe_tags(self):
        from generated_recipe_metadata import greeter_version

        for version in INVALID_VERSIONS:
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    greeter_version("v" + version)

    def test_gameshell_preserves_git_abbreviation(self):
        for length in (12, 13, 16, 40):
            with self.subTest(length=length):
                short = GAME_SHA[:length]

                self.assertEqual(
                    gameshell_version(
                        "v0.6.0", 40, GAME_SHA,
                        abbreviation=short,
                    ),
                    "0.6.0.r40.g" + short,
                )

    def test_gameshell_rejects_invalid_abbreviation(self):
        for short in (
            "",
            GAME_SHA[:11],
            GAME_SHA + "a",
            "a" * 12,
            GAME_SHA[:12].upper(),
            GAME_SHA[:12] + "\n",
        ):
            with self.subTest(short=short):
                with self.assertRaises(ValueError):
                    gameshell_version(
                        "v0.6.0", 40, GAME_SHA,
                        abbreviation=short,
                    )

    def test_gameshell_exact_release(self):
        self.assertEqual(
            gameshell_version("v0.6.0", 0, GAME_SHA),
            "0.6.0",
        )

    def test_reject_unsafe_source_tags(self):
        for tag in INVALID_VERSIONS:
            with self.subTest(tag=tag):
                if tag != "1.2.3-4":
                    with self.assertRaises(ValueError):
                        noctalia_version(
                            "v" + tag, SOURCE_SHA
                        )

                with self.assertRaises(ValueError):
                    gameshell_version(
                        "v" + tag, 40, GAME_SHA
                    )

    def test_reject_invalid_commit_identity(self):
        for sha in (
            "",
            "a" * 39,
            "a" * 41,
            "g" * 40,
            "A" * 40,
            SOURCE_SHA + "\n",
        ):
            with self.subTest(sha=sha):
                with self.assertRaises(ValueError):
                    noctalia_version("v5.6.0", sha)

                with self.assertRaises(ValueError):
                    gameshell_version("v0.6.0", 40, sha)

    def test_reject_invalid_revision_distance(self):
        for distance in (-1, True, 1.5, "40", None):
            with self.subTest(distance=distance):
                with self.assertRaises(ValueError):
                    gameshell_version(
                        "v0.6.0", distance, GAME_SHA
                    )


class RenderingTests(unittest.TestCase):

    def template(self, package):
        return (
            ROOT / "arch" / package / "PKGBUILD.in"
        ).read_text()

    def assert_rendering_parity(
        self, package, values
    ):
        template = self.template(package)

        expected = template

        for key, value in values.items():
            expected = expected.replace(
                "@" + key + "@", value
            )

        self.assertEqual(
            render_recipe(package, template, values),
            expected,
        )

    def test_noctalia_rendering_parity(self):
        self.assert_rendering_parity(
            "noctalia-custom",
            {
                "PKGVER": "5.6.0.custom.23080f65",
                "SOURCE_SHA256": DIGEST,
            },
        )

    def test_greeter_rendering_parity(self):
        self.assert_rendering_parity(
            "noctalia-greeter-t4t3z0r",
            {
                "PKGVER": "1.7.1",
                "SOURCE_SHA256": DIGEST,
            },
        )

    def test_gameshell_rendering_parity(self):
        self.assert_rendering_parity(
            "gameshell",
            {
                "PKGVER": "0.6.0.r40.g63ae30982cf2",
                "SOURCE_SHA": GAME_SHA,
                "ARCHIVE_SHA256": DIGEST,
                "LAUNCHER_SHA256": DIGEST,
                "SOURCE_SHA256": DIGEST,
                "LICENSE_SHA256": DIGEST,
                "README_SHA256": DIGEST,
            },
        )

    def test_reject_unsafe_package_versions(self):
        package = "noctalia-custom"
        template = self.template(package)

        for version in INVALID_VERSIONS:
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    render_recipe(
                        package,
                        template,
                        {
                            "PKGVER": version,
                            "SOURCE_SHA256": DIGEST,
                        },
                    )

    def test_reject_invalid_checksums(self):
        package = "noctalia-custom"
        template = self.template(package)

        for digest in (
            "",
            "a" * 63,
            "a" * 65,
            "g" * 64,
            "A" * 64,
            DIGEST + "\n",
        ):
            with self.subTest(digest=digest):
                with self.assertRaises(ValueError):
                    render_recipe(
                        package,
                        template,
                        {
                            "PKGVER": "5.6.0.custom.23080f65",
                            "SOURCE_SHA256": digest,
                        },
                    )

    def test_reject_missing_or_extra_values(self):
        package = "noctalia-custom"
        template = self.template(package)

        for values in (
            {"PKGVER": "5.6.0"},
            {
                "PKGVER": "5.6.0",
                "SOURCE_SHA256": DIGEST,
                "UNEXPECTED": "value",
            },
        ):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    render_recipe(
                        package, template, values
                    )

    def test_reject_changed_placeholder_layout(self):
        package = "noctalia-custom"
        template = self.template(package)

        values = {
            "PKGVER": "5.6.0.custom.23080f65",
            "SOURCE_SHA256": DIGEST,
        }

        for modified in (
            template.replace("@PKGVER@", ""),
            template + "\n@PKGVER@\n",
            template + "\n@UNKNOWN@\n",
        ):
            with self.subTest(template=modified):
                with self.assertRaises(ValueError):
                    render_recipe(
                        package, modified, values
                    )

    def test_reject_unknown_package(self):
        with self.assertRaises(ValueError):
            render_recipe("unknown", "", {})



class CommandLineTests(unittest.TestCase):

    def invoke(self, *args):
        import subprocess

        return subprocess.run(
            [
                sys.executable,
                str(
                    ROOT / "scripts/package-pipeline"
                    / "generated_recipe_metadata.py"
                ),
                *args,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_cli_noctalia_version(self):
        result = self.invoke(
            "noctalia-version",
            "--tag", "v5.6.0",
            "--source-sha", SOURCE_SHA,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "5.6.0.custom.23080f65\n",
        )

    def test_cli_greeter_version(self):
        result = self.invoke(
            "greeter-version",
            "--tag", "v1.7.1",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1.7.1\n")

    def test_cli_gameshell_version(self):
        result = self.invoke(
            "gameshell-version",
            "--tag", "v0.6.0",
            "--source-sha", GAME_SHA,
            "--distance", "40",
            "--abbreviation", GAME_SHA[:13],
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "0.6.0.r40.g" + GAME_SHA[:13] + "\n",
        )

    def test_cli_validate_commit(self):
        result = self.invoke(
            "validate-commit",
            "--sha", SOURCE_SHA,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, SOURCE_SHA + "\n")

    def test_cli_validate_gameshell_base_tag(self):
        result = self.invoke(
            "gameshell-base-tag",
            "--tag", "v0.6.0",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "v0.6.0\n")

    def test_cli_rejects_invalid_metadata(self):
        cases = (
            (
                "noctalia-version",
                "--tag", "v5.6.0$(false)",
                "--source-sha", SOURCE_SHA,
            ),
            (
                "greeter-version",
                "--tag", "v1.7.1\nOTHER=value",
            ),
            (
                "validate-commit",
                "--sha", SOURCE_SHA + "\n",
            ),
            (
                "gameshell-base-tag",
                "--tag", "v0.6.0;false",
            ),
            (
                "gameshell-version",
                "--tag", "v0.6.0",
                "--source-sha", GAME_SHA,
                "--distance", "-1",
                "--abbreviation", GAME_SHA[:12],
            ),
            (
                "gameshell-version",
                "--tag", "v0.6.0",
                "--source-sha", GAME_SHA,
                "--distance", "40",
                "--abbreviation", "a" * 12,
            ),
        )

        for args in cases:
            with self.subTest(args=args):
                result = self.invoke(*args)

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertTrue(result.stderr)

    def test_cli_rendering_parity(self):
        package = "noctalia-custom"

        values = {
            "PKGVER": "5.6.0.custom.23080f65",
            "SOURCE_SHA256": DIGEST,
        }

        template = (
            ROOT / "arch" / package / "PKGBUILD.in"
        ).read_text()

        result = self.invoke(
            "render",
            "--package", package,
            "--value", "PKGVER=" + values["PKGVER"],
            "--value", "SOURCE_SHA256=" + DIGEST,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            render_recipe(package, template, values),
        )

    def test_cli_rejects_duplicate_render_values(self):
        result = self.invoke(
            "render",
            "--package", "noctalia-custom",
            "--value", "PKGVER=5.6.0",
            "--value", "PKGVER=5.7.0",
            "--value", "SOURCE_SHA256=" + DIGEST,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_cli_rejects_invalid_render_values(self):
        result = self.invoke(
            "render",
            "--package", "noctalia-custom",
            "--value", "PKGVER=5.6.0$(false)",
            "--value", "SOURCE_SHA256=" + DIGEST,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
