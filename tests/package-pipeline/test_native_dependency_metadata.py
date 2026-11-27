"""Regression coverage for native Arch dependency metadata."""

import subprocess
import sys
import unittest

from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0, str(ROOT / "scripts/package-pipeline")
)

from native_dependency_metadata import (
    extract_dependencies,
    check_dependencies,
    MissingDependencies,
    DependencyCheckError,
)


def metadata(*declarations):
    """Construct a minimal native-style SRCINFO fixture."""

    return "\n".join((
        "pkgbase = fixture",
        "\tpkgver = 1.0",
        "\tpkgrel = 1",
        "\tarch = x86_64",
        *("\t" + line for line in declarations),
        "",
        "pkgname = fixture",
        "",
    ))


class DependencyExtractionTests(unittest.TestCase):

    def test_runtime_and_build_dependencies(self):
        source = metadata(
            "depends = bash",
            "depends = glibc",
            "makedepends = meson",
            "makedepends = ninja",
        )

        self.assertEqual(
            extract_dependencies(source, "x86_64"),
            ["bash", "glibc", "meson", "ninja"],
        )

    def test_architecture_specific_dependencies(self):
        source = metadata(
            "depends = bash",
            "depends_x86_64 = libfoo",
            "depends_aarch64 = libbar",
            "makedepends_x86_64 = nasm",
            "makedepends_aarch64 = cross-tool",
        )

        self.assertEqual(
            extract_dependencies(source, "x86_64"),
            ["bash", "libfoo", "nasm"],
        )

    def test_other_architecture_dependencies(self):
        source = metadata(
            "depends = bash",
            "depends_x86_64 = libfoo",
            "depends_aarch64 = libbar",
        ).replace(
            "arch = x86_64",
            "arch = aarch64",
        )

        self.assertEqual(
            extract_dependencies(source, "aarch64"),
            ["bash", "libbar"],
        )

    def test_version_constraints_are_preserved(self):
        dependencies = [
            "libfoo>=2.0",
            "libbar=1:3.0-2",
            "libbaz<4",
            "libqux<=5.2",
            "libtest>1.0",
            "libexample.so=2-64",
        ]

        source = metadata(*(
            "depends = " + dependency
            for dependency in dependencies
        ))

        self.assertEqual(
            extract_dependencies(source, "x86_64"),
            dependencies,
        )

    def test_duplicate_dependencies_are_removed(self):
        source = metadata(
            "depends = bash",
            "depends = glibc",
            "makedepends = bash",
            "depends_x86_64 = glibc",
        )

        self.assertEqual(
            extract_dependencies(source, "x86_64"),
            ["bash", "glibc"],
        )

    def test_distinct_version_constraints_are_preserved(self):
        source = metadata(
            "depends = libfoo>=2",
            "depends = libfoo<4",
        )

        self.assertEqual(
            extract_dependencies(source, "x86_64"),
            ["libfoo>=2", "libfoo<4"],
        )

    def test_optional_dependencies_are_not_required(self):
        source = metadata(
            "depends = bash",
            "optdepends = example: optional feature",
            "provides = fixture-virtual",
            "conflicts = fixture-old",
            "replaces = fixture-old",
            "checkdepends = test-framework",
        )

        self.assertEqual(
            extract_dependencies(source, "x86_64"),
            ["bash"],
        )

    def test_split_package_dependencies(self):
        source = (
            "pkgbase = fixture\n"
            "\tpkgver = 1.0\n"
            "\tpkgrel = 1\n"
            "\tarch = x86_64\n"
            "\tmakedepends = meson\n"
            "\tdepends = glibc\n"
            "\n"
            "pkgname = fixture-main\n"
            "\tdepends = libfoo>=2\n"
            "\n"
            "pkgname = fixture-tools\n"
            "\tdepends_x86_64 = libbar\n"
        )

        self.assertEqual(
            extract_dependencies(source, "x86_64"),
            ["meson", "glibc", "libfoo>=2", "libbar"],
        )

    def test_valid_recipe_without_dependencies(self):
        self.assertEqual(
            extract_dependencies(metadata(), "x86_64"),
            [],
        )

    def test_architecture_independent_package(self):
        source = metadata(
            "depends = bash",
        ).replace(
            "arch = x86_64", "arch = any"
        )

        self.assertEqual(
            extract_dependencies(source, "x86_64"),
            ["bash"],
        )

    def test_reject_unsupported_target_architecture(self):
        with self.assertRaises(ValueError):
            extract_dependencies(
                metadata("depends = bash"),
                "aarch64",
            )

    def test_reject_malformed_dependencies(self):
        for value in (
            "",
            "--root",
            "--dbpath=/tmp/example",
            "-S",
            "core/bash",
            "bash another-package",
            "bash;false",
            "bash$(false)",
            "bash`false`",
            "bash|false",
            "bash&false",
            "bash\\other",
            "bash>= ",
            "bash==2",
            "bash><2",
            "bash=",
            "bash>=2/other",
            "bash\x00",
            "ｂash",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    extract_dependencies(
                        metadata("depends = " + value),
                        "x86_64",
                    )

    def test_reject_malformed_metadata_structure(self):
        for source in (
            "",
            "depends = bash\n",
            "pkgbase = fixture\n",
            "pkgname = fixture\n\tdepends = bash\n",
            metadata("depends bash"),
            metadata("depends = bash") + "unexpected shell\n",
            metadata("depends = bash").replace(
                "pkgbase = fixture\n",
                "pkgbase = fixture\npkgbase = other\n",
            ),
            metadata("depends = bash").replace(
                "pkgname = fixture\n",
                "pkgname = fixture\npkgname = fixture\n",
            ),
        ):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    extract_dependencies(source, "x86_64")


class DependencyCheckTests(unittest.TestCase):

    def set_result(self, run, status, stdout="", stderr=""):
        run.return_value = subprocess.CompletedProcess(
            args=["pacman", "-T"],
            returncode=status,
            stdout=stdout,
            stderr=stderr,
        )

    @patch("native_dependency_metadata.subprocess.run")
    def test_satisfied_dependencies(self, run):
        self.set_result(run, 0)

        self.assertIsNone(
            check_dependencies(["bash", "libfoo>=2"])
        )

        command = run.call_args.args[0]

        self.assertEqual(
            command,
            ["pacman", "-T", "--", "bash", "libfoo>=2"],
        )

        self.assertFalse(
            run.call_args.kwargs.get("shell", False)
        )

    @patch("native_dependency_metadata.subprocess.run")
    def test_no_dependencies_needs_no_pacman_call(self, run):
        self.assertIsNone(check_dependencies([]))
        run.assert_not_called()

    @patch("native_dependency_metadata.subprocess.run")
    def test_missing_dependencies(self, run):
        self.set_result(
            run, 127, "libfoo>=2\n"
        )

        with self.assertRaises(MissingDependencies):
            check_dependencies(["bash", "libfoo>=2"])

    @patch("native_dependency_metadata.subprocess.run")
    def test_unexpected_pacman_failure(self, run):
        self.set_result(
            run, 1, stderr="database error"
        )

        with self.assertRaises(DependencyCheckError):
            check_dependencies(["bash"])

    @patch("native_dependency_metadata.subprocess.run")
    def test_unexpected_failure_with_stdout(self, run):
        self.set_result(run, 1, "bash\n")

        with self.assertRaises(DependencyCheckError):
            check_dependencies(["bash"])

    @patch("native_dependency_metadata.subprocess.run")
    def test_missing_status_without_missing_output(self, run):
        self.set_result(run, 127)

        with self.assertRaises(DependencyCheckError):
            check_dependencies(["bash"])

    @patch("native_dependency_metadata.subprocess.run")
    def test_unexpected_success_output(self, run):
        self.set_result(run, 0, "bash\n")

        with self.assertRaises(DependencyCheckError):
            check_dependencies(["bash"])

    @patch("native_dependency_metadata.subprocess.run")
    def test_unrequested_dependency_output(self, run):
        self.set_result(run, 127, "unrelated-package\n")

        with self.assertRaises(DependencyCheckError):
            check_dependencies(["bash"])

    @patch("native_dependency_metadata.subprocess.run")
    def test_execution_failure(self, run):
        run.side_effect = OSError("cannot execute pacman")

        with self.assertRaises(DependencyCheckError):
            check_dependencies(["bash"])

    @patch("native_dependency_metadata.subprocess.run")
    def test_reject_unsafe_arguments_before_execution(self, run):
        with self.assertRaises(ValueError):
            check_dependencies(["--root"])

        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
