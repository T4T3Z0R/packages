"""Validate native SRCINFO dependency data without evaluating shell."""

import argparse
import re
import subprocess
import sys

from pathlib import Path


PACKAGE_NAME = re.compile(
    r"[A-Za-z0-9_+][A-Za-z0-9_+.-]*",
    re.ASCII,
)

ARCHITECTURE = re.compile(
    r"[A-Za-z0-9_]+",
    re.ASCII,
)

FIELD = re.compile(
    r"[a-z][a-z0-9_]*",
    re.ASCII,
)

DEPENDENCY = re.compile(
    r"[A-Za-z0-9_+][A-Za-z0-9_+.-]*"
    r"(?:(?:>=|<=|=|>|<)"
    r"(?:[0-9]+:)?"
    r"[A-Za-z0-9_+.~]+"
    r"(?:-[0-9]+(?:[.][0-9]+)?)?"
    r")?",
    re.ASCII,
)

DEPENDENCY_FIELD = re.compile(
    r"(?:depends|makedepends)"
    r"(?:_([A-Za-z0-9_]+))?",
    re.ASCII,
)


class MissingDependencies(RuntimeError):
    """Native pacman confirmed unsatisfied dependencies."""

    def __init__(self, dependencies):
        self.dependencies = tuple(dependencies)

        super().__init__(
            "Missing dependencies: "
            + ", ".join(self.dependencies)
        )


class DependencyCheckError(RuntimeError):
    """Dependency satisfaction could not be established."""


def validate_dependency(value):
    """Accept a restricted literal Arch dependency expression."""

    if (
        not isinstance(value, str)
        or DEPENDENCY.fullmatch(value) is None
    ):
        raise ValueError("Invalid dependency expression")

    return value


def parse_srcinfo(source):
    """Parse native metadata into base and package sections."""

    if not isinstance(source, str) or not source:
        raise ValueError("Empty or invalid SRCINFO")

    if any(
        ord(character) < 32
        and character not in "\n\t"
        for character in source
    ):
        raise ValueError("Invalid SRCINFO control character")

    base = None
    packages = {}
    current = None

    for line in source.split("\n"):
        if not line.strip():
            continue

        indented = line.startswith((" ", "\t"))

        key, separator, value = (
            line.lstrip(" \t").partition(" = ")
        )

        if (
            not separator
            or FIELD.fullmatch(key) is None
        ):
            raise ValueError("Malformed SRCINFO declaration")

        if key in ("pkgbase", "pkgname"):
            if (
                indented
                or PACKAGE_NAME.fullmatch(value) is None
            ):
                raise ValueError("Invalid SRCINFO section")

            if key == "pkgbase":
                if base is not None:
                    raise ValueError("Duplicate pkgbase")

                base = []
                current = base

            else:
                if base is None or value in packages:
                    raise ValueError(
                        "Invalid or duplicate package section"
                    )

                current = []
                packages[value] = current

            continue

        if current is None or not indented:
            raise ValueError("Metadata outside package section")

        current.append((key, value))

    if base is None or not packages:
        raise ValueError("Incomplete SRCINFO structure")

    for key in ("pkgver", "pkgrel"):
        values = [
            value for field, value in base
            if field == key
        ]

        if len(values) != 1 or not values[0]:
            raise ValueError(
                f"Missing or duplicate {key}"
            )

    return base, packages


def extract_dependencies(source, architecture):
    """Extract runtime/build dependencies for the target architecture.

    Split-package dependencies are conservatively combined.
    This is not a general split-package dependency resolver.
    """

    if (
        not isinstance(architecture, str)
        or ARCHITECTURE.fullmatch(architecture) is None
        or architecture == "any"
    ):
        raise ValueError("Invalid target architecture")

    base, packages = parse_srcinfo(source)

    architectures = [
        value for key, value in base
        if key == "arch"
    ]

    if (
        not architectures
        or any(
            ARCHITECTURE.fullmatch(value) is None
            for value in architectures
        )
    ):
        raise ValueError("Invalid recipe architecture")

    if (
        architecture not in architectures
        and "any" not in architectures
    ):
        raise ValueError("Unsupported target architecture")

    dependencies = []

    for section in (base, *packages.values()):
        for key, value in section:
            match = DEPENDENCY_FIELD.fullmatch(key)

            if match is None:
                continue

            # Validate even declarations for other architectures.
            validate_dependency(value)

            suffix = match.group(1)

            if suffix is not None and suffix != architecture:
                continue

            dependencies.append(value)

    return list(dict.fromkeys(dependencies))


def check_dependencies(dependencies):
    """Require successful native pacman dependency satisfaction."""

    if not isinstance(dependencies, (list, tuple)):
        raise ValueError("Invalid dependency collection")

    checked = [
        validate_dependency(value)
        for value in dependencies
    ]

    if not checked:
        return

    try:
        result = subprocess.run(
            ["pacman", "-T", "--", *checked],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
        UnicodeError,
    ) as exc:
        raise DependencyCheckError(
            "Could not execute native dependency check"
        ) from exc

    if (
        result.returncode == 0
        and not result.stdout
        and not result.stderr
    ):
        return

    if (
        result.returncode == 127
        and not result.stderr
    ):
        missing = result.stdout.splitlines()

        if (
            missing
            and all(value in checked for value in missing)
        ):
            raise MissingDependencies(missing)

    raise DependencyCheckError(
        "Unexpected pacman dependency-check result "
        f"(exit status {result.returncode})"
    )


def main():
    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "--srcinfo",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--architecture",
        required=True,
    )

    args = parser.parse_args()

    try:
        dependencies = extract_dependencies(
            args.srcinfo.read_text(encoding="utf-8"),
            args.architecture,
        )

        check_dependencies(dependencies)

    except MissingDependencies as exc:
        print(str(exc), file=sys.stderr)
        return 2

    except (
        ValueError,
        OSError,
        DependencyCheckError,
    ) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(
        f"PASS: All {len(dependencies)} "
        "declared dependencies satisfied."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
