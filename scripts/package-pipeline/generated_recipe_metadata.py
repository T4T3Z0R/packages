"""Validate and render generated package recipe metadata."""

import re
from collections import Counter


COMMIT = re.compile(r"[0-9a-f]{40}", re.ASCII)

SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)

STABLE_TAG = re.compile(
    r"v([0-9]+(?:[.][0-9]+){2,3})",
    re.ASCII,
)

NOCTALIA_TAG = re.compile(
    r"v[0-9]+(?:[.][0-9]+){2,3}"
    r"(?:-(?:(?:alpha|beta|rc)[.]?[0-9]+|[0-9]+))?",
    re.ASCII,
)

GREETER_TAG = re.compile(
    r"v[0-9]+(?:[.][0-9]+){2,3}"
    r"(?:-(?:alpha|beta|rc)[.]?[0-9]+)?",
    re.ASCII,
)

ABBREVIATION = re.compile(
    r"[0-9a-f]{12,40}", re.ASCII
)

PKGVER = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9.+_]*",
    re.ASCII,
)

PLACEHOLDER = re.compile(
    r"@([A-Za-z0-9_]+)@",
    re.ASCII,
)

CONTRACTS = {
    "noctalia-custom": {
        "PKGVER": 1,
        "SOURCE_SHA256": 1,
    },
    "noctalia-greeter-t4t3z0r": {
        "PKGVER": 1,
        "SOURCE_SHA256": 1,
    },
    "gameshell": {
        "PKGVER": 1,
        "SOURCE_SHA": 1,
        "ARCHIVE_SHA256": 1,
        "LAUNCHER_SHA256": 1,
        "SOURCE_SHA256": 1,
        "LICENSE_SHA256": 1,
        "README_SHA256": 1,
    },
}


def validated(value, pattern, field):
    """Return a validated string without normalization."""

    if (
        not isinstance(value, str)
        or pattern.fullmatch(value) is None
    ):
        raise ValueError(f"Invalid {field}")

    return value


def stable_version(tag):
    """Extract a supported stable upstream version."""

    validated(tag, STABLE_TAG, "upstream version tag")

    return tag[1:]


def greeter_version(tag):
    """Preserve the existing Greeter tag transformation."""

    validated(tag, GREETER_TAG, "Greeter source tag")

    return validated(
        tag[1:].replace("-", "_"),
        PKGVER,
        "Greeter package version",
    )


def noctalia_version(tag, source_sha):
    """Preserve the current Noctalia version format."""

    validated(tag, NOCTALIA_TAG, "Noctalia source tag")

    version = tag[1:].replace("-", "_")

    validated(source_sha, COMMIT, "source commit")

    return validated(
        f"{version}.custom.{source_sha[:8]}",
        PKGVER,
        "Noctalia package version",
    )


def gameshell_version(
    tag, distance, source_sha, *, abbreviation=None
):
    """Preserve the current GameShell version format."""

    version = stable_version(tag)

    validated(source_sha, COMMIT, "source commit")

    if type(distance) is not int or distance < 0:
        raise ValueError("Invalid revision distance")

    if abbreviation is None:
        abbreviation = source_sha[:12]

    validated(
        abbreviation, ABBREVIATION, "commit abbreviation"
    )

    if not source_sha.startswith(abbreviation):
        raise ValueError("Commit abbreviation mismatch")

    if distance:
        version += f".r{distance}.g{abbreviation}"

    return validated(
        version,
        PKGVER,
        "GameShell package version",
    )


def render_recipe(package, template, values):
    """Render an approved template using validated literals."""

    if (
        not isinstance(package, str)
        or package not in CONTRACTS
    ):
        raise ValueError("Unsupported generated recipe")

    if not isinstance(template, str):
        raise ValueError("Invalid recipe template")

    expected = CONTRACTS[package]

    if (
        not isinstance(values, dict)
        or set(values) != set(expected)
    ):
        raise ValueError("Unexpected recipe metadata fields")

    actual = Counter(PLACEHOLDER.findall(template))

    if actual != expected:
        raise ValueError("Unexpected recipe placeholder layout")

    checked = {}

    for field, value in values.items():
        if field == "PKGVER":
            pattern = PKGVER
        elif field == "SOURCE_SHA":
            pattern = COMMIT
        elif field.endswith("_SHA256"):
            pattern = SHA256
        else:
            raise ValueError("Unsupported metadata field")

        checked[field] = validated(
            value, pattern, field
        )

    rendered = PLACEHOLDER.sub(
        lambda match: checked[match.group(1)],
        template,
    )

    if PLACEHOLDER.search(rendered):
        raise ValueError("Unresolved recipe placeholder")

    return rendered


def main():
    """Expose validated metadata through a narrow CLI."""

    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description=__doc__
    )

    commands = parser.add_subparsers(
        dest="command", required=True
    )

    noctalia = commands.add_parser("noctalia-version")
    noctalia.add_argument("--tag", required=True)
    noctalia.add_argument("--source-sha", required=True)

    greeter = commands.add_parser("greeter-version")
    greeter.add_argument("--tag", required=True)

    gameshell = commands.add_parser("gameshell-version")
    gameshell.add_argument("--tag", required=True)
    gameshell.add_argument("--source-sha", required=True)
    gameshell.add_argument("--distance", type=int, required=True)
    gameshell.add_argument("--abbreviation", required=True)

    base = commands.add_parser("gameshell-base-tag")
    base.add_argument("--tag", required=True)

    commit = commands.add_parser("validate-commit")
    commit.add_argument("--sha", required=True)

    render = commands.add_parser("render")
    render.add_argument(
        "--package",
        choices=sorted(CONTRACTS),
        required=True,
    )
    render.add_argument(
        "--value", action="append", required=True
    )

    args = parser.parse_args()

    try:
        if args.command == "noctalia-version":
            result = noctalia_version(
                args.tag, args.source_sha
            )

        elif args.command == "greeter-version":
            result = greeter_version(args.tag)

        elif args.command == "gameshell-version":
            result = gameshell_version(
                args.tag,
                args.distance,
                args.source_sha,
                abbreviation=args.abbreviation,
            )

        elif args.command == "gameshell-base-tag":
            stable_version(args.tag)
            result = args.tag

        elif args.command == "validate-commit":
            result = validated(
                args.sha, COMMIT, "source commit"
            )

        elif args.command == "render":
            values = {}

            for entry in args.value:
                key, separator, value = entry.partition("=")

                if not separator or key in values:
                    raise ValueError(
                        "Malformed or duplicate metadata field"
                    )

                values[key] = value

            root = Path(__file__).resolve().parents[2]

            template = (
                root / "arch" / args.package / "PKGBUILD.in"
            ).read_text()

            result = render_recipe(
                args.package, template, values
            )

        else:
            raise ValueError("Unsupported command")

    except (ValueError, OSError) as exc:
        parser.exit(1, f"FAIL: {exc}\n")

    if args.command == "render":
        sys.stdout.write(result)
    else:
        print(result)


if __name__ == "__main__":
    main()
