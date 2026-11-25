#!/usr/bin/env python3
"""Verify selected upstream source against an existing PKGBUILD."""

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "arch/packages/manifest.json"


def assignment(source, variable):
    """Read one literal shell assignment, never execute shell code."""
    pattern = re.compile(
        rf"^{re.escape(variable)}=([^\s#]+)\s*$",
        re.MULTILINE,
    )
    matches = pattern.findall(source)
    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one literal {variable} assignment"
        )
    return matches[0]


def verify(name, config, root=ROOT):
    if config["status"] != "approved":
        raise ValueError(f"{name}: package is not approved")

    recipe = config["recipe"]
    if recipe != f"arch/{name}/PKGBUILD":
        raise ValueError(
            f"{name}: fixed PKGBUILD required for this validator"
        )

    path = root / recipe
    if not path.is_file():
        raise ValueError(f"{name}: recipe is missing")

    source = path.read_text()
    policy = config["release_policy"]
    selected = config["source_ref"]

    if policy in ("stable-tag", "stable-git-tag", "pinned-tag"):
        expected = selected.removeprefix("v")
        actual = assignment(source, "pkgver")
        field = "pkgver"
    elif policy in ("development-commit", "pinned-commit"):
        if not re.fullmatch(r"[0-9a-f]{40}", selected):
            raise ValueError(f"{name}: invalid selected commit")
        expected = selected
        actual = assignment(source, "_commit")
        field = "_commit"
    else:
        raise ValueError(f"{name}: unsupported release policy")

    if actual != expected:
        raise ValueError(
            f"{name}: {field} mismatch: "
            f"manifest={expected}, recipe={actual}"
        )

    if name in ("ghostty", "yazi", "broot"):
        pinned = re.findall(
            r"^sha256sums=\('[0-9a-f]{64}'\)$",
            source, re.MULTILINE
        )
        declarations = re.findall(
            r"^[ \t]*sha256sums[ \t]*=",
            source, re.MULTILINE
        )
        if len(pinned) != 1 or len(declarations) != 1:
            raise ValueError(
                f"{name}: expected one literal pinned SHA-256 checksum"
            )

    if name == "broot":
        if (
            config["upstream"] != "Canop/broot"
            or policy != "stable-git-tag"
            or selected != "v" + actual
        ):
            raise ValueError("broot: unexpected source policy")

        expected_source = (
            'source=("https://github.com/Canop/broot/'
            'archive/v$pkgver/$pkgname-v$pkgver.tar.gz")'
        )

        declarations = [
            line for line in source.splitlines()
            if line.strip().partition("=")[0].strip() == "source"
        ]

        if (
            declarations != [expected_source]
            or assignment(source, "pkgname") != "broot"
        ):
            raise ValueError("broot: unexpected archive source")

    if name == "yazi":
        if (
            config["upstream"] != "sxyazi/yazi"
            or policy != "stable-tag"
            or selected != "v" + actual
        ):
            raise ValueError("yazi: unexpected source policy")

        expected_source = (
            'source=("$pkgname-$pkgver.tar.gz::'
            'https://github.com/sxyazi/$pkgname/'
            'archive/v$pkgver.tar.gz")'
        )

        declarations = [
            line for line in source.splitlines()
            if line.strip().partition("=")[0].strip() == "source"
        ]

        if (
            declarations != [expected_source]
            or assignment(source, "pkgname") != "yazi"
        ):
            raise ValueError("yazi: unexpected archive source")

    if name == "moonlight-qt":
        if (
            config["upstream"] != "moonlight-stream/moonlight-qt"
            or policy != "stable-tag"
            or selected != "v" + actual
        ):
            raise ValueError(
                "moonlight-qt: unexpected source policy"
            )

        pinned = re.findall(
            r"^sha512sums=\('[0-9a-f]{128}'\)$",
            source, re.MULTILINE
        )
        declarations = re.findall(
            r"^[ \t]*sha512sums[ \t]*=",
            source, re.MULTILINE
        )
        if len(pinned) != 1 or len(declarations) != 1:
            raise ValueError(
                "moonlight-qt: expected one literal pinned SHA-512 checksum"
            )

    pkgver = assignment(source, "pkgver")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_]*", pkgver):
        raise ValueError(f"{name}: invalid pkgver")

    pkgrel = assignment(source, "pkgrel")
    if not re.fullmatch(r"[1-9][0-9]*", pkgrel):
        raise ValueError(f"{name}: invalid pkgrel")

    return {
        "package": name,
        "source_ref": selected,
        "source_field": field,
        "source_value": actual,
        "pkgver": pkgver,
        "pkgrel": int(pkgrel),
        "recipe": recipe,
        "verified": True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--package", required=True)
    args = parser.parse_args()

    data = json.loads(args.manifest.read_text())
    config = data["packages"][args.package]
    result = verify(args.package, config, ROOT)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
