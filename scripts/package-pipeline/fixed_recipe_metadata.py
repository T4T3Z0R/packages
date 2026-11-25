"""Resolve fixed-recipe source metadata without building packages."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

import xfce_source
import mate_source

from fixed_recipe_selection import (
    COMMIT, VERSION, SOURCE_POLICIES, require,
    CHECKSUM_POLICIES,
)

ROOT = Path(__file__).resolve().parents[2]


def run(args, *, cwd=None):
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=900,
    ).stdout.strip()


def wezterm_version(candidate):
    require(
        COMMIT.fullmatch(candidate),
        "Invalid WezTerm commit",
    )

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)

        run(["git", "init", "-q"], cwd=root)

        run([
            "git", "remote", "add", "origin",
            "https://github.com/wezterm/wezterm.git",
        ], cwd=root)

        run([
            "git", "fetch", "--quiet",
            "--filter=blob:none", "--no-tags",
            "origin", candidate,
            "+refs/tags/20*:refs/tags/20*",
        ], cwd=root)

        resolved = run([
            "git", "rev-parse",
            candidate + "^{commit}",
        ], cwd=root)

        require(
            resolved == candidate,
            "Fetched WezTerm commit mismatch",
        )

        description = run([
            "git", "describe", "--tags",
            "--match", "20*", "--long",
            candidate,
        ], cwd=root)

        match = re.fullmatch(
            r"(20[A-Za-z0-9._+-]*)"
            r"-([0-9]+)-g([0-9a-f]+)",
            description,
        )

        require(
            match is not None,
            "Unexpected WezTerm Git description",
        )

        tag, distance, abbreviated = match.groups()

        require(
            candidate.startswith(abbreviated),
            "WezTerm Git description commit mismatch",
        )

        # Match the existing production PKGBUILD's
        # pkgver() transformation exactly.
        return (
            tag.replace("-", ".")
            + ".r" + distance
            + ".g" + candidate[:9]
        )


def archive_url(package, version):
    require(
        VERSION.fullmatch(version),
        "Invalid archive version",
    )

    if package == "ghostty":
        return (
            "https://github.com/ghostty-org/ghostty"
            f"/archive/v{version}/"
            f"ghostty-{version}.tar.gz"
        )

    if package == "syncthing":
        return (
            "https://github.com/syncthing/syncthing"
            f"/releases/download/v{version}/"
            f"syncthing-source-v{version}.tar.gz"
        )

    if package == "broot":
        return (
            "https://github.com/Canop/broot"
            f"/archive/v{version}/"
            f"broot-v{version}.tar.gz"
        )

    if package == "yazi":
        return (
            "https://github.com/sxyazi/yazi"
            f"/archive/v{version}.tar.gz"
        )

    if package == "moonlight-qt":
        return (
            "https://github.com/moonlight-stream/moonlight-qt"
            f"/releases/download/v{version}/"
            f"MoonlightSrc-{version}.tar.gz"
        )

    raise ValueError("Unsupported archive source")


def archive_checksum(package, version):
    url = archive_url(package, version)

    with tempfile.TemporaryDirectory() as temp:
        target = Path(temp) / "source.tar.gz"

        run([
            "curl", "--fail", "--silent",
            "--show-error", "--location",
            "--proto", "=https",
            "--proto-redir", "=https",
            "--connect-timeout", "30",
            "--max-time", "600",
            "--retry", "2",
            "--output", str(target),
            url,
        ])

        require(
            target.is_file()
            and target.stat().st_size > 0,
            "Empty upstream source archive",
        )

        algorithm, _ = CHECKSUM_POLICIES[package]
        digest = hashlib.new(algorithm)

        with target.open("rb") as stream:
            require(
                stream.read(2) == bytes([31, 139]),
                "Unexpected archive format",
            )
            stream.seek(0)

            for block in iter(
                lambda: stream.read(1024 * 1024),
                b"",
            ):
                digest.update(block)

        return digest.hexdigest()


def parse_native_checksum(output):
    matches = re.findall(
        r"^sha256sums=\('([0-9a-f]{64})'\)$",
        output,
        re.MULTILINE,
    )

    require(
        len(matches) == 1,
        "Expected exactly one native Git checksum",
    )

    return matches[0]


def keepassxc_checksum(version):
    require(
        VERSION.fullmatch(version),
        "Invalid KeePassXC version",
    )

    require(
        os.geteuid() != 0,
        "Native checksum resolver requires unprivileged user",
    )

    # A minimal source-only recipe, not downloaded build code.
    recipe = "\n".join((
        "pkgname=keepassxc",
        f"pkgver={version}",
        "pkgrel=1",
        "arch=('any')",
        'source=("git+https://github.com/'
        'keepassxreboot/keepassxc.git'
        '#tag=${pkgver}?signed")',
        "sha256sums=('"
        + "0" * 64 + "')",
        "",
    ))

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "PKGBUILD").write_text(recipe)

        output = run([
            "makepkg", "--geninteg", "--noconfirm",
        ], cwd=root)

        return parse_native_checksum(output)


def xfce_checksum(package, version):
    if package not in xfce_source.UPSTREAMS:
        raise ValueError("Unsupported XFCE package")

    upstream = xfce_source.UPSTREAMS[package]
    tag = package + "-" + version

    xfce_source.validate_source(package, upstream, tag)

    require(
        os.geteuid() != 0,
        "Native checksum resolver requires unprivileged user",
    )

    # Source-only recipe. Preserve the official Git source
    # declaration without executing upstream build code.
    recipe = "\n".join((
        f"pkgname={package}",
        f"pkgver={version}",
        "pkgrel=1",
        "arch=('any')",
        f'source=("git+{upstream}#tag=$pkgname-$pkgver")',
        "sha256sums=('"
        + "0" * 64 + "')",
        "",
    ))

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "PKGBUILD").write_text(recipe)

        output = run([
            "makepkg", "--geninteg", "--noconfirm",
        ], cwd=root)

        return parse_native_checksum(output)


def thunar_checksum(version):
    return xfce_checksum("thunar", version)


def mousepad_checksum(version):
    return xfce_checksum("mousepad", version)


def engrampa_checksum(version):
    mate_source.stable_version("v" + version)

    require(
        os.geteuid() != 0,
        "Native checksum resolver requires unprivileged user",
    )

    # Source-only recipe matching the official primary Git
    # source and checksum algorithm. Do not execute upstream
    # preparation or build functions.
    recipe = "\n".join((
        "pkgname=engrampa",
        f"pkgver={version}",
        "pkgrel=1",
        "arch=('any')",
        'source=("git+https://github.com/'
        'mate-desktop/engrampa.git#tag=v$pkgver")',
        "b2sums=('" + "0" * 128 + "')",
        "",
    ))

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "PKGBUILD").write_text(recipe)

        output = run([
            "makepkg", "--geninteg", "--noconfirm",
        ], cwd=root)

        matches = re.findall(
            r"^b2sums=\('([0-9a-f]{128})'\)$",
            output,
            re.MULTILINE,
        )

        require(
            len(matches) == 1,
            "Expected exactly one native BLAKE2b checksum",
        )

        return matches[0]


def resolve(package, candidate, config):
    require(
        package in SOURCE_POLICIES,
        "Unsupported fixed recipe",
    )

    require(
        isinstance(config, dict)
        and config.get("status") == "approved"
        and config.get("auto_publish") is False,
        "Unapproved package",
    )

    require(
        config.get("recipe")
        == f"arch/{package}/PKGBUILD",
        "Unexpected fixed recipe path",
    )

    require(
        (
            config.get("upstream"),
            config.get("release_policy"),
        ) == SOURCE_POLICIES[package],
        "Unexpected upstream or source policy",
    )

    require(
        isinstance(candidate, str)
        and candidate != config.get("source_ref"),
        "Invalid source candidate",
    )

    result = {
        "package": package,
        "candidate": candidate,
    }

    if package == "wezterm":
        result["pkgver"] = wezterm_version(candidate)
        return result

    if package == mate_source.PACKAGE:
        mate_source.validate_source(
            package, config["upstream"], config["source_ref"]
        )
        version = mate_source.stable_version(candidate)
        expected = "v" + version
    elif package in xfce_source.UPSTREAMS:
        xfce_source.validate_source(
            package, config["upstream"], config["source_ref"]
        )
        version = xfce_source.stable_version(candidate, package)
        expected = package + "-" + version
    else:
        version = candidate.removeprefix("v")
        expected = (
            version if package == "keepassxc"
            else "v" + version
        )

    require(
        VERSION.fullmatch(version),
        "Invalid stable version",
    )

    require(
        candidate == expected,
        "Unexpected upstream tag format",
    )

    if package == "keepassxc":
        checksum = keepassxc_checksum(version)
    elif package == "thunar":
        checksum = thunar_checksum(version)
    elif package == "mousepad":
        checksum = mousepad_checksum(version)
    elif package == mate_source.PACKAGE:
        checksum = engrampa_checksum(version)
    else:
        checksum = archive_checksum(package, version)

    algorithm, pattern = CHECKSUM_POLICIES[package]

    require(
        pattern.fullmatch(checksum),
        "Invalid resolved checksum",
    )

    result.update(
        pkgver=version,
        **{algorithm: checksum},
    )

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "arch/packages/manifest.json",
    )

    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text())

    result = resolve(
        args.package,
        args.candidate,
        manifest["packages"][args.package],
    )

    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
