"""Controlled source updates for fixed package recipes."""

import re

from verify_source_contract import assignment
from resolve_candidate import compare_versions

FIXED_PACKAGES = frozenset({
    "ghostty", "keepassxc", "syncthing", "wezterm",
})

SOURCE_POLICIES = {
    "ghostty": (
        "ghostty-org/ghostty", "stable-git-tag"
    ),
    "keepassxc": (
        "keepassxreboot/keepassxc", "stable-tag"
    ),
    "syncthing": (
        "syncthing/syncthing", "stable-tag"
    ),
    "wezterm": (
        "wezterm/wezterm", "development-commit"
    ),
}

SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"[0-9]+(?:[.][0-9]+){2,3}")
PKGVER = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_]*")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def replace_assignment(source, field, value):
    old = assignment(source, field)

    pattern = re.compile(
        rf"^{re.escape(field)}={re.escape(old)}$",
        re.MULTILINE,
    )

    updated, count = pattern.subn(
        lambda _: f"{field}={value}", source
    )

    require(
        count == 1,
        f"Unexpected {field} assignment layout",
    )

    return updated


def replace_source_checksum(source, checksum):
    require(
        isinstance(checksum, str)
        and SHA256.fullmatch(checksum),
        "Missing or invalid upstream SHA-256",
    )

    declarations = re.findall(
        r"^[ \t]*sha256sums[ \t]*=",
        source,
        re.MULTILINE,
    )

    require(
        len(declarations) == 1,
        "Ambiguous checksum declaration",
    )

    pattern = re.compile(
        r"^(sha256sums=\(')([0-9a-f]{64})(')",
        re.MULTILINE,
    )

    updated, count = pattern.subn(
        lambda match: (
            match.group(1)
            + checksum
            + match.group(3)
        ),
        source,
    )

    require(
        count == 1,
        "Expected one pinned upstream source checksum",
    )

    return updated


def render_recipe(
    package,
    config,
    candidate,
    source,
    metadata,
    *,
    compare=compare_versions,
):
    """Render recipe fields without executing shell code."""

    require(
        package in FIXED_PACKAGES,
        "Unsupported fixed recipe",
    )

    require(
        isinstance(config, dict)
        and config.get("status") == "approved"
        and config.get("auto_publish") is False,
        "Package is not approved for source selection",
    )

    require(
        config.get("recipe") == f"arch/{package}/PKGBUILD",
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
        and isinstance(metadata, dict),
        "Invalid source metadata",
    )

    require(
        metadata.get("package") == package
        and metadata.get("candidate") == candidate,
        "Source metadata identity mismatch",
    )

    selected = config.get("source_ref")

    require(
        isinstance(selected, str)
        and selected != candidate,
        "Invalid source selection",
    )

    old_version = assignment(source, "pkgver")
    old_release = assignment(source, "pkgrel")

    require(
        PKGVER.fullmatch(old_version)
        and re.fullmatch(r"[1-9][0-9]*", old_release),
        "Invalid existing package version",
    )

    version = metadata.get("pkgver")

    require(
        isinstance(version, str)
        and PKGVER.fullmatch(version),
        "Invalid proposed package version",
    )

    if package == "wezterm":
        require(
            set(metadata) == {
                "package", "candidate", "pkgver"
            },
            "Unexpected WezTerm metadata fields",
        )

        require(
            COMMIT.fullmatch(selected)
            and COMMIT.fullmatch(candidate)
            and assignment(source, "_commit") == selected,
            "WezTerm commit does not match selection",
        )

        require(
            version.endswith(".g" + candidate[:9]),
            "WezTerm version does not identify candidate",
        )

        updated = replace_assignment(
            source, "_commit", candidate
        )

    else:
        require(
            set(metadata) == {
                "package", "candidate", "pkgver",
                "sha256",
            },
            "Unexpected stable-source metadata fields",
        )

        require(
            VERSION.fullmatch(candidate.removeprefix("v"))
            and VERSION.fullmatch(selected.removeprefix("v"))
            and version == candidate.removeprefix("v")
            and old_version == selected.removeprefix("v"),
            "Stable version does not match selection",
        )

        updated = replace_source_checksum(
            source, metadata["sha256"]
        )

    require(
        compare(old_version, version) == -1,
        "Proposed package version is not newer",
    )

    updated = replace_assignment(
        updated, "pkgver", version
    )

    updated = replace_assignment(
        updated, "pkgrel", "1"
    )

    return updated
