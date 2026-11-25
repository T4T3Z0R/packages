"""Restricted stable MATE Git source policy."""

import re

POLICY = "stable-mate-git-tag"
PACKAGE = "engrampa"
UPSTREAM = "mate-desktop/engrampa"

TAG = re.compile(
    r"v([0-9]+)[.]([0-9]+)[.]([0-9]+)",
    re.ASCII,
)


def stable_version(tag):
    """Return a canonical stable MATE version."""
    if not isinstance(tag, str):
        raise ValueError("Invalid MATE source tag")

    match = TAG.fullmatch(tag)

    if match is None:
        raise ValueError("Invalid MATE source tag")

    parts = match.groups()

    if any(str(int(part)) != part for part in parts):
        raise ValueError("Noncanonical MATE source version")

    if int(parts[1]) % 2:
        raise ValueError("MATE development series is not stable")

    return ".".join(parts)


def validate_source(name, upstream, selected):
    if name != PACKAGE or upstream != UPSTREAM:
        raise ValueError("Unsupported MATE upstream repository")

    return stable_version(selected)


def is_stable_tag(tag):
    try:
        stable_version(tag)
    except ValueError:
        return False

    return True


SOURCE_BLOCK = """source=(
  "git+https://github.com/mate-desktop/engrampa.git#tag=v$pkgver"
  git+https://github.com/mate-desktop/mate-submodules.git
  engrampa-fix-window-size.patch
)"""

PATCH_NAME = "engrampa-fix-window-size.patch"

B2 = re.compile(r"[0-9a-f]{128}", re.ASCII)

CHECKSUM_BLOCK = re.compile(
    r"^b2sums=\(\n"
    r"  ([0-9a-f]{128})\n"
    r"  SKIP\n"
    r"  ([0-9a-f]{128})\n"
    r"\)$",
    re.MULTILINE | re.ASCII,
)


def verify_recipe_layout(source):
    """Validate the exact approved source/checksum arrangement."""
    declarations = re.findall(
        r"^[ \t]*source(?:_[A-Za-z0-9_]+)?[ \t]*\+?=",
        source,
        re.MULTILINE,
    )

    if len(declarations) != 1:
        raise ValueError("Engrampa: unexpected source declarations")

    if source.count(SOURCE_BLOCK + "\n") != 1:
        raise ValueError("Engrampa: unexpected source layout")

    checksum_declarations = re.findall(
        r"^[ \t]*(?:md5|sha1|sha224|sha256|sha384|sha512|b2)"
        r"sums(?:_[A-Za-z0-9_]+)?[ \t]*\+?=",
        source,
        re.MULTILINE,
    )

    if len(checksum_declarations) != 1:
        raise ValueError("Engrampa: unexpected checksum declarations")

    matches = list(CHECKSUM_BLOCK.finditer(source))

    if len(matches) != 1:
        raise ValueError("Engrampa: invalid BLAKE2b checksum layout")

    return matches[0]


def replace_primary_checksum(source, checksum):
    """Replace only the primary Git source checksum."""
    if not isinstance(checksum, str) or not B2.fullmatch(checksum):
        raise ValueError("Engrampa: invalid primary BLAKE2b checksum")

    match = verify_recipe_layout(source)
    start, end = match.span(1)

    return source[:start] + checksum + source[end:]


def verify_patch(source, directory):
    """Verify the local patch against its declared BLAKE2b checksum."""
    import hashlib

    match = verify_recipe_layout(source)
    patch = directory / PATCH_NAME

    if not patch.is_file() or patch.is_symlink():
        raise ValueError("Engrampa: missing or invalid local patch")

    actual = hashlib.blake2b(patch.read_bytes()).hexdigest()

    if actual != match.group(2):
        raise ValueError("Engrampa: local patch checksum mismatch")

    return actual
