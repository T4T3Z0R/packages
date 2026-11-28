"""Read-only structural inspection of Arch package archives.

This module produces a structural inventory. Symbolic link
relationships require additional policy validation before an
archive may be accepted.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import tarfile
import time
import unicodedata

from pathlib import Path


MAX_COMPRESSED_BYTES = 512 * 1024**2
MAX_EXPANDED_BYTES = 2 * 1024**3
MAX_MEMBER_BYTES = 512 * 1024**2
MAX_METADATA_BYTES = 1024**2
MAX_MEMBERS = 25_000
MAX_PATH_BYTES = 4096
INSPECTION_TIMEOUT = 300
PROCESS_CLEANUP_TIMEOUT = 30
ZSTD_MEMORY_LIMIT = "-M128MB"
HASH_CHUNK_BYTES = 1024**2

REQUIRED_METADATA = frozenset({
    ".PKGINFO",
    ".BUILDINFO",
    ".MTREE",
})

OPTIONAL_METADATA = frozenset({
    ".INSTALL",
    ".CHANGELOG",
})


class ArchiveError(RuntimeError):
    """Package archive inspection failed."""


def require_unprivileged():
    if (
        os.getuid() == 0
        or os.geteuid() == 0
        or os.getuid() != os.geteuid()
    ):
        raise ArchiveError(
            "Archive inspection requires an unprivileged identity"
        )

    if (
        os.getgid() == 0
        or os.getegid() == 0
        or os.getgid() != os.getegid()
        or 0 in os.getgroups()
    ):
        raise ArchiveError(
            "Archive inspector has privileged group"
        )


def validate_text(value, description):
    if not isinstance(value, str) or not value:
        raise ArchiveError(
            f"Empty or invalid {description}"
        )

    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ArchiveError(
            f"Invalid encoding in {description}"
        ) from error

    if len(encoded) > MAX_PATH_BYTES:
        raise ArchiveError(
            f"{description} exceeds length limit"
        )

    if "\\" in value:
        raise ArchiveError(
            f"Backslash in {description}"
        )

    if any(
        unicodedata.category(character) == "Cc"
        for character in value
    ):
        raise ArchiveError(
            f"Control character in {description}"
        )

    return value


def normalize_member_path(name, *, directory=False):
    """Normalize an optional leading ./ without hiding traversal."""
    validate_text(name, "archive member path")

    if name.startswith("/"):
        raise ArchiveError(
            f"Absolute archive member path: {name!r}"
        )

    if name in {".", "./"}:
        if directory:
            return "."

        raise ArchiveError(
            "Archive root member must be a directory"
        )

    if name.startswith("./"):
        name = name[2:]

    if directory and name.endswith("/"):
        name = name[:-1]

    parts = name.split("/")

    if any(part in {"", ".", ".."} for part in parts):
        raise ArchiveError(
            f"Unsafe archive member path: {name!r}"
        )

    return "/".join(parts)


def member_kind(member):
    if member.sparse is not None:
        raise ArchiveError(
            f"Sparse archive member: {member.name!r}"
        )

    if member.type in {
        tarfile.REGTYPE,
        tarfile.AREGTYPE,
    }:
        return "file"

    if member.type == tarfile.DIRTYPE:
        return "directory"

    if member.type == tarfile.SYMTYPE:
        return "symlink"

    raise ArchiveError(
        f"Unsupported archive member type: "
        f"{member.name!r}, {member.type!r}"
    )


def remaining_time(deadline):
    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise ArchiveError(
            "Package inspection deadline exceeded"
        )

    return remaining


class DeadlinePipeReader:
    """Read decompressor output without indefinite blocking."""

    def __init__(self, stream, deadline):
        self.stream = stream
        self.deadline = deadline
        self.fd = stream.fileno()
        self.selector = None

    def __enter__(self):
        os.set_blocking(self.fd, False)

        selector = selectors.DefaultSelector()

        try:
            selector.register(
                self.fd,
                selectors.EVENT_READ,
            )
        except BaseException:
            selector.close()
            raise

        self.selector = selector

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.selector.close()
        self.selector = None

    def read(self, size):
        if not 0 <= size <= TAR_READ_CHUNK:
            raise ArchiveError(
                "Invalid decompressor read size"
            )

        if size == 0:
            return b""

        while True:
            remaining = remaining_time(
                self.deadline
            )

            if not self.selector.select(remaining):
                raise ArchiveError(
                    "Package decompression timed out"
                )

            remaining_time(self.deadline)

            try:
                data = os.read(self.fd, size)
            except BlockingIOError:
                continue
            except InterruptedError:
                continue

            remaining_time(self.deadline)

            return data


class BoundedReader:
    """Limit bytes read from the decompressed package stream."""

    def __init__(self, stream, limit):
        self.stream = stream
        self.limit = limit
        self.total = 0

    def read(self, size=-1):
        remaining = self.limit - self.total

        if size < 0 or size > remaining + 1:
            size = remaining + 1

        data = self.stream.read(size)
        self.total += len(data)

        if self.total > self.limit:
            raise ArchiveError(
                "Expanded archive exceeds size limit"
            )

        return data


def validate_member_relationships(entries):
    """Reject any member placed beneath a non-directory member."""
    for name in entries:
        if name == ".":
            continue

        components = name.split("/")

        for count in range(1, len(components)):
            ancestor = "/".join(components[:count])
            existing = entries.get(ancestor)

            if (
                existing is not None
                and existing["type"] != "directory"
            ):
                raise ArchiveError(
                    f"Member beneath non-directory ancestor: "
                    f"{name!r}, {ancestor!r}"
                )



MAX_LINK_HOPS = 40

DEBUG_BUILD_ID = re.compile(
    r"usr/lib/debug/\.build-id/"
    r"[0-9a-f]{2}/[0-9a-f]{38}(?:\.debug)?",
    re.ASCII,
)

ENGRAMPA_DOCUMENTATION = re.compile(
    r"usr/share/help/([A-Za-z0-9_@.-]+)/"
    r"engrampa/figures/([^/]+\.png)",
    re.ASCII,
)


def link_target_path(entries, name, target):
    """Resolve a target lexically within a virtual package root.

    Intermediate symbolic links are deliberately unsupported.
    Terminal symbolic link chains are handled separately.
    """
    validate_text(target, "symbolic link target")

    if target.startswith("/"):
        raise ArchiveError(
            f"Unexpected absolute link target: {name!r}"
        )

    components = name.split("/")[:-1]
    target_parts = target.split("/")

    for index, part in enumerate(target_parts):
        if part == "":
            raise ArchiveError(
                f"Empty link target component: {name!r}"
            )

        if part == ".":
            continue

        if part == "..":
            if not components:
                raise ArchiveError(
                    f"Link escapes package root: {name!r}"
                )

            components.pop()
            continue

        components.append(part)

        current = "/".join(components)
        entry = entries.get(current)

        if index < len(target_parts) - 1:
            if entry is not None:
                if entry["type"] != "directory":
                    raise ArchiveError(
                        f"Link traverses non-directory member: "
                        f"{name!r}, {current!r}"
                    )
            else:
                raise ArchiveError(
                    f"Missing intermediate link directory: "
                    f"{name!r}, {current!r}"
                )

    if not components:
        raise ArchiveError(
            f"Link resolves to package root: {name!r}"
        )

    return "/".join(components)


def engrampa_absolute_target(package, name, target):
    """Permit only the observed localized documentation aliases."""
    if package != "engrampa":
        raise ArchiveError(
            f"Absolute link not permitted: {package!r}, {name!r}"
        )

    match = ENGRAMPA_DOCUMENTATION.fullmatch(name)

    if match is None or match.group(1) == "C":
        raise ArchiveError(
            f"Unexpected Engrampa absolute link: {name!r}"
        )

    expected = (
        "/usr/share/help/C/engrampa/figures/"
        + match.group(2)
    )

    if target != expected:
        raise ArchiveError(
            f"Unexpected Engrampa documentation target: "
            f"{name!r}, {target!r}"
        )

    return expected[1:]


def merge_debug_lookup(entries, companion_entries):
    """Construct a virtual lookup for one approved split pair."""
    merged = dict(companion_entries)

    for name, entry in entries.items():
        previous = merged.get(name)

        if previous is not None:
            # Shared archive metadata describes each individual
            # package and is not an installed cross-package target.
            if name in REQUIRED_METADATA | OPTIONAL_METADATA:
                merged[name] = entry
                continue

            if (
                previous["type"] != "directory"
                or entry["type"] != "directory"
            ):
                raise ArchiveError(
                    f"Conflicting split package member: {name!r}"
                )

        merged[name] = entry

    validate_member_relationships(merged)

    return merged


def validate_symbolic_links(
    package,
    entries,
    *,
    companion_entries=None,
):
    """Validate links against exact package and split-pair inventories.

    The caller must establish the package identity and approved
    companion relationship independently of candidate metadata.
    """
    resolved = {}

    lookup = entries

    if companion_entries is not None:
        lookup = merge_debug_lookup(
            entries,
            companion_entries,
        )

    for name, entry in entries.items():
        if entry["type"] != "symlink":
            continue

        current = name
        visited = set()
        hops = 0

        debug_link = (
            package.endswith("-debug")
            and DEBUG_BUILD_ID.fullmatch(name) is not None
        )

        if package.endswith("-debug") and not debug_link:
            raise ArchiveError(
                f"Unexpected debug package link: {name!r}"
            )

        active_lookup = lookup if debug_link else entries

        while True:
            if current in visited:
                raise ArchiveError(
                    f"Symbolic link cycle: {name!r}"
                )

            visited.add(current)

            current_entry = active_lookup.get(current)

            if current_entry is None:
                raise ArchiveError(
                    f"Missing symbolic link target: "
                    f"{name!r}, {current!r}"
                )

            kind = current_entry["type"]

            if kind == "file":
                break

            if kind != "symlink":
                raise ArchiveError(
                    f"Link does not resolve to a regular file: "
                    f"{name!r}, {current!r}"
                )

            # Debug links must not follow links in the companion
            # package. Their observed targets are regular files.
            if debug_link and current != name:
                raise ArchiveError(
                    f"Unexpected chained debug link: {name!r}"
                )

            if hops >= MAX_LINK_HOPS:
                raise ArchiveError(
                    f"Symbolic link chain exceeds limit: {name!r}"
                )

            target = current_entry["target"]

            if target.startswith("/"):
                current = engrampa_absolute_target(
                    package,
                    current,
                    target,
                )

                destination = entries.get(current)

                if (
                    destination is None
                    or destination["type"] != "file"
                ):
                    raise ArchiveError(
                        "Engrampa absolute documentation link "
                        "must resolve directly to a regular file"
                    )
            else:
                current = link_target_path(
                    active_lookup,
                    current,
                    target,
                )

            hops += 1

        if current in REQUIRED_METADATA | OPTIONAL_METADATA:
            raise ArchiveError(
                f"Link resolves to package metadata: {name!r}"
            )

        if debug_link:
            if name.endswith(".debug"):
                if (
                    current not in entries
                    or not current.startswith("usr/lib/debug/")
                    or not current.endswith(".debug")
                    or current.startswith(
                        "usr/lib/debug/.build-id/"
                    )
                ):
                    raise ArchiveError(
                        f"Unexpected debug data target: {name!r}"
                    )
            else:
                if (
                    companion_entries is None
                    or current not in companion_entries
                    or not current.startswith(
                        ("usr/bin/", "usr/lib/")
                    )
                    or current.startswith("usr/lib/debug/")
                ):
                    raise ArchiveError(
                        f"Unexpected debug executable target: "
                        f"{name!r}"
                    )

        resolved[name] = {
            "target": entry["target"],
            "resolved": current,
            "hops": hops,
            "cross_package": current not in entries,
        }

    return dict(sorted(resolved.items()))


TAR_BLOCK_BYTES = 512
TAR_ZERO_BLOCK = bytes(TAR_BLOCK_BYTES)
TAR_USTAR_MAGIC = b"ustar\x0000"
TAR_READ_CHUNK = 1024**2

TAR_MEMBER_TYPES = {
    b"0": "file",
    b"2": "symlink",
    b"5": "directory",
}


def read_exact(reader, size):
    """Read a complete bounded archive region."""
    if not 0 <= size <= TAR_READ_CHUNK:
        raise ArchiveError(
            "Invalid physical archive read size"
        )

    data = bytearray()

    while len(data) < size:
        chunk = reader.read(size - len(data))

        if not chunk:
            raise ArchiveError(
                "Truncated physical archive region"
            )

        data.extend(chunk)

    return bytes(data)


def consume_payload(reader, size):
    """Consume a regular payload without retaining it in memory."""
    while size:
        length = min(size, TAR_READ_CHUNK)
        read_exact(reader, length)
        size -= length


def validate_zero_padding(reader, size):
    if size and any(read_exact(reader, size)):
        raise ArchiveError(
            "Nonzero physical member padding"
        )


def validate_tar_termination(reader):
    """Require the second zero block and zero-only trailing padding."""
    if read_exact(reader, TAR_BLOCK_BYTES) != TAR_ZERO_BLOCK:
        raise ArchiveError(
            "Missing second tar termination block"
        )

    trailing = 0

    while True:
        data = reader.read(TAR_READ_CHUNK)

        if not data:
            break

        if any(data):
            raise ArchiveError(
                "Nonzero data after tar termination"
            )

        trailing += len(data)

    if trailing % TAR_BLOCK_BYTES:
        raise ArchiveError(
            "Unaligned trailing tar padding"
        )


USTAR_NUMERIC_FIELDS = {
    "mode": (100, 108),
    "uid": (108, 116),
    "gid": (116, 124),
    "size": (124, 136),
    "mtime": (136, 148),
    "checksum": (148, 156),
    "devmajor": (329, 337),
    "devminor": (337, 345),
}

USTAR_TEXT_FIELDS = {
    "name": (0, 100),
    "linkname": (157, 257),
    "uname": (265, 297),
    "gname": (297, 329),
    "prefix": (345, 500),
}


def decode_ustar_number(field, raw):
    """Accept only unambiguous conventional octal fields."""
    width = len(raw)

    if field == "checksum":
        pattern = rb"[0-7]{6}\x00 "

        if not re.fullmatch(pattern, raw):
            raise ArchiveError(
                "Invalid USTAR checksum encoding"
            )

        return int(raw[:6], 8)

    # Python USTAR and conventional libarchive forms.
    if re.fullmatch(rb"[0-7]+\x00", raw):
        digits = raw[:-1]

        if len(digits) == width - 1:
            return int(digits, 8)

    if re.fullmatch(rb"[0-7]+ \x00", raw):
        digits = raw[:-2]

        if len(digits) == width - 2:
            return int(digits, 8)

    if re.fullmatch(rb"[0-7]+ ", raw):
        digits = raw[:-1]

        if len(digits) == width - 1:
            return int(digits, 8)

    # Python's USTAR writer can emit zero-filled
    # unused device fields for non-device members.
    if (
        field in {"devmajor", "devminor"}
        and not any(raw)
    ):
        return 0

    raise ArchiveError(
        f"Invalid USTAR numeric encoding: {field}"
    )


def decode_ustar_text(field, raw):
    """Reject hidden bytes after NUL; permit full-width fields."""
    content, separator, remainder = raw.partition(b"\x00")

    if separator and any(remainder):
        raise ArchiveError(
            f"Nonzero bytes after USTAR NUL: {field}"
        )

    try:
        return content.decode(
            "utf-8",
            errors="strict",
        )
    except UnicodeError as error:
        raise ArchiveError(
            f"Invalid USTAR text encoding: {field}"
        ) from error


def validate_ustar_fields(header):
    numbers = {
        field: decode_ustar_number(
            field,
            header[start:end],
        )
        for field, (start, end)
        in USTAR_NUMERIC_FIELDS.items()
    }

    strings = {
        field: decode_ustar_text(
            field,
            header[start:end],
        )
        for field, (start, end)
        in USTAR_TEXT_FIELDS.items()
    }

    # POSIX unsigned byte checksum, with the checksum
    # field itself treated as eight ASCII spaces.
    checksum = (
        sum(header[:148])
        + 8 * 32
        + sum(header[156:])
    )

    if numbers["checksum"] != checksum:
        raise ArchiveError(
            "Invalid unsigned USTAR checksum"
        )

    if any(header[500:512]):
        raise ArchiveError(
            "Nonzero reserved USTAR header bytes"
        )

    if (
        numbers["uid"] != 0
        or numbers["gid"] != 0
        or strings["uname"] != "root"
        or strings["gname"] != "root"
    ):
        raise ArchiveError(
            "Unexpected USTAR package ownership"
        )

    if numbers["devmajor"] or numbers["devminor"]:
        raise ArchiveError(
            "Unexpected USTAR device field values"
        )

    if not strings["name"]:
        raise ArchiveError(
            "Empty USTAR member name"
        )

    physical_type = header[156:157]
    mode = numbers["mode"]

    if physical_type == b"2":
        if mode != 0o777:
            raise ArchiveError(
                "Unexpected symbolic link permissions"
            )
    elif mode & 0o022:
        raise ArchiveError(
            "Group/world-writable package member"
        )

    return numbers, strings


def decode_physical_header(header):
    """Decode one conventional USTAR header without extensions."""
    if len(header) != TAR_BLOCK_BYTES:
        raise ArchiveError(
            "Incomplete physical tar header"
        )

    if header[257:265] != TAR_USTAR_MAGIC:
        raise ArchiveError(
            "Unsupported physical tar format"
        )

    physical_type = header[156:157]

    if physical_type not in TAR_MEMBER_TYPES:
        raise ArchiveError(
            f"Unsupported physical member type: {physical_type!r}"
        )

    numbers, strings = validate_ustar_fields(header)

    try:
        member = tarfile.TarInfo.frombuf(
            header,
            encoding="utf-8",
            errors="strict",
        )
    except (tarfile.TarError, UnicodeError, ValueError) as error:
        raise ArchiveError(
            "Invalid physical tar header"
        ) from error

    for field in (
        "mode",
        "uid",
        "gid",
        "size",
        "mtime",
        "devmajor",
        "devminor",
    ):
        if getattr(member, field) != numbers[field]:
            raise ArchiveError(
                f"Physical and decoded USTAR fields differ: {field}"
            )

    for field in ("linkname", "uname", "gname"):
        if getattr(member, field) != strings[field]:
            raise ArchiveError(
                f"Physical and decoded USTAR text differs: {field}"
            )

    physical_name = strings["name"]

    if strings["prefix"]:
        physical_name = (
            strings["prefix"] + "/" + physical_name
        )

    if physical_type == b"5":
        physical_name = physical_name.rstrip("/")
        decoded_name = member.name.rstrip("/")
    else:
        decoded_name = member.name

    if physical_name != decoded_name:
        raise ArchiveError(
            "Physical and decoded USTAR paths differ"
        )

    # Preserve the original path spelling for the
    # subsequent strict path normalization checks.
    member.name = (
        strings["prefix"] + "/" + strings["name"]
        if strings["prefix"]
        else strings["name"]
    )

    if member.type != physical_type:
        raise ArchiveError(
            "Physical and decoded member types differ"
        )

    kind = member_kind(member)

    if kind != TAR_MEMBER_TYPES[physical_type]:
        raise ArchiveError(
            "Inconsistent physical member type"
        )

    return member, kind


def inspect_tar_stream(stream):
    """Inspect a strictly bounded conventional USTAR archive."""
    entries = {}
    metadata = {}
    member_count = 0

    reader = BoundedReader(
        stream,
        MAX_EXPANDED_BYTES,
    )

    while True:
        header = read_exact(reader, TAR_BLOCK_BYTES)

        if header == TAR_ZERO_BLOCK:
            validate_tar_termination(reader)
            break

        member_count += 1

        if member_count > MAX_MEMBERS:
            raise ArchiveError(
                "Archive member count exceeds limit"
            )

        member, kind = decode_physical_header(header)

        name = normalize_member_path(
            member.name,
            directory=(kind == "directory"),
        )

        if name in entries:
            raise ArchiveError(
                f"Duplicate archive member: {name!r}"
            )

        if not 0 <= member.mode <= 0o777:
            raise ArchiveError(
                f"Unsupported permission bits: {name!r}"
            )

        if not 0 <= member.size <= MAX_MEMBER_BYTES:
            raise ArchiveError(
                f"Member size outside policy: {name!r}"
            )

        if kind != "file" and member.size != 0:
            raise ArchiveError(
                f"Nonregular member has payload: {name!r}"
            )

        record = {
            "type": kind,
            "mode": member.mode,
            "size": member.size,
        }

        if kind == "symlink":
            record["target"] = validate_text(
                member.linkname,
                "symbolic link target",
            )
        elif member.linkname:
            raise ArchiveError(
                f"Unexpected link target: {name!r}"
            )

        if name in REQUIRED_METADATA | OPTIONAL_METADATA:
            if kind != "file":
                raise ArchiveError(
                    f"Metadata must be regular: {name!r}"
                )

        entries[name] = record

        if name == ".PKGINFO":
            if not 0 < member.size <= MAX_METADATA_BYTES:
                raise ArchiveError(
                    ".PKGINFO size outside policy"
                )

            payload = read_exact(reader, member.size)

            metadata[name] = payload.decode(
                "utf-8",
                errors="strict",
            )
        else:
            consume_payload(reader, member.size)

        validate_zero_padding(
            reader,
            (-member.size) % TAR_BLOCK_BYTES,
        )

    missing = REQUIRED_METADATA - entries.keys()

    if missing:
        raise ArchiveError(
            "Missing required package metadata: "
            + ", ".join(sorted(missing))
        )

    validate_member_relationships(entries)

    return {
        "schema": 1,
        "structural_inventory_only": True,
        "member_count": member_count,
        "expanded_bytes": reader.total,
        "entries": dict(sorted(entries.items())),
        "metadata": metadata,
        "symlink_count": sum(
            entry["type"] == "symlink"
            for entry in entries.values()
        ),
    }


PACKAGE_IDENTITY_NAME = re.compile(
    r"[a-z][a-z0-9-]*",
    re.ASCII,
)

PACKAGE_IDENTITY_VERSION = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9.+_]*"
    r"-[0-9]+(?:\.[0-9]+)?",
    re.ASCII,
)

PACKAGE_DIGEST = re.compile(
    r"[0-9a-f]{64}",
    re.ASCII,
)

IDENTITY_FIELDS = frozenset({
    "pkgname",
    "pkgver",
    "arch",
})


def validate_identity_values(name, version, architecture):
    if (
        not isinstance(name, str)
        or not PACKAGE_IDENTITY_NAME.fullmatch(name)
    ):
        raise ArchiveError("Invalid package identity name")

    if (
        not isinstance(version, str)
        or not PACKAGE_IDENTITY_VERSION.fullmatch(version)
    ):
        raise ArchiveError("Invalid package identity version")

    if architecture not in {"x86_64", "any"}:
        raise ArchiveError("Unsupported package architecture")

    filename = (
        f"{name}-{version}-{architecture}.pkg.tar.zst"
    )

    if len(filename.encode("ascii")) > 255:
        raise ArchiveError("Package filename exceeds limit")

    return filename


def parse_package_identity(metadata):
    """Parse literal package identity fields without evaluating data."""
    if not isinstance(metadata, str) or not metadata:
        raise ArchiveError("Missing package metadata")

    if len(metadata.encode("utf-8")) > MAX_METADATA_BYTES:
        raise ArchiveError("Package metadata exceeds size limit")

    for character in metadata:
        if (
            unicodedata.category(character) == "Cc"
            and character not in {"\n", "\t"}
        ):
            raise ArchiveError(
                "Control character in package metadata"
            )

    fields = {}

    for line in metadata.split("\n"):
        if not line or line.startswith("#"):
            continue

        key, separator, value = line.partition(" = ")

        if (
            not separator
            or not re.fullmatch(
                r"[a-z][a-z0-9_]*",
                key,
                re.ASCII,
            )
        ):
            raise ArchiveError(
                "Malformed package metadata field"
            )

        if key not in IDENTITY_FIELDS:
            continue

        if key in fields:
            raise ArchiveError(
                f"Duplicate identity field: {key}"
            )

        if not value or value != value.strip():
            raise ArchiveError(
                f"Malformed identity value: {key}"
            )

        fields[key] = value

    missing = IDENTITY_FIELDS - fields.keys()

    if missing:
        raise ArchiveError(
            "Missing package identity fields: "
            + ", ".join(sorted(missing))
        )

    validate_identity_values(
        fields["pkgname"],
        fields["pkgver"],
        fields["arch"],
    )

    return fields


def validate_expected_identity(
    inventory,
    *,
    name,
    version,
    architecture,
    expected_sha256,
):
    """Bind inspected bytes to independently expected identity."""
    filename = validate_identity_values(
        name,
        version,
        architecture,
    )

    if (
        not isinstance(expected_sha256, str)
        or not PACKAGE_DIGEST.fullmatch(expected_sha256)
    ):
        raise ArchiveError(
            "Invalid expected package digest"
        )

    actual = parse_package_identity(
        inventory["metadata"][".PKGINFO"]
    )

    expected = {
        "pkgname": name,
        "pkgver": version,
        "arch": architecture,
    }

    for field in sorted(IDENTITY_FIELDS):
        if actual[field] != expected[field]:
            raise ArchiveError(
                f"Package identity mismatch: {field}"
            )

    if inventory.get("package") != filename:
        raise ArchiveError(
            "Package filename does not match expected identity"
        )

    if inventory.get("sha256") != expected_sha256:
        raise ArchiveError(
            "Package digest does not match protected intake"
        )

    return {
        "pkgname": name,
        "pkgver": version,
        "arch": architecture,
        "filename": filename,
        "sha256": expected_sha256,
    }


def file_digest(source, expected_size, deadline):
    """Hash exactly the original compressed file length."""
    if not 0 < expected_size <= MAX_COMPRESSED_BYTES:
        raise ArchiveError(
            "Compressed package size outside policy"
        )

    remaining_time(deadline)
    source.seek(0)

    result = hashlib.sha256()
    remaining = expected_size

    while remaining:
        remaining_time(deadline)

        chunk = source.read(
            min(remaining, HASH_CHUNK_BYTES)
        )

        remaining_time(deadline)

        if not chunk:
            raise ArchiveError(
                "Package shortened during hashing"
            )

        result.update(chunk)
        remaining -= len(chunk)

    remaining_time(deadline)

    if source.read(1):
        raise ArchiveError(
            "Package grew during hashing"
        )

    remaining_time(deadline)
    source.seek(0)

    return result.hexdigest()


def archive_file_identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def inspect_package(path):
    """Decompress and inspect a package without executing it."""
    require_unprivileged()

    deadline = time.monotonic() + INSPECTION_TIMEOUT

    path = Path(path)

    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
        | os.O_CLOEXEC,
    )

    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())

        if not stat.S_ISREG(info.st_mode):
            raise ArchiveError(
                "Package input must be a regular file"
            )

        if not 0 < info.st_size <= MAX_COMPRESSED_BYTES:
            raise ArchiveError(
                "Compressed package size outside policy"
            )

        original_digest = file_digest(
            source,
            info.st_size,
            deadline,
        )

        if archive_file_identity(info) != archive_file_identity(
            os.fstat(source.fileno())
        ):
            raise ArchiveError(
                "Package changed during initial hashing"
            )

        remaining_time(deadline)

        process = subprocess.Popen(
            [
                "/usr/bin/zstd",
                "-q",
                "-d",
                "-c",
                ZSTD_MEMORY_LIMIT,
            ],
            stdin=source,
            stdout=subprocess.PIPE,
            cwd="/",
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
            },
        )

        try:
            with DeadlinePipeReader(
                process.stdout,
                deadline,
            ) as reader:
                result = inspect_tar_stream(reader)

            try:
                status = process.wait(
                    timeout=remaining_time(deadline)
                )
            except subprocess.TimeoutExpired as error:
                raise ArchiveError(
                    "Package decompressor exit timed out"
                ) from error

            if status != 0:
                raise ArchiveError(
                    "Package decompression failed"
                )

            final_digest = file_digest(
                source,
                info.st_size,
                deadline,
            )
            after = os.fstat(source.fileno())

            if (
                archive_file_identity(info)
                != archive_file_identity(after)
                or original_digest != final_digest
            ):
                raise ArchiveError(
                    "Package changed during inspection"
                )

            result["package"] = path.name
            result["compressed_bytes"] = info.st_size
            result["sha256"] = original_digest

            remaining_time(deadline)

            return result

        finally:
            if process.poll() is None:
                process.kill()

            try:
                process.wait(
                    timeout=PROCESS_CLEANUP_TIMEOUT
                )
            finally:
                process.stdout.close()



def merge_package_members(inventories):
    """Merge installed paths and retain their package ownership."""
    merged = {}
    owners = {}

    for package, inventory in sorted(inventories.items()):
        for name, entry in inventory["entries"].items():
            if name in REQUIRED_METADATA | OPTIONAL_METADATA:
                continue

            previous = merged.get(name)

            if previous is not None:
                if (
                    previous["type"] != "directory"
                    or entry["type"] != "directory"
                ):
                    raise ArchiveError(
                        f"Conflicting package family member: "
                        f"{name!r}, {owners[name]!r}, {package!r}"
                    )

                continue

            merged[name] = entry
            owners[name] = package

    validate_member_relationships(merged)

    return merged, owners


def expected_batch_names(contract, version, checksums):
    """Map trusted expected filenames to approved output identities."""
    allowed = contract.required + contract.optional

    filenames = {
        validate_identity_values(
            name,
            version,
            contract.architecture,
        ): name
        for name in allowed
    }

    if not isinstance(checksums, dict) or not checksums:
        raise ArchiveError(
            "Missing expected candidate checksums"
        )

    names = {}

    for filename, digest in checksums.items():
        if filename not in filenames:
            raise ArchiveError(
                f"Unexpected candidate filename: {filename!r}"
            )

        if (
            not isinstance(digest, str)
            or not PACKAGE_DIGEST.fullmatch(digest)
        ):
            raise ArchiveError(
                f"Invalid candidate checksum: {filename!r}"
            )

        names[filename] = filenames[filename]

    return names


def validate_family_inventories(
    family,
    version,
    inventories,
    expected_checksums,
    *,
    registry,
):
    """Validate inspected candidates against trusted family inputs.

    The registry must be supplied by the trusted pipeline, not
    constructed from candidate-controlled data.

    The inventories must originate from inspect_package().
    This function does not authenticate arbitrary inventory JSON.
    """
    try:
        contract = registry.output_contract(family)
    except ValueError as error:
        raise ArchiveError(str(error)) from error

    expected_names = expected_batch_names(
        contract,
        version,
        expected_checksums,
    )

    try:
        registry.validate_output_names(
            family,
            expected_names.values(),
        )
    except ValueError as error:
        raise ArchiveError(str(error)) from error

    if not isinstance(inventories, dict):
        raise ArchiveError(
            "Invalid candidate inventory collection"
        )

    if set(inventories) != set(expected_names):
        raise ArchiveError(
            "Candidate inventory differs from expected batch"
        )

    verified = {}
    identities = {}

    # Establish all identities before applying link exceptions.
    for filename, name in sorted(expected_names.items()):
        inventory = inventories[filename]

        if inventory.get("structural_inventory_only") is not True:
            raise ArchiveError(
                f"Missing structural inventory: {filename!r}"
            )

        identity = validate_expected_identity(
            inventory,
            name=name,
            version=version,
            architecture=contract.architecture,
            expected_sha256=expected_checksums[filename],
        )

        if name in verified:
            raise ArchiveError(
                f"Duplicate package identity: {name!r}"
            )

        verified[name] = inventory
        identities[name] = identity

    # Reject overlapping installed files or cross-package
    # non-directory ancestors, even when no debug links exist.
    merge_package_members(verified)

    debug_companions = dict(contract.debug_companions)
    results = {}

    for name, inventory in sorted(verified.items()):
        companion_names = debug_companions.get(name, ())
        companion_entries = None
        companion_owners = {}

        if companion_names:
            companions = {}

            for companion in companion_names:
                if companion not in verified:
                    raise ArchiveError(
                        f"Missing approved debug companion: "
                        f"{name!r}, {companion!r}"
                    )

                companions[companion] = verified[companion]

            companion_entries, companion_owners = (
                merge_package_members(companions)
            )

        resolved = validate_symbolic_links(
            name,
            inventory["entries"],
            companion_entries=companion_entries,
        )

        if len(resolved) != inventory["symlink_count"]:
            raise ArchiveError(
                f"Inconsistent symbolic link inventory: {name!r}"
            )

        for record in resolved.values():
            if record["cross_package"]:
                target = record["resolved"]

                if target not in companion_owners:
                    raise ArchiveError(
                        f"Unowned companion link target: {target!r}"
                    )

                record["target_package"] = (
                    companion_owners[target]
                )
            else:
                record["target_package"] = name

        results[name] = {
            "identity": identities[name],
            "member_count": inventory["member_count"],
            "compressed_bytes": inventory["compressed_bytes"],
            "expanded_bytes": inventory["expanded_bytes"],
            "symlink_count": inventory["symlink_count"],
            "entries": inventory["entries"],
            "symbolic_links": resolved,
        }

    return {
        "schema": 1,
        "family": family,
        "version": version,
        "architecture": contract.architecture,
        "structural_and_identity_validation": True,
        "packages": results,
    }


def inspect_family(
    family,
    version,
    paths,
    expected_checksums,
    *,
    registry,
):
    """Inspect actual package files before validating their family."""
    require_unprivileged()

    try:
        contract = registry.output_contract(family)
    except ValueError as error:
        raise ArchiveError(str(error)) from error

    expected_names = expected_batch_names(
        contract,
        version,
        expected_checksums,
    )

    try:
        registry.validate_output_names(
            family,
            expected_names.values(),
        )
    except ValueError as error:
        raise ArchiveError(str(error)) from error

    selected = {}

    for value in paths:
        path = Path(value)

        if path.name in selected:
            raise ArchiveError(
                f"Duplicate candidate filename: {path.name!r}"
            )

        selected[path.name] = path

    if set(selected) != set(expected_names):
        raise ArchiveError(
            "Candidate file inventory differs from expected batch"
        )

    inventories = {}

    for filename, path in sorted(selected.items()):
        inventories[filename] = inspect_package(path)

    return validate_family_inventories(
        family,
        version,
        inventories,
        expected_checksums,
        registry=registry,
    )


MAX_CHECKSUM_MANIFEST_BYTES = 16 * 1024

CHECKSUM_RECORD = re.compile(
    r"([0-9a-f]{64})  "
    r"([a-z][A-Za-z0-9.+_-]*\.pkg\.tar\.zst)",
    re.ASCII,
)


def load_release_registry():
    """Load the sibling contract without altering module search paths."""
    contract_path = Path(__file__).resolve(
        strict=True
    ).with_name("package_release_contract.py")

    if (
        contract_path.is_symlink()
        or not contract_path.is_file()
    ):
        raise ArchiveError(
            "Trusted release contract is unavailable"
        )

    name = "_candidate_archive_release_contract"

    spec = importlib.util.spec_from_file_location(
        name,
        contract_path,
    )

    if spec is None or spec.loader is None:
        raise ArchiveError(
            "Cannot load trusted release contract"
        )

    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module

    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise

    return module


def parse_checksum_manifest(data):
    """Parse exact protected-intake checksum records."""
    if (
        not isinstance(data, bytes)
        or not 0 < len(data) <= MAX_CHECKSUM_MANIFEST_BYTES
    ):
        raise ArchiveError(
            "Checksum manifest size outside policy"
        )

    try:
        content = data.decode("ascii", errors="strict")
    except UnicodeError as error:
        raise ArchiveError(
            "Checksum manifest must be ASCII"
        ) from error

    if not content.endswith("\n"):
        raise ArchiveError(
            "Checksum manifest lacks final newline"
        )

    checksums = {}

    for number, line in enumerate(
        content[:-1].split("\n"),
        1,
    ):
        match = CHECKSUM_RECORD.fullmatch(line)

        if match is None:
            raise ArchiveError(
                f"Malformed checksum record at line {number}"
            )

        digest, filename = match.groups()

        if len(filename.encode("ascii")) > 255:
            raise ArchiveError(
                "Checksum manifest filename exceeds limit"
            )

        if filename in checksums:
            raise ArchiveError(
                f"Duplicate checksum record: {filename!r}"
            )

        checksums[filename] = digest

    return checksums


def read_checksum_manifest(path):
    """Read a bounded regular manifest without following its final link.

    The caller must independently establish protected storage
    and trusted provenance for the checksum manifest.
    """
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
        | os.O_CLOEXEC,
    )

    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())

        if not stat.S_ISREG(before.st_mode):
            raise ArchiveError(
                "Checksum manifest must be a regular file"
            )

        if not (
            0 < before.st_size
            <= MAX_CHECKSUM_MANIFEST_BYTES
        ):
            raise ArchiveError(
                "Checksum manifest size outside policy"
            )

        data = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())

        if (
            len(data) != before.st_size
            or archive_file_identity(before)
            != archive_file_identity(after)
        ):
            raise ArchiveError(
                "Checksum manifest changed during reading"
            )

    return parse_checksum_manifest(data)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Inspect Arch package archives or validate an "
            "exact candidate family against trusted inputs."
        ),
        allow_abbrev=False,
    )

    parser.add_argument(
        "--package",
        help="Structural diagnostic only; not family validation",
    )

    commands = parser.add_subparsers(
        dest="command",
    )

    family = commands.add_parser(
        "validate-family",
        help="Validate an exact candidate family",
        allow_abbrev=False,
    )

    family.add_argument("--family", required=True)
    family.add_argument("--version", required=True)
    family.add_argument("--checksums", required=True)

    family.add_argument(
        "--package",
        dest="packages",
        action="append",
        required=True,
    )

    args = parser.parse_args()

    if args.command is None:
        if args.package is None:
            parser.error(
                "Specify --package or validate-family"
            )
    elif args.package is not None:
        parser.error(
            "Diagnostic --package cannot be combined "
            "with validate-family"
        )

    try:
        require_unprivileged()

        if args.command == "validate-family":
            registry = load_release_registry()

            checksums = read_checksum_manifest(
                args.checksums
            )

            result = inspect_family(
                args.family,
                args.version,
                args.packages,
                checksums,
                registry=registry,
            )
        else:
            result = inspect_package(
                args.package
            )

        json.dump(
            result,
            sys.stdout,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )

        sys.stdout.write("\n")

    except (
        ArchiveError,
        OSError,
        UnicodeError,
        ValueError,
        tarfile.TarError,
        subprocess.SubprocessError,
    ) as error:
        print(
            f"FAIL: {error}",
            file=sys.stderr,
        )

        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
