"""Inspect generated GameShell archives without executing or extracting them."""

import argparse
import gzip
import hashlib
import io
import os
import stat
import sys
import tarfile

from pathlib import Path, PurePosixPath


MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 50_000
MAX_HEADER_BYTES = 1024 * 1024


def read_generated_file(directory_fd, name):
    """Read a bounded regular file from an open output directory."""

    if name not in ("gameshell.sh", "gameshell.tgz"):
        raise ValueError("Unexpected generated filename")

    descriptor = os.open(
        name,
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
        | os.O_CLOEXEC,
        dir_fd=directory_fd,
    )

    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())

        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Generated output is not a regular file")

        if before.st_nlink != 1:
            raise ValueError("Generated output has multiple hard links")

        if not 0 < before.st_size <= MAX_ARCHIVE_BYTES:
            raise ValueError("Generated output has invalid size")

        content = source.read(MAX_ARCHIVE_BYTES + 1)

        after = os.fstat(source.fileno())

        if (
            len(content) != before.st_size
            or len(content) > MAX_ARCHIVE_BYTES
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise ValueError("Generated output changed during intake")

        return content


def verify_member_relationships(members):
    """Reject unsafe archive ancestry and restrict mission symlinks."""

    for name, member in members.items():
        path = PurePosixPath(name)

        # Implicit directories are permitted, but an explicitly
        # represented ancestor must be a real directory.
        for ancestor in path.parents:
            parent = members.get(str(ancestor))

            if parent is not None and not parent.isdir():
                raise ValueError(
                    f"Archive member has non-directory ancestor: {name}"
                )

        if not member.issym():
            continue

        # Match the selected upstream layout:
        # gameshell/missions/group/mission/asset
        if (
            len(path.parts) != 5
            or path.parts[:2] != ("gameshell", "missions")
        ):
            raise ValueError(
                f"Unsupported archive symbolic link location: {name}"
            )

        raw_target = member.linkname
        target_parts = PurePosixPath(raw_target).parts

        if (
            not raw_target
            or any(ord(character) < 32 for character in raw_target)
            or "\\" in raw_target
            or len(target_parts) != 3
            or target_parts[0] != ".."
            or target_parts[1] in (".", "..")
            or target_parts[2] in (".", "..")
            or raw_target != "/".join(target_parts)
        ):
            raise ValueError(
                f"Invalid archive mission link target: {name}"
            )

        target = (
            path.parent.parent
            / target_parts[1]
            / target_parts[2]
        )

        target_member = members.get(str(target))

        if target_member is None:
            raise ValueError(
                f"Missing archive mission link target: {name}"
            )

        if not (
            target_member.isfile()
            or target_member.isdir()
        ):
            raise ValueError(
                f"Archive mission link target is not direct: {name}"
            )

        for ancestor in target.parents:
            parent = members.get(str(ancestor))

            if parent is not None and not parent.isdir():
                raise ValueError(
                    f"Archive mission link has unsafe target ancestry: {name}"
                )


def inspect_payload(payload, expected_header=None):
    """Validate expected archive structure without filesystem extraction."""

    names = set()
    members = {}
    regular_files = set()
    expanded_size = 0

    if not 0 < len(payload) <= MAX_ARCHIVE_BYTES:
        raise ValueError("Compressed archive exceeds size limit")

    # Bound the entire decompressed stream, including tar headers,
    # padding and extended metadata, not just regular-file contents.
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as compressed:
        expanded = compressed.read(MAX_EXPANDED_BYTES + 1)

    if len(expanded) > MAX_EXPANDED_BYTES:
        raise ValueError("Expanded archive exceeds size limit")

    with tarfile.open(
        fileobj=io.BytesIO(expanded),
        mode="r:",
    ) as archive:
        for member in archive:
            name = member.name

            if (
                not name
                or any(ord(character) < 32 for character in name)
                or "\\" in name
            ):
                raise ValueError("Invalid archive member name")

            path = PurePosixPath(name)

            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or path.parts[0] != "gameshell"
            ):
                raise ValueError("Archive member escapes expected tree")

            normalized = str(path)

            if normalized in names:
                raise ValueError("Duplicate archive member")

            names.add(normalized)
            members[normalized] = member

            if len(names) > MAX_MEMBERS:
                raise ValueError("Too many archive members")

            if not (
                member.isfile()
                or member.isdir()
                or member.issym()
            ):
                raise ValueError("Unsupported archive member type")

            if member.sparse is not None:
                raise ValueError("Unsupported sparse archive member")

            if member.size < 0:
                raise ValueError("Invalid archive member size")

            if not member.isfile() and member.size != 0:
                raise ValueError("Invalid non-regular archive member size")

            if member.mode & 0o7000:
                raise ValueError("Unexpected special permission bits")

            if member.isfile():
                expanded_size += member.size

                if expanded_size > MAX_EXPANDED_BYTES:
                    raise ValueError("Expanded archive exceeds size limit")

                regular_files.add(normalized)

        verify_member_relationships(members)

        if expected_header is not None:
            header = members.get("gameshell/lib/header.sh")

            if header is None or not header.isfile():
                raise ValueError("Required embedded header missing")

            if not 0 < header.size <= MAX_HEADER_BYTES:
                raise ValueError("Invalid embedded header size")

            with archive.extractfile(header) as source:
                embedded_header = source.read(MAX_HEADER_BYTES + 1)

            if embedded_header != expected_header:
                raise ValueError(
                    "Standalone and embedded headers differ"
                )

    required = {
        "gameshell/start.sh",
        "gameshell/lib/profile.sh",
        "gameshell/lib/header.sh",
        "gameshell/missions/default.idx",
    }

    if not required.issubset(regular_files):
        raise ValueError("Required GameShell archive files missing")

    if not any(
        name.startswith("gameshell/scripts/")
        for name in regular_files
    ):
        raise ValueError("Required GameShell scripts missing")

    # The mandatory default.idx is an index, not mission content.
    # Require a regular file below an actual mission subdirectory.
    if not any(
        name.startswith("gameshell/missions/")
        and len(PurePosixPath(name).parts) >= 4
        for name in regular_files
    ):
        raise ValueError("Required GameShell mission content missing")

    return sorted(names)


def validate_archive(standalone, payload):
    """Check the standalone script contains exactly the retained payload."""

    if not 0 < len(standalone) <= MAX_ARCHIVE_BYTES:
        raise ValueError("Standalone archive exceeds size limit")

    if not standalone.startswith(b"#!"):
        raise ValueError("Missing standalone shell header")

    if not payload.startswith(b"\x1f\x8b"):
        raise ValueError("Missing compressed archive signature")

    if not standalone.endswith(payload):
        raise ValueError("Standalone archive payload mismatch")

    header_size = len(standalone) - len(payload)

    if not 0 < header_size <= MAX_HEADER_BYTES:
        raise ValueError("Invalid standalone header size")

    return inspect_payload(
        payload,
        expected_header=standalone[:header_size],
    )


def write_new_file(path, content, mode=0o644):
    """Create a fresh protected output without following a symlink."""

    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC,
        mode,
    )

    with os.fdopen(descriptor, "wb") as output:
        output.write(content)


def intake(generated, destination, evidence):
    """Validate generated bytes, then stage the accepted standalone file."""

    for directory in (destination, evidence):
        metadata = directory.lstat()

        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
        ):
            raise ValueError("Output directory is not protected")

    directory_fd = os.open(
        generated,
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC,
    )

    try:
        standalone = read_generated_file(
            directory_fd, "gameshell.sh"
        )

        payload = read_generated_file(
            directory_fd, "gameshell.tgz"
        )
    finally:
        os.close(directory_fd)

    inventory = validate_archive(standalone, payload)

    write_new_file(
        destination / "gameshell.sh",
        standalone,
        0o755,
    )

    write_new_file(
        evidence / "game-archive-files.txt",
        ("\n".join(inventory) + "\n").encode("utf-8"),
    )

    write_new_file(
        evidence / "gameshell.tgz",
        payload,
    )

    write_new_file(
        evidence / "game-payload-SHA256SUMS",
        (
            hashlib.sha256(payload).hexdigest()
            + "  gameshell.tgz\n"
        ).encode("ascii"),
    )

    print(f"PASS: Validated {len(inventory)} archive members.")
    print("PASS: Standalone archive matches retained payload.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    for argument in (
        "generated",
        "destination",
        "evidence",
    ):
        parser.add_argument(
            "--" + argument,
            type=Path,
            required=True,
        )

    args = parser.parse_args()

    try:
        intake(
            args.generated,
            args.destination,
            args.evidence,
        )
    except (
        OSError,
        ValueError,
        EOFError,
        tarfile.TarError,
    ) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
