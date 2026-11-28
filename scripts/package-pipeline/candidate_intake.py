"""Transfer builder-controlled package bytes into protected storage."""

import argparse
import errno
import hashlib
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile

from pathlib import Path


MAX_PACKAGE_BYTES = 2 * 1024**3
CHUNK_BYTES = 1024**2
TRANSFER_TIMEOUT = 600

PACKAGE_NAME = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._+@-]*"
    r"\.pkg\.tar\.zst",
    re.ASCII,
)

DIRECTORY_FLAGS = (
    os.O_RDONLY
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
    | os.O_CLOEXEC
)

SOURCE_FLAGS = (
    os.O_RDONLY
    | os.O_NOFOLLOW
    | os.O_NONBLOCK
    | os.O_CLOEXEC
)


class IntakeError(RuntimeError):
    """Candidate intake failed."""


def validate_package_name(name):
    if not PACKAGE_NAME.fullmatch(name):
        raise IntakeError("Invalid package filename")

    if len(os.fsencode(name)) > 255:
        raise IntakeError("Package filename too long")

    return name


def absolute_parts(path):
    raw = os.fspath(path)

    if not raw.startswith("/") or raw.startswith("//"):
        raise IntakeError("Expected absolute filesystem path")

    parts = raw[1:].split("/")

    if any(part in {"", ".", ".."} for part in parts):
        raise IntakeError("Unsafe filesystem path component")

    return parts


def open_directory(path, *, protected=False, builder_uid=None):
    """Open each directory without following symbolic links."""
    parts = absolute_parts(path)
    current = os.open("/", DIRECTORY_FLAGS)

    try:
        for part in parts:
            following = os.open(
                part,
                DIRECTORY_FLAGS,
                dir_fd=current,
            )

            os.close(current)
            current = following

            if protected:
                info = os.fstat(current)

                if info.st_uid == builder_uid:
                    raise IntakeError(
                        "Builder-owned protected directory ancestor"
                    )

                if info.st_mode & 0o022:
                    raise IntakeError(
                        "Writable protected directory ancestor"
                    )

        result = current
        current = None
        return result
    finally:
        if current is not None:
            os.close(current)


def source_identity(info):
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


def validate_source(info, uid):
    if not stat.S_ISREG(info.st_mode):
        raise IntakeError("Candidate source is not regular")

    if info.st_uid != uid:
        raise IntakeError("Candidate source owner mismatch")

    if info.st_nlink != 1:
        raise IntakeError("Candidate source has multiple links")

    if not 0 < info.st_size <= MAX_PACKAGE_BYTES:
        raise IntakeError("Candidate source size outside policy")


def stream_source(source):
    """Read candidate data only under a non-root identity."""
    uid = os.getuid()

    if uid == 0 or os.geteuid() != uid:
        raise IntakeError("Source reader must be unprivileged")

    if (
        os.getgid() == 0
        or os.getegid() == 0
        or 0 in os.getgroups()
    ):
        raise IntakeError("Source reader has privileged group")

    parts = absolute_parts(source)
    validate_package_name(parts[-1])

    directory = "/" + "/".join(parts[:-1])
    parent_fd = open_directory(directory)

    try:
        initial = os.stat(
            parts[-1],
            dir_fd=parent_fd,
            follow_symlinks=False,
        )

        validate_source(initial, uid)

        source_fd = os.open(
            parts[-1],
            SOURCE_FLAGS,
            dir_fd=parent_fd,
        )

        try:
            before = os.fstat(source_fd)
            validate_source(before, uid)

            if source_identity(initial) != source_identity(before):
                raise IntakeError(
                    "Candidate source changed before opening"
                )

            remaining = before.st_size

            while remaining:
                data = os.read(
                    source_fd,
                    min(CHUNK_BYTES, remaining),
                )

                if not data:
                    raise IntakeError(
                        "Candidate source truncated during transfer"
                    )

                sys.stdout.buffer.write(data)
                remaining -= len(data)

            if os.read(source_fd, 1):
                raise IntakeError(
                    "Candidate source grew during transfer"
                )

            after = os.fstat(source_fd)

            if source_identity(before) != source_identity(after):
                raise IntakeError(
                    "Candidate source changed during transfer"
                )

            current = os.stat(
                parts[-1],
                dir_fd=parent_fd,
                follow_symlinks=False,
            )

            if source_identity(after) != source_identity(current):
                raise IntakeError(
                    "Candidate source path changed during transfer"
                )

            sys.stdout.buffer.flush()
        finally:
            os.close(source_fd)
    finally:
        os.close(parent_fd)


def hash_file(path):
    digest = hashlib.sha256()
    size = 0

    with open(path, "rb") as source:
        while data := source.read(CHUNK_BYTES):
            size += len(data)

            if size > MAX_PACKAGE_BYTES:
                raise IntakeError("Staged candidate exceeds limit")

            digest.update(data)

    if size == 0:
        raise IntakeError("Staged candidate is empty")

    return digest.hexdigest(), size


def verify_destination_access(user, destination):
    """Check protected ancestry using the actual builder identity."""
    uid = os.getuid()

    if uid == 0 or os.geteuid() != uid:
        raise IntakeError("Access check must be unprivileged")

    if (
        os.getgid() == 0
        or os.getegid() == 0
        or 0 in os.getgroups()
    ):
        raise IntakeError("Access checker has privileged group")

    current = Path("/")

    for part in absolute_parts(destination):
        current = current / part

        info = current.lstat()

        if not stat.S_ISDIR(info.st_mode):
            raise IntakeError(
                "Protected ancestor is not a real directory"
            )

        if info.st_uid == uid:
            raise IntakeError(
                "Builder owns protected destination ancestor"
            )

        if not os.access(current, os.X_OK):
            raise IntakeError(
                "Protected ancestor is inaccessible"
            )

        if os.access(current, os.W_OK):
            raise IntakeError(
                "Builder can write protected destination ancestor"
            )


def stage_candidate(user, source, destination):
    """Stage package bytes without privileged source-file access."""
    if os.getuid() != 0 or os.geteuid() != 0:
        raise IntakeError("Candidate staging requires root")

    account = pwd.getpwnam(user)

    if account.pw_uid == 0 or account.pw_gid == 0:
        raise IntakeError("Invalid builder identity")

    parts = absolute_parts(source)
    name = validate_package_name(parts[-1])

    absolute_parts(destination)

    destination_fd = open_directory(
        destination,
        protected=True,
        builder_uid=account.pw_uid,
    )

    temporary = None

    try:
        info = os.fstat(destination_fd)

        if info.st_uid != 0 or info.st_mode & 0o022:
            raise IntakeError("Candidate destination is not protected")

        destination_path = Path(destination)
        target = destination_path / name

        if os.path.lexists(target):
            raise IntakeError("Candidate destination already exists")

        helper = Path(__file__).resolve(strict=True)

        groups = os.getgrouplist(
            user,
            account.pw_gid,
        )

        if 0 in groups:
            raise IntakeError(
                "Builder has privileged supplementary group"
            )

        identity_command = [
            "/usr/bin/python3",
            "-I",
            str(helper),
        ]

        identity_options = {
            "user": account.pw_uid,
            "group": account.pw_gid,
            "extra_groups": groups,
            "cwd": "/",
            "env": {
                "HOME": account.pw_dir,
                "USER": user,
                "LOGNAME": user,
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
            },
        }

        subprocess.run(
            identity_command + [
                "check-destination",
                "--destination",
                destination,
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=30,
            **identity_options,
        )

        command = identity_command + [
            "stream",
            "--source",
            source,
        ]

        fd, temporary = tempfile.mkstemp(
            prefix=".candidate-intake-",
            dir=destination_path,
        )

        # Root writes only to its own protected temporary file.
        # Candidate bytes are never interpreted here.
        with os.fdopen(fd, "wb") as output:
            # Remove any inherited access ACL before widening
            # permissions or transferring candidate bytes.
            try:
                os.removexattr(
                    output.fileno(),
                    "system.posix_acl_access",
                )
            except OSError as error:
                if error.errno not in {
                    errno.ENODATA,
                    errno.ENOTSUP,
                }:
                    raise

            os.fchmod(output.fileno(), 0o600)

            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                **identity_options,
            )

            try:
                import selectors
                import time

                deadline = time.monotonic() + TRANSFER_TIMEOUT
                size = 0
                digest = hashlib.sha256()

                with selectors.DefaultSelector() as selector:
                    selector.register(
                        process.stdout,
                        selectors.EVENT_READ,
                    )

                    while True:
                        remaining = deadline - time.monotonic()

                        if remaining <= 0:
                            raise IntakeError(
                                "Candidate transfer timed out"
                            )

                        if not selector.select(remaining):
                            raise IntakeError(
                                "Candidate transfer timed out"
                            )

                        data = os.read(
                            process.stdout.fileno(),
                            CHUNK_BYTES,
                        )

                        if not data:
                            break

                        size += len(data)

                        if size > MAX_PACKAGE_BYTES:
                            raise IntakeError(
                                "Candidate transfer exceeds limit"
                            )

                        output.write(data)
                        digest.update(data)

                remaining = max(
                    0.001,
                    deadline - time.monotonic(),
                )

                if process.wait(timeout=remaining) != 0:
                    raise IntakeError(
                        "Unprivileged candidate reader failed"
                    )

                if not size:
                    raise IntakeError("Empty candidate transfer")

                output.flush()
                os.fsync(output.fileno())

            finally:
                # Popen now owns the direct reader process,
                # rather than a runuser wrapper.
                if process.poll() is None:
                    process.kill()

                try:
                    process.wait(timeout=30)
                finally:
                    process.stdout.close()

        actual_digest, actual_size = hash_file(temporary)

        if (
            actual_digest != digest.hexdigest()
            or actual_size != size
        ):
            raise IntakeError("Staged candidate verification failed")

        check_fd = open_directory(
            destination,
            protected=True,
            builder_uid=account.pw_uid,
        )

        try:
            original = os.fstat(destination_fd)
            current = os.fstat(check_fd)

            if (
                original.st_dev,
                original.st_ino,
            ) != (
                current.st_dev,
                current.st_ino,
            ):
                raise IntakeError(
                    "Protected destination changed during transfer"
                )
        finally:
            os.close(check_fd)

        os.chmod(temporary, 0o644)

        # Hard-link our own protected temporary file into place.
        # Unlike rename, this cannot overwrite an existing target.
        os.link(
            Path(temporary).name,
            name,
            src_dir_fd=destination_fd,
            dst_dir_fd=destination_fd,
            follow_symlinks=False,
        )

        os.unlink(temporary)
        temporary = None

        print(f"{actual_digest}  {name}")

    finally:
        if temporary is not None:
            os.unlink(temporary)

        os.close(destination_fd)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    stream = commands.add_parser("stream")
    stream.add_argument("--source", required=True)

    stage = commands.add_parser("stage")
    stage.add_argument("--user", required=True)
    stage.add_argument("--source", required=True)
    stage.add_argument("--destination", required=True)

    destination_check = commands.add_parser(
        "check-destination"
    )
    destination_check.add_argument(
        "--destination",
        required=True,
    )

    args = parser.parse_args()

    try:
        if args.command == "stream":
            stream_source(args.source)
        elif args.command == "check-destination":
            verify_destination_access(
                os.environ.get("USER", ""),
                args.destination,
            )
        else:
            stage_candidate(
                args.user,
                args.source,
                args.destination,
            )
    except (
        IntakeError,
        OSError,
        KeyError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
