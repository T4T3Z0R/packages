"""Protected receipt of opaque, independently verified member bytes.

This module must not parse candidate archives or ELF contents.
Expected identities originate exclusively from protected validation
results. Candidate bytes are never executed by this module.
"""

import errno
import hashlib
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import time

from pathlib import Path


MAX_MEMBER_BYTES = 128 * 1024**2
MAX_DIAGNOSTIC_BYTES = 64 * 1024
CHUNK_BYTES = 1024**2

TRANSFER_TIMEOUT = 360
CLEANUP_TIMEOUT = 30

SETPRIV = "/usr/bin/setpriv"
PYTHON = "/usr/bin/python"

ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "HOME": "/tmp",
}

DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)

SAFE_PATH = re.compile(
    r"/[A-Za-z0-9_.+@/-]+",
    re.ASCII,
)

DIRECTORY_FLAGS = (
    os.O_RDONLY
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
    | os.O_CLOEXEC
)

FILE_FLAGS = (
    os.O_RDONLY
    | os.O_NOFOLLOW
    | os.O_NONBLOCK
    | os.O_CLOEXEC
)


class ReceiverError(RuntimeError):
    """Protected member transfer failed."""


def validate_absolute_path(path):
    raw = os.fspath(path)

    if (
        not isinstance(raw, str)
        or len(raw) > 4096
        or SAFE_PATH.fullmatch(raw) is None
        or any(
            part in {"", ".", ".."}
            for part in raw[1:].split("/")
        )
    ):
        raise ReceiverError(
            "Invalid protected filesystem path"
        )

    return raw


def validate_expected_member(size, digest):
    if (
        type(size) is not int
        or not 0 < size <= MAX_MEMBER_BYTES
    ):
        raise ReceiverError(
            "Expected member size outside policy"
        )

    if (
        not isinstance(digest, str)
        or DIGEST.fullmatch(digest) is None
    ):
        raise ReceiverError(
            "Invalid expected member digest"
        )


def validate_inspection_account(uid, gid):
    if (
        type(uid) is not int
        or type(gid) is not int
        or uid <= 0
        or gid <= 0
        or uid >= 2**32 - 1
        or gid >= 2**32 - 1
    ):
        raise ReceiverError(
            "Invalid inspection account"
        )


def require_root():
    if (
        os.getresuid() != (0, 0, 0)
        or os.getresgid() != (0, 0, 0)
    ):
        raise ReceiverError(
            "Protected receiver requires root identity"
        )


def validate_protected_directory(info):
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
    ):
        raise ReceiverError(
            "Unprotected directory ancestor"
        )


def open_protected_directory(path):
    raw = validate_absolute_path(path)

    current = os.open("/", DIRECTORY_FLAGS)

    try:
        validate_protected_directory(
            os.fstat(current)
        )

        for part in raw[1:].split("/"):
            following = os.open(
                part,
                DIRECTORY_FLAGS,
                dir_fd=current,
            )

            os.close(current)
            current = following

            validate_protected_directory(
                os.fstat(current)
            )

        result = current
        current = None

        return result
    finally:
        if current is not None:
            os.close(current)


def file_identity(info):
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


def validate_protected_file(info):
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o7022
        or info.st_nlink != 1
        or info.st_size <= 0
    ):
        raise ReceiverError(
            "Protected input file outside storage policy"
        )


def protected_file_identity(path):
    raw = validate_absolute_path(path)

    parent = str(Path(raw).parent)

    directory = open_protected_directory(parent)

    try:
        descriptor = os.open(
            Path(raw).name,
            FILE_FLAGS,
            dir_fd=directory,
        )

        try:
            info = os.fstat(descriptor)
            validate_protected_file(info)

            current = os.stat(
                Path(raw).name,
                dir_fd=directory,
                follow_symlinks=False,
            )

            if file_identity(info) != file_identity(current):
                raise ReceiverError(
                    "Protected file identity changed"
                )

            return file_identity(info)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def restricted_command(uid, gid, helper, arguments):
    validate_inspection_account(uid, gid)

    helper = validate_absolute_path(helper)

    if Path(helper).name != "candidate_archive.py":
        raise ReceiverError(
            "Unexpected archive helper name"
        )

    return [
        SETPRIV,
        f"--reuid={uid}",
        f"--regid={gid}",
        "--clear-groups",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        PYTHON,
        "-I",
        "-B",
        helper,
        *arguments,
    ]


def remaining_time(deadline):
    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise ReceiverError(
            "Member transfer deadline exceeded"
        )

    return remaining


def remove_access_acl(descriptor):
    try:
        os.removexattr(
            descriptor,
            "system.posix_acl_access",
        )
    except OSError as error:
        if error.errno not in {
            errno.ENODATA,
            errno.ENOTSUP,
        }:
            raise


def observe_reader_exit(process, deadline):
    """Observe child termination without releasing its PID.

    The caller exclusively owns the process lifecycle and must
    terminate its dedicated group before reaping the leader.
    """

    if process.returncode is not None:
        raise ReceiverError(
            "Member reader was prematurely reaped"
        )

    while True:
        remaining = remaining_time(deadline)

        try:
            status = os.waitid(
                os.P_PID,
                process.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError as error:
            raise ReceiverError(
                "Member reader lifecycle ownership lost"
            ) from error

        if status is None:
            time.sleep(min(0.01, remaining))
            continue

        remaining_time(deadline)

        if status.si_pid != process.pid:
            raise ReceiverError(
                "Unexpected member reader process identity"
            )

        if status.si_code == os.CLD_EXITED:
            return status.si_status

        if status.si_code in {
            os.CLD_KILLED,
            os.CLD_DUMPED,
        }:
            return -status.si_status

        raise ReceiverError(
            "Unexpected member reader termination state"
        )


def stop_process_group(process):
    """Terminate the dedicated group before releasing its PID."""

    try:
        if process.returncode is not None:
            raise ReceiverError(
                "Cannot signal a previously reaped reader group"
            )

        try:
            os.waitid(
                os.P_PID,
                process.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError as error:
            raise ReceiverError(
                "Cannot signal an unowned reader group"
            ) from error

        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

        process.wait(timeout=CLEANUP_TIMEOUT)
    finally:
        if process.stdout is not None:
            process.stdout.close()

        if process.stderr is not None:
            process.stderr.close()


def receive_stream(
    process,
    output,
    *,
    expected_size,
    expected_sha256,
    deadline,
):
    """Receive bounded provisional bytes without interpreting them."""

    validate_expected_member(
        expected_size,
        expected_sha256,
    )

    size = 0
    diagnostic_size = 0
    digest = hashlib.sha256()

    with selectors.DefaultSelector() as selector:
        selector.register(
            process.stdout,
            selectors.EVENT_READ,
            "member",
        )

        selector.register(
            process.stderr,
            selectors.EVENT_READ,
            "diagnostics",
        )

        while selector.get_map():
            events = selector.select(
                remaining_time(deadline)
            )

            if not events:
                raise ReceiverError(
                    "Member transfer deadline exceeded"
                )

            for key, _ in events:
                remaining_time(deadline)

                if key.data == "member":
                    limit = min(
                        CHUNK_BYTES,
                        expected_size - size + 1,
                    )
                else:
                    limit = min(
                        CHUNK_BYTES,
                        MAX_DIAGNOSTIC_BYTES
                        - diagnostic_size + 1,
                    )

                data = os.read(key.fd, limit)

                if not data:
                    selector.unregister(key.fileobj)
                    continue

                if key.data == "diagnostics":
                    diagnostic_size += len(data)

                    if diagnostic_size > MAX_DIAGNOSTIC_BYTES:
                        raise ReceiverError(
                            "Reader diagnostics exceed policy"
                        )

                    continue

                size += len(data)

                if size > expected_size:
                    raise ReceiverError(
                        "Member transfer exceeds expected size"
                    )

                if output.write(data) != len(data):
                    raise ReceiverError(
                        "Incomplete provisional member write"
                    )

                digest.update(data)

    status = observe_reader_exit(
        process,
        deadline,
    )

    if status != 0:
        raise ReceiverError(
            f"Restricted member reader failed: {status}"
        )

    if diagnostic_size:
        raise ReceiverError(
            "Unexpected member reader diagnostics"
        )

    if size != expected_size:
        raise ReceiverError(
            "Transferred member size mismatch"
        )

    if digest.hexdigest() != expected_sha256:
        raise ReceiverError(
            "Transferred member digest mismatch"
        )

    remaining_time(deadline)

    return {
        "size": size,
        "sha256": digest.hexdigest(),
    }


def verify_staged_bytes(
    output,
    *,
    expected_size,
    expected_sha256,
    deadline,
):
    """Independently verify the bytes retained by the receiver."""

    validate_expected_member(
        expected_size,
        expected_sha256,
    )

    output.flush()
    os.fsync(output.fileno())

    before = os.fstat(output.fileno())
    validate_protected_file(before)

    if before.st_size != expected_size:
        raise ReceiverError(
            "Staged member size mismatch"
        )

    output.seek(0)

    digest = hashlib.sha256()
    size = 0

    while True:
        remaining_time(deadline)

        data = output.read(
            min(
                CHUNK_BYTES,
                expected_size - size + 1,
            )
        )

        if not data:
            break

        size += len(data)

        if size > expected_size:
            raise ReceiverError(
                "Staged member exceeds expected size"
            )

        digest.update(data)

    after = os.fstat(output.fileno())

    if file_identity(before) != file_identity(after):
        raise ReceiverError(
            "Staged member changed during verification"
        )

    if (
        size != expected_size
        or digest.hexdigest() != expected_sha256
    ):
        raise ReceiverError(
            "Staged member verification failed"
        )

    remaining_time(deadline)

    return {
        "size": size,
        "sha256": digest.hexdigest(),
    }

DESTINATION_NAME = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,254}",
    re.ASCII,
)


def validate_destination_name(name):
    if (
        not isinstance(name, str)
        or DESTINATION_NAME.fullmatch(name) is None
    ):
        raise ReceiverError(
            "Invalid materialized destination name"
        )

    return name


def directory_identity(info):
    return info.st_dev, info.st_ino


def verify_directory_identity(path, descriptor):
    current = open_protected_directory(path)

    try:
        if directory_identity(
            os.fstat(current)
        ) != directory_identity(
            os.fstat(descriptor)
        ):
            raise ReceiverError(
                "Protected destination directory changed"
            )
    finally:
        os.close(current)


def require_absent_destination(directory, name):
    try:
        os.stat(
            name,
            dir_fd=directory,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return

    raise ReceiverError(
        "Materialized destination already exists"
    )


def create_provisional_member(directory):
    name = (
        ".candidate-member-"
        + secrets.token_hex(16)
    )

    descriptor = os.open(
        name,
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC,
        0o600,
        dir_fd=directory,
    )

    try:
        remove_access_acl(descriptor)
        os.fchmod(descriptor, 0o600)

        info = os.fstat(descriptor)

        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != 0
        ):
            raise ReceiverError(
                "Invalid provisional member file"
            )

        return name, descriptor

    except BaseException:
        try:
            os.close(descriptor)
        finally:
            os.unlink(name, dir_fd=directory)

        raise


def materialize_verified_member(
    *,
    uid,
    gid,
    helper,
    package,
    name,
    version,
    architecture,
    archive_sha256,
    member,
    member_size,
    member_sha256,
    destination,
    destination_name,
):
    """Receive an independently selected archive member.

    All expected identities and filesystem locations must come
    from the trusted coordinator and protected validation result.

    This function requires exclusive ownership of its subprocess
    lifecycle and a protected local filesystem. It never parses
    candidate archive or executable contents.
    """

    require_root()

    validate_inspection_account(uid, gid)

    validate_expected_member(
        member_size,
        member_sha256,
    )

    if (
        not isinstance(archive_sha256, str)
        or DIGEST.fullmatch(archive_sha256) is None
    ):
        raise ReceiverError(
            "Invalid expected archive digest"
        )

    helper = validate_absolute_path(helper)
    package = validate_absolute_path(package)
    destination = validate_absolute_path(destination)

    destination_name = validate_destination_name(
        destination_name
    )

    for value in (
        name,
        version,
        architecture,
        member,
    ):
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 4096
            or "\0" in value
        ):
            raise ReceiverError(
                "Invalid expected reader argument"
            )

    command = restricted_command(
        uid,
        gid,
        helper,
        [
            "stream-member",
            "--package=" + package,
            "--name=" + name,
            "--version=" + version,
            "--architecture=" + architecture,
            "--archive-sha256=" + archive_sha256,
            "--member=" + member,
            "--member-size=" + str(member_size),
            "--member-sha256=" + member_sha256,
        ],
    )

    guard = str(
        Path(helper).with_name(
            "candidate_privileges.py"
        )
    )

    protected_inputs = {
        path: protected_file_identity(path)
        for path in (helper, guard, package)
    }

    directory = open_protected_directory(destination)

    provisional = None
    descriptor = None
    published = False
    completed = False

    deadline = time.monotonic() + TRANSFER_TIMEOUT

    try:
        require_absent_destination(
            directory,
            destination_name,
        )

        provisional, descriptor = (
            create_provisional_member(directory)
        )

        output = os.fdopen(descriptor, "w+b")
        descriptor = None

        with output:
            remaining_time(deadline)

            process = subprocess.Popen(
                command,
                cwd="/",
                env=ENVIRONMENT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
            )

            try:
                received = receive_stream(
                    process,
                    output,
                    expected_size=member_size,
                    expected_sha256=member_sha256,
                    deadline=deadline,
                )
            finally:
                stop_process_group(process)

            if process.returncode != 0:
                raise ReceiverError(
                    "Member reader did not terminate successfully"
                )

            retained = verify_staged_bytes(
                output,
                expected_size=member_size,
                expected_sha256=member_sha256,
                deadline=deadline,
            )

            expected = {
                "size": member_size,
                "sha256": member_sha256,
            }

            if received != expected or retained != expected:
                raise ReceiverError(
                    "Member transfer verification disagreement"
                )

            for input_path, identity in protected_inputs.items():
                if protected_file_identity(
                    input_path
                ) != identity:
                    raise ReceiverError(
                        "Protected reader input changed"
                    )

            verify_directory_identity(
                destination,
                directory,
            )

            require_absent_destination(
                directory,
                destination_name,
            )

            before = os.fstat(output.fileno())
            current = os.stat(
                provisional,
                dir_fd=directory,
                follow_symlinks=False,
            )

            if file_identity(before) != file_identity(current):
                raise ReceiverError(
                    "Provisional member path changed"
                )

            os.fchmod(output.fileno(), 0o644)
            os.fsync(output.fileno())

            prepared = os.fstat(output.fileno())

            validate_protected_file(prepared)

            if (
                stat.S_IMODE(prepared.st_mode) != 0o644
                or prepared.st_size != member_size
            ):
                raise ReceiverError(
                    "Materialized member mode or size mismatch"
                )

            remaining_time(deadline)

            os.link(
                provisional,
                destination_name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )

            published = True

            os.unlink(
                provisional,
                dir_fd=directory,
            )

            provisional = None

            final = os.stat(
                destination_name,
                dir_fd=directory,
                follow_symlinks=False,
            )

            validate_protected_file(final)

            if (
                file_identity(final)
                != file_identity(os.fstat(output.fileno()))
                or directory_identity(final)
                != directory_identity(prepared)
                or stat.S_IMODE(final.st_mode) != 0o644
                or final.st_size != member_size
            ):
                raise ReceiverError(
                    "Materialized member identity mismatch"
                )

            verify_directory_identity(
                destination,
                directory,
            )

            os.fsync(directory)

            remaining_time(deadline)

        receipt = {
            "package": package,
            "name": name,
            "version": version,
            "architecture": architecture,
            "archive_sha256": archive_sha256,
            "member": member,
            "size": member_size,
            "sha256": member_sha256,
            "path": str(
                Path(destination) / destination_name
            ),
        }

        completed = True

        return receipt

    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            try:
                if published and not completed:
                    os.unlink(
                        destination_name,
                        dir_fd=directory,
                    )
            finally:
                try:
                    if provisional is not None:
                        os.unlink(
                            provisional,
                            dir_fd=directory,
                        )
                finally:
                    os.close(directory)
