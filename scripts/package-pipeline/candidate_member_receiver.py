"""Protected receipt of opaque, independently verified member bytes.

This module must not parse candidate archives or ELF contents.
Expected identities originate exclusively from protected validation
results. Candidate bytes are never executed by this module.
"""

import errno
import hashlib
import json
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

LINKAGE_TIMEOUT = 90
MAX_LINKAGE_RECEIPT_BYTES = 1024**2
MAX_LINKAGE_JSON_DEPTH = 8

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


def protected_helper_identities(helper, dependencies):
    """Establish identities for a protected helper and its dependencies.

    The helper directory must contain trusted source files and no
    Python bytecode cache directory. The caller must exclusively
    control provisioning of this directory.
    """

    helper = validate_absolute_path(helper)
    parent = Path(helper).parent

    directory = open_protected_directory(parent)

    try:
        try:
            os.stat(
                "__pycache__",
                dir_fd=directory,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise ReceiverError(
                "Protected helper bytecode cache is forbidden"
            )

        paths = [helper]

        for name in dependencies:
            if (
                not isinstance(name, str)
                or Path(name).name != name
                or not name.endswith(".py")
                or name.startswith(".")
            ):
                raise ReceiverError(
                    "Invalid protected helper dependency"
                )

            paths.append(str(parent / name))

        if len(set(paths)) != len(paths):
            raise ReceiverError(
                "Duplicate protected helper dependency"
            )

        identities = {
            path: protected_file_identity(path)
            for path in paths
        }

        verify_directory_identity(
            parent,
            directory,
        )

        return identities

    finally:
        os.close(directory)


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

    dependencies = (
        "candidate_privileges.py",
        "package_release_contract.py",
    )

    protected_helpers = protected_helper_identities(
        helper,
        dependencies,
    )

    protected_package = protected_file_identity(
        package
    )

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

            if (
                protected_helper_identities(
                    helper,
                    dependencies,
                ) != protected_helpers
                or protected_file_identity(
                    package
                ) != protected_package
            ):
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

def restricted_linkage_command(
    uid,
    gid,
    helper,
    executable,
    expected_size,
    expected_sha256,
):
    """Construct the restricted, identity-bound ELF inspector command."""

    validate_inspection_account(uid, gid)

    helper = validate_absolute_path(helper)
    executable = validate_absolute_path(executable)

    validate_expected_member(
        expected_size,
        expected_sha256,
    )

    if Path(helper).name != "candidate_linkage.py":
        raise ReceiverError(
            "Unexpected linkage helper name"
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
        "--path=" + executable,
        "--expected-size=" + str(expected_size),
        "--expected-sha256=" + expected_sha256,
    ]


def receive_linkage_receipt(process, *, deadline):
    """Receive bounded provisional JSON bytes from a restricted reader.

    The caller exclusively owns the process lifecycle and must
    stop its dedicated process group before accepting any result.
    """

    output = bytearray()
    diagnostic_size = 0

    with selectors.DefaultSelector() as selector:
        selector.register(
            process.stdout,
            selectors.EVENT_READ,
            "receipt",
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
                    "Linkage receipt deadline exceeded"
                )

            for key, _ in events:
                remaining_time(deadline)

                if key.data == "receipt":
                    limit = min(
                        CHUNK_BYTES,
                        MAX_LINKAGE_RECEIPT_BYTES
                        - len(output) + 1,
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

                    if (
                        diagnostic_size
                        > MAX_DIAGNOSTIC_BYTES
                    ):
                        raise ReceiverError(
                            "Linkage diagnostics exceed policy"
                        )

                    continue

                if (
                    len(output) + len(data)
                    > MAX_LINKAGE_RECEIPT_BYTES
                ):
                    raise ReceiverError(
                        "Linkage receipt exceeds size policy"
                    )

                output.extend(data)

    status = observe_reader_exit(
        process,
        deadline,
    )

    if status != 0:
        raise ReceiverError(
            f"Restricted linkage inspector failed: {status}"
        )

    if diagnostic_size:
        raise ReceiverError(
            "Unexpected linkage inspector diagnostics"
        )

    if not output:
        raise ReceiverError(
            "Empty linkage inspection receipt"
        )

    remaining_time(deadline)

    return bytes(output)


def reject_duplicate_json_keys(pairs):
    result = {}

    for name, value in pairs:
        if name in result:
            raise ReceiverError(
                "Duplicate linkage receipt field"
            )

        result[name] = value

    return result


def reject_json_constant(value):
    raise ReceiverError(
        "Nonstandard linkage JSON constant"
    )


def reject_json_float(value):
    raise ReceiverError(
        "Floating-point linkage JSON value"
    )


def parse_bounded_json_integer(value):
    if len(value) > 20:
        raise ReceiverError(
            "Linkage JSON integer exceeds policy"
        )

    return int(value)


def validate_linkage_json_depth(data):
    """Bound JSON nesting before invoking the decoder."""

    depth = 0
    quoted = False
    escaped = False

    for value in data:
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False

            continue

        if value == 34:
            quoted = True

        elif value in (123, 91):
            depth += 1

            if depth > MAX_LINKAGE_JSON_DEPTH:
                raise ReceiverError(
                    "Linkage JSON nesting exceeds policy"
                )

        elif value in (125, 93):
            depth -= 1

            if depth < 0:
                raise ReceiverError(
                    "Invalid linkage JSON nesting"
                )

    if depth != 0 or quoted or escaped:
        raise ReceiverError(
            "Incomplete linkage JSON structure"
        )


def decode_linkage_receipt(data):
    """Decode a bounded receipt without accepting ambiguous JSON.

    This is a transport decoder, not the final linkage evidence
    schema validator. A decoded result is not acceptance evidence.
    """

    if (
        not isinstance(data, bytes)
        or not 0 < len(data) <= MAX_LINKAGE_RECEIPT_BYTES
    ):
        raise ReceiverError(
            "Linkage receipt outside size policy"
        )

    if (
        not data.endswith(b"\n")
        or data.count(b"\n") != 1
        or b"\r" in data
    ):
        raise ReceiverError(
            "Unexpected linkage receipt framing"
        )

    validate_linkage_json_depth(data)

    try:
        result = json.loads(
            data.decode("ascii", errors="strict"),
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=reject_json_constant,
            parse_float=reject_json_float,
            parse_int=parse_bounded_json_integer,
        )

    except (ValueError, RecursionError) as error:
        raise ReceiverError(
            "Invalid linkage JSON receipt"
        ) from error

    if not isinstance(result, dict):
        raise ReceiverError(
            "Linkage receipt must be a JSON object"
        )

    return result

def verify_materialized_identity(
    path,
    *,
    expected_size,
    expected_sha256,
    deadline,
):
    """Verify protected materialized bytes without interpreting ELF."""

    path = validate_absolute_path(path)

    validate_expected_member(
        expected_size,
        expected_sha256,
    )

    parent = Path(path).parent

    directory = open_protected_directory(parent)

    try:
        descriptor = os.open(
            Path(path).name,
            FILE_FLAGS,
            dir_fd=directory,
        )

        try:
            before = os.fstat(descriptor)

            validate_protected_file(before)

            if (
                stat.S_IMODE(before.st_mode) != 0o644
                or before.st_size != expected_size
            ):
                raise ReceiverError(
                    "Materialized linkage input size or mode mismatch"
                )

            digest = hashlib.sha256()
            total = 0

            while total < expected_size:
                remaining_time(deadline)

                data = os.read(
                    descriptor,
                    min(
                        CHUNK_BYTES,
                        expected_size - total,
                    ),
                )

                if not data:
                    raise ReceiverError(
                        "Truncated materialized linkage input"
                    )

                total += len(data)
                digest.update(data)

            if os.read(descriptor, 1):
                raise ReceiverError(
                    "Materialized linkage input grew"
                )

            if (
                total != expected_size
                or digest.hexdigest() != expected_sha256
            ):
                raise ReceiverError(
                    "Materialized linkage input digest mismatch"
                )

            current = os.stat(
                Path(path).name,
                dir_fd=directory,
                follow_symlinks=False,
            )

            identity = file_identity(before)

            if (
                file_identity(os.fstat(descriptor))
                != identity
                or file_identity(current) != identity
            ):
                raise ReceiverError(
                    "Materialized linkage input changed"
                )

            verify_directory_identity(
                parent,
                directory,
            )

            remaining_time(deadline)

            return identity

        finally:
            os.close(descriptor)

    finally:
        os.close(directory)


def inspect_materialized_member(
    *,
    uid,
    gid,
    helper,
    executable,
    expected_size,
    expected_sha256,
    receipt_validator,
):
    """Collect identity-bound evidence from the restricted inspector.

    The validator must be supplied by trusted pipeline code.
    This function accepts neither an arbitrary command nor
    candidate-supplied validation logic.

    The caller must provision and exclusively control the
    protected helper and materialized member directories.
    """

    require_root()

    if not callable(receipt_validator):
        raise ReceiverError(
            "Trusted linkage receipt validator required"
        )

    helper = validate_absolute_path(helper)
    executable = validate_absolute_path(executable)

    command = restricted_linkage_command(
        uid,
        gid,
        helper,
        executable,
        expected_size,
        expected_sha256,
    )

    dependencies = (
        "candidate_privileges.py",
    )

    deadline = (
        time.monotonic() + LINKAGE_TIMEOUT
    )

    protected_helpers = protected_helper_identities(
        helper,
        dependencies,
    )

    protected_executable = verify_materialized_identity(
        executable,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
        deadline=deadline,
    )

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
        data = receive_linkage_receipt(
            process,
            deadline=deadline,
        )

    finally:
        stop_process_group(process)

    if process.returncode != 0:
        raise ReceiverError(
            "Linkage inspector did not terminate successfully"
        )

    remaining_time(deadline)

    if protected_helper_identities(
        helper,
        dependencies,
    ) != protected_helpers:
        raise ReceiverError(
            "Protected linkage helper changed"
        )

    if verify_materialized_identity(
        executable,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
        deadline=deadline,
    ) != protected_executable:
        raise ReceiverError(
            "Protected linkage input changed"
        )

    receipt = decode_linkage_receipt(data)

    result = receipt_validator(
        receipt,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
    )

    if (
        type(result) is not dict
        or type(result.get("schema")) is not int
        or result["schema"] != 1
        or result.get("static_linkage_validation")
            is not True
        or result.get("sha256") != expected_sha256
    ):
        raise ReceiverError(
            "Validated linkage receipt identity disagreement"
        )

    remaining_time(deadline)

    return result

MAX_FAMILY_ARCHIVES = 64
MAX_FAMILY_REQUESTS = 64
MAX_FAMILY_MANIFEST_BYTES = 16 * 1024
FAMILY_ARCHIVE_TIMEOUT = 360


def restricted_family_command(
    *,
    uid,
    gid,
    helper,
    family,
    version,
    checksums,
    packages,
    requests,
):
    """Construct the exact restricted family inspection command.

    Package identities and member selection must originate from
    trusted release policy, not from candidate-reported evidence.
    """

    for value in (family, version):
        if (
            not isinstance(value, str)
            or not 0 < len(value) <= 255
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.+:-]*",
                value,
                re.ASCII,
            ) is None
        ):
            raise ReceiverError(
                "Invalid expected family identity"
            )

    checksums = validate_absolute_path(checksums)

    if (
        type(packages) is not dict
        or not 0 < len(packages) <= MAX_FAMILY_ARCHIVES
    ):
        raise ReceiverError(
            "Family package inventory outside policy"
        )

    normalized = {}

    for filename, package in packages.items():
        package = validate_absolute_path(package)

        if (
            not isinstance(filename, str)
            or Path(package).name != filename
            or not filename.endswith(".pkg.tar.zst")
            or filename.startswith("-")
        ):
            raise ReceiverError(
                "Invalid expected family package path"
            )

        normalized[filename] = package

    if checksums in normalized.values():
        raise ReceiverError(
            "Checksum manifest overlaps package input"
        )

    if (
        type(requests) is not dict
        or not set(requests) <= normalized.keys()
    ):
        raise ReceiverError(
            "Unexpected family member request inventory"
        )

    arguments = [
        "validate-family",
        "--restricted-receipt",
        "--family=" + family,
        "--version=" + version,
        "--checksums=" + checksums,
    ]

    for filename in sorted(normalized):
        arguments.append(
            "--package=" + normalized[filename]
        )

    total = 0

    for filename, members in sorted(requests.items()):
        if (
            type(members) is not tuple
            or not members
        ):
            raise ReceiverError(
                "Invalid family member request collection"
            )

        seen = set()

        for member in members:
            if (
                not isinstance(member, str)
                or not 0 < len(member) <= 4096
                or member.startswith("-")
                or re.fullmatch(
                    r"[A-Za-z0-9_.+@/-]+",
                    member,
                    re.ASCII,
                ) is None
                or any(
                    component in {"", ".", ".."}
                    for component in member.split("/")
                )
            ):
                raise ReceiverError(
                    "Invalid family member request path"
                )

            if member in seen:
                raise ReceiverError(
                    "Duplicate family member request"
                )

            seen.add(member)

            total += 1

            if total > MAX_FAMILY_REQUESTS:
                raise ReceiverError(
                    "Family member request count exceeds policy"
                )

        for member in sorted(seen):
            arguments.extend([
                "--select-member",
                filename,
                member,
            ])

    return restricted_command(
        uid,
        gid,
        helper,
        arguments,
    )


def inspect_protected_family(
    *,
    uid,
    gid,
    helper,
    family,
    version,
    architecture,
    checksums,
    packages,
    expected_names,
    expected_checksums,
    request_builder,
    evidence_binder,
    manifest_reader,
):
    """Acquire a restricted family receipt and bind its member plan.

    The expected identities, checksums and policy callbacks must
    originate from trusted pipeline code.

    The caller must exclusively control protected storage and
    provision trusted helper source files before invoking this
    operation.
    """

    require_root()

    if not all(
        callable(callback)
        for callback in (
            request_builder,
            evidence_binder,
            manifest_reader,
        )
    ):
        raise ReceiverError(
            "Trusted family policy callbacks required"
        )

    if (
        type(packages) is not dict
        or type(expected_names) is not dict
        or type(expected_checksums) is not dict
        or not packages
        or set(packages) != set(expected_names)
        or set(packages) != set(expected_checksums)
    ):
        raise ReceiverError(
            "Expected family input inventory mismatch"
        )

    packages = dict(packages)
    expected_names = dict(expected_names)
    expected_checksums = dict(expected_checksums)

    for digest in expected_checksums.values():
        if (
            not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
        ):
            raise ReceiverError(
                "Invalid expected family archive digest"
            )

    if architecture not in ("x86_64", "any"):
        raise ReceiverError(
            "Unexpected family architecture"
        )

    helper = validate_absolute_path(helper)
    checksums = validate_absolute_path(checksums)

    requests = request_builder(expected_names)

    command = restricted_family_command(
        uid=uid,
        gid=gid,
        helper=helper,
        family=family,
        version=version,
        checksums=checksums,
        packages=packages,
        requests=requests,
    )

    dependencies = (
        "candidate_privileges.py",
        "package_release_contract.py",
    )

    deadline = (
        time.monotonic()
        + len(packages) * FAMILY_ARCHIVE_TIMEOUT
    )

    helpers = protected_helper_identities(
        helper,
        dependencies,
    )

    manifest_identity = protected_file_identity(
        checksums
    )

    # file_identity includes the stat size at index 6.
    if not (
        0 < manifest_identity[6]
        <= MAX_FAMILY_MANIFEST_BYTES
    ):
        raise ReceiverError(
            "Protected checksum manifest outside size policy"
        )

    archive_identities = {
        filename: protected_file_identity(
            package
        )
        for filename, package in sorted(
            packages.items()
        )
    }

    if manifest_reader(checksums) != expected_checksums:
        raise ReceiverError(
            "Protected checksum manifest disagreement"
        )

    if (
        protected_file_identity(checksums)
        != manifest_identity
    ):
        raise ReceiverError(
            "Protected checksum manifest changed"
        )

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
        data = receive_linkage_receipt(
            process,
            deadline=deadline,
        )

    finally:
        stop_process_group(process)

    if process.returncode != 0:
        raise ReceiverError(
            "Family inspector did not terminate successfully"
        )

    remaining_time(deadline)

    if protected_helper_identities(
        helper,
        dependencies,
    ) != helpers:
        raise ReceiverError(
            "Protected family helper changed"
        )

    if (
        protected_file_identity(checksums)
        != manifest_identity
        or manifest_reader(checksums)
        != expected_checksums
        or protected_file_identity(checksums)
        != manifest_identity
    ):
        raise ReceiverError(
            "Protected checksum manifest changed"
        )

    for filename, package in sorted(
        packages.items()
    ):
        if (
            protected_file_identity(package)
            != archive_identities[filename]
        ):
            raise ReceiverError(
                "Protected family archive changed"
            )

    receipt = decode_linkage_receipt(data)

    if set(receipt) != {
        "schema",
        "family",
        "version",
        "architecture",
        "structural_and_identity_validation",
        "packages",
    }:
        raise ReceiverError(
            "Unexpected compact family receipt fields"
        )

    if type(receipt["packages"]) is not dict:
        raise ReceiverError(
            "Invalid compact family package collection"
        )

    if set(receipt["packages"]) != set(
        expected_names.values()
    ):
        raise ReceiverError(
            "Compact family package inventory mismatch"
        )

    for filename, name in expected_names.items():
        package = receipt["packages"][name]

        required = requests.get(filename, ())

        fields = {"identity"}

        if required:
            fields.update({
                "entries",
                "selected_members",
            })

        if (
            type(package) is not dict
            or set(package) != fields
        ):
            raise ReceiverError(
                "Unexpected compact package receipt fields"
            )

        if required:
            if (
                type(package["entries"]) is not dict
                or set(package["entries"])
                != set(required)
            ):
                raise ReceiverError(
                    "Unexpected compact member inventory"
                )

            for entry in package["entries"].values():
                if (
                    type(entry) is not dict
                    or set(entry) != {"type", "size"}
                ):
                    raise ReceiverError(
                        "Unexpected compact member fields"
                    )

    plan = evidence_binder(
        receipt,
        expected_names=expected_names,
        expected_checksums=expected_checksums,
        family=family,
        version=version,
        architecture=architecture,
    )

    expected_members = [
        (filename, member)
        for filename in sorted(requests)
        for member in sorted(requests[filename])
    ]

    if (
        type(plan) is not list
        or len(plan) != len(expected_members)
        or any(
            type(record) is not dict
            or set(record) != {
                "name",
                "version",
                "architecture",
                "filename",
                "archive_sha256",
                "member",
                "size",
                "sha256",
            }
            for record in plan
        )
        or [
            (record["filename"], record["member"])
            for record in plan
        ] != expected_members
    ):
        raise ReceiverError(
            "Bound family member plan disagreement"
        )

    for record in plan:
        filename = record["filename"]

        if (
            record["name"] != expected_names[filename]
            or record["version"] != version
            or record["architecture"] != architecture
            or record["archive_sha256"]
                != expected_checksums[filename]
        ):
            raise ReceiverError(
                "Bound family archive identity disagreement"
            )

        validate_expected_member(
            record["size"],
            record["sha256"],
        )

    remaining_time(deadline)

    return {
        "archive_receipt": receipt,
        "member_plan": plan,
    }


def validate_combined_family(
    *,
    uid,
    gid,
    archive_helper,
    linkage_helper,
    family,
    version,
    architecture,
    checksums,
    packages,
    expected_names,
    expected_checksums,
    workspace,
    request_builder,
    evidence_binder,
    manifest_reader,
    receipt_validator,
):
    """Validate a complete family and all policy-required executables.

    Candidate archives and materialized members are never executed.

    Trusted pipeline code must supply the expected release identities,
    protected intake checksums, policy callbacks and exclusively
    controlled protected storage.

    No combined evidence is returned until all required inspections,
    protected input revalidation and temporary file cleanup succeed.
    """

    require_root()

    validate_inspection_account(uid, gid)

    if not all(
        callable(callback)
        for callback in (
            request_builder,
            evidence_binder,
            manifest_reader,
            receipt_validator,
        )
    ):
        raise ReceiverError(
            "Trusted combined family policy callbacks required"
        )

    if (
        type(packages) is not dict
        or type(expected_names) is not dict
        or type(expected_checksums) is not dict
        or not 0 < len(packages) <= MAX_FAMILY_ARCHIVES
        or set(packages) != set(expected_names)
        or set(packages) != set(expected_checksums)
    ):
        raise ReceiverError(
            "Combined family input inventory mismatch"
        )

    packages = {
        filename: validate_absolute_path(package)
        for filename, package in packages.items()
    }

    expected_names = dict(expected_names)
    expected_checksums = dict(expected_checksums)

    archive_helper = validate_absolute_path(
        archive_helper
    )

    linkage_helper = validate_absolute_path(
        linkage_helper
    )

    checksums = validate_absolute_path(checksums)
    workspace = validate_absolute_path(workspace)

    if (
        Path(archive_helper).name != "candidate_archive.py"
        or Path(linkage_helper).name != "candidate_linkage.py"
    ):
        raise ReceiverError(
            "Unexpected combined family helper name"
        )

    requests = request_builder(expected_names)

    # Validate command inputs before establishing any
    # provisional materialization workspace.
    restricted_family_command(
        uid=uid,
        gid=gid,
        helper=archive_helper,
        family=family,
        version=version,
        checksums=checksums,
        packages=packages,
        requests=requests,
    )

    archive_dependencies = (
        "candidate_privileges.py",
        "package_release_contract.py",
    )

    linkage_dependencies = (
        "candidate_privileges.py",
    )

    initial_archive_helpers = protected_helper_identities(
        archive_helper,
        archive_dependencies,
    )

    initial_linkage_helpers = None

    if requests:
        initial_linkage_helpers = (
            protected_helper_identities(
                linkage_helper,
                linkage_dependencies,
            )
        )

    initial_manifest = protected_file_identity(
        checksums
    )

    initial_archives = {
        filename: protected_file_identity(package)
        for filename, package in sorted(
            packages.items()
        )
    }

    def verify_inputs():
        if protected_helper_identities(
            archive_helper,
            archive_dependencies,
        ) != initial_archive_helpers:
            raise ReceiverError(
                "Combined family archive helper changed"
            )

        if requests and protected_helper_identities(
            linkage_helper,
            linkage_dependencies,
        ) != initial_linkage_helpers:
            raise ReceiverError(
                "Combined family linkage helper changed"
            )

        if (
            protected_file_identity(checksums)
            != initial_manifest
        ):
            raise ReceiverError(
                "Combined family checksum manifest changed"
            )

        for filename, package in sorted(
            packages.items()
        ):
            if (
                protected_file_identity(package)
                != initial_archives[filename]
            ):
                raise ReceiverError(
                    "Combined family archive identity changed"
                )

    acquired = inspect_protected_family(
        uid=uid,
        gid=gid,
        helper=archive_helper,
        family=family,
        version=version,
        architecture=architecture,
        checksums=checksums,
        packages=packages,
        expected_names=expected_names,
        expected_checksums=expected_checksums,
        request_builder=request_builder,
        evidence_binder=evidence_binder,
        manifest_reader=manifest_reader,
    )

    verify_inputs()

    archive_receipt = acquired["archive_receipt"]
    plan = acquired["member_plan"]

    expected_members = [
        (filename, member)
        for filename in sorted(requests)
        for member in sorted(requests[filename])
    ]

    if [
        (record["filename"], record["member"])
        for record in plan
    ] != expected_members:
        raise ReceiverError(
            "Combined family member inventory disagreement"
        )

    # Independently compare the bound plan with the selected
    # member records before accepting materialization inputs.
    for record in plan:
        selected = archive_receipt["packages"][
            record["name"]
        ]["selected_members"][record["member"]]

        if selected != {
            "size": record["size"],
            "sha256": record["sha256"],
        }:
            raise ReceiverError(
                "Combined family member evidence disagreement"
            )

    evidence = []

    if plan:
        parent = open_protected_directory(workspace)

        directory_name = (
            ".candidate-family-" + secrets.token_hex(16)
        )

        directory_path = str(
            Path(workspace) / directory_name
        )

        created = False
        directory = None

        try:
            os.mkdir(
                directory_name,
                mode=0o700,
                dir_fd=parent,
            )

            created = True

            directory = os.open(
                directory_name,
                DIRECTORY_FLAGS,
                dir_fd=parent,
            )

            info = os.fstat(directory)

            validate_protected_directory(info)

            # Remove inherited access and default ACLs.
            remove_access_acl(directory)

            try:
                os.removexattr(
                    directory,
                    "system.posix_acl_default",
                )
            except OSError as error:
                if error.errno not in (
                    errno.ENODATA,
                    errno.ENOTSUP,
                ):
                    raise

            # The restricted inspector needs traversal access,
            # but must not be able to modify the workspace.
            os.fchmod(directory, 0o755)

            info = os.fstat(directory)

            validate_protected_directory(info)

            if stat.S_IMODE(info.st_mode) != 0o755:
                raise ReceiverError(
                    "Invalid combined family workspace mode"
                )

            verify_directory_identity(
                workspace,
                parent,
            )

            verify_directory_identity(
                directory_path,
                directory,
            )

            for index, record in enumerate(plan):
                verify_inputs()

                verify_directory_identity(
                    directory_path,
                    directory,
                )

                destination_name = f"member-{index:04d}"

                member_path = str(
                    Path(directory_path)
                    / destination_name
                )

                require_absent_destination(
                    directory,
                    destination_name,
                )

                materialized = False

                try:
                    transfer = materialize_verified_member(
                        uid=uid,
                        gid=gid,
                        helper=archive_helper,
                        package=packages[record["filename"]],
                        name=record["name"],
                        version=record["version"],
                        architecture=record["architecture"],
                        archive_sha256=record["archive_sha256"],
                        member=record["member"],
                        member_size=record["size"],
                        member_sha256=record["sha256"],
                        destination=directory_path,
                        destination_name=destination_name,
                    )

                    materialized = True

                    expected_transfer = {
                        "package": packages[record["filename"]],
                        "name": record["name"],
                        "version": record["version"],
                        "architecture": record["architecture"],
                        "archive_sha256": record["archive_sha256"],
                        "member": record["member"],
                        "size": record["size"],
                        "sha256": record["sha256"],
                        "path": member_path,
                    }

                    if transfer != expected_transfer:
                        raise ReceiverError(
                            "Combined member transfer disagreement"
                        )

                    linkage = inspect_materialized_member(
                        uid=uid,
                        gid=gid,
                        helper=linkage_helper,
                        executable=member_path,
                        expected_size=record["size"],
                        expected_sha256=record["sha256"],
                        receipt_validator=receipt_validator,
                    )

                    evidence.append({
                        **record,
                        "linkage": linkage,
                    })

                finally:
                    if materialized:
                        os.unlink(
                            destination_name,
                            dir_fd=directory,
                        )

                        os.fsync(directory)

                verify_inputs()

            if os.listdir(directory):
                raise ReceiverError(
                    "Combined family workspace is not empty"
                )

            verify_directory_identity(
                directory_path,
                directory,
            )

        finally:
            try:
                if directory is not None:
                    os.close(directory)
            finally:
                try:
                    if created:
                        os.rmdir(
                            directory_name,
                            dir_fd=parent,
                        )

                        os.fsync(parent)
                finally:
                    os.close(parent)

    verify_inputs()

    if manifest_reader(checksums) != expected_checksums:
        raise ReceiverError(
            "Final combined family manifest disagreement"
        )

    verify_inputs()

    if len(evidence) != len(expected_members):
        raise ReceiverError(
            "Incomplete combined family linkage evidence"
        )

    return {
        "schema": 1,
        "family": family,
        "version": version,
        "architecture": architecture,
        "structural_and_identity_validation": True,
        "required_linkage_validation": {
            "applicable": bool(expected_members),
            "required_member_count": len(expected_members),
            "validated_member_count": len(evidence),
        },
        "archive_receipt": archive_receipt,
        "linkage_members": evidence,
    }
