"""Portable policy and Linux subprocess receiver regressions."""

import hashlib
import importlib.util
import io
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]

HELPER = (
    ROOT
    / "scripts/package-pipeline/candidate_member_receiver.py"
)

SPEC = importlib.util.spec_from_file_location(
    "_candidate_member_receiver",
    HELPER,
)

receiver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receiver)

PAYLOAD = bytes(range(256)) * 64
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class ReceiverPolicyTests(unittest.TestCase):

    def test_resource_policy(self):
        self.assertEqual(
            receiver.MAX_MEMBER_BYTES, 128 * 1024**2
        )
        self.assertEqual(
            receiver.MAX_DIAGNOSTIC_BYTES, 64 * 1024
        )
        self.assertEqual(receiver.CHUNK_BYTES, 1024**2)
        self.assertEqual(receiver.TRANSFER_TIMEOUT, 360)
        self.assertEqual(receiver.CLEANUP_TIMEOUT, 30)

    def test_valid_absolute_paths(self):
        for value in (
            "/protected/fixture",
            "/protected/package-1.0+2.pkg.tar.zst",
            Path("/protected/fixture"),
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    receiver.validate_absolute_path(value),
                    str(value),
                )

    def test_invalid_absolute_paths(self):
        for value in (
            "",
            "/",
            "relative",
            "//protected/fixture",
            "/protected//fixture",
            "/protected/./fixture",
            "/protected/../fixture",
            "/protected/fixture/",
            "/protected/file name",
            "/protected/file\nname",
            "/protected/file\0name",
            "/" + "x" * 4096,
            b"/protected/fixture",
        ):
            with self.subTest(value=value):
                with self.assertRaises(receiver.ReceiverError):
                    receiver.validate_absolute_path(value)

    def test_valid_expected_member_boundaries(self):
        for size in (1, receiver.MAX_MEMBER_BYTES):
            receiver.validate_expected_member(size, DIGEST)

    def test_invalid_expected_member_sizes(self):
        for size in (
            None, False, True, 0, -1, 1.5, "1",
            receiver.MAX_MEMBER_BYTES + 1,
        ):
            with self.subTest(size=size):
                with self.assertRaises(receiver.ReceiverError):
                    receiver.validate_expected_member(
                        size, DIGEST
                    )

    def test_invalid_expected_member_digests(self):
        for digest in (
            None, 1, "", "a" * 63, "a" * 65,
            "A" * 64, "g" * 64,
        ):
            with self.subTest(digest=digest):
                with self.assertRaises(receiver.ReceiverError):
                    receiver.validate_expected_member(
                        1, digest
                    )

    def test_invalid_inspection_accounts(self):
        for value in (
            None, True, False, 0, -1, 1.5, "65534",
            2**32 - 1,
        ):
            for uid, gid in (
                (value, 65534),
                (65534, value),
            ):
                with self.subTest(uid=uid, gid=gid):
                    with self.assertRaises(
                        receiver.ReceiverError
                    ):
                        receiver.validate_inspection_account(
                            uid, gid
                        )

    def test_root_identity_required(self):
        for uid, gid in (
            ((1000, 1000, 1000), (0, 0, 0)),
            ((0, 0, 1000), (0, 0, 0)),
            ((0, 0, 0), (0, 0, 1000)),
            ((0, 0, 0), (1000, 1000, 1000)),
        ):
            with (
                patch.object(
                    receiver.os,
                    "getresuid",
                    return_value=uid,
                ),
                patch.object(
                    receiver.os,
                    "getresgid",
                    return_value=gid,
                ),
            ):
                with self.assertRaises(
                    receiver.ReceiverError
                ):
                    receiver.require_root()

    def test_exact_restricted_launcher(self):
        result = receiver.restricted_command(
            65534,
            65534,
            "/protected/candidate_archive.py",
            ["stream-member"],
        )

        self.assertEqual(
            result,
            [
                "/usr/bin/setpriv",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--bounding-set=-all",
                "--no-new-privs",
                "/usr/bin/python",
                "-I", "-B",
                "/protected/candidate_archive.py",
                "stream-member",
            ],
        )

    def test_unexpected_helper_name_rejected(self):
        with self.assertRaises(receiver.ReceiverError):
            receiver.restricted_command(
                65534,
                65534,
                "/protected/other.py",
                ["stream-member"],
            )

    def test_protected_directory_policy(self):
        receiver.validate_protected_directory(
            SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o755,
                st_uid=0,
            )
        )

        for mode, uid in (
            (stat.S_IFDIR | 0o775, 0),
            (stat.S_IFDIR | 0o777, 0),
            (stat.S_IFDIR | 0o1777, 0),
            (stat.S_IFDIR | 0o755, 1000),
            (stat.S_IFREG | 0o644, 0),
            (stat.S_IFLNK | 0o777, 0),
        ):
            with self.subTest(mode=mode, uid=uid):
                with self.assertRaises(
                    receiver.ReceiverError
                ):
                    receiver.validate_protected_directory(
                        SimpleNamespace(
                            st_mode=mode,
                            st_uid=uid,
                        )
                    )

    def test_protected_file_policy(self):
        valid = {
            "st_mode": stat.S_IFREG | 0o644,
            "st_uid": 0,
            "st_nlink": 1,
            "st_size": 1,
        }

        receiver.validate_protected_file(
            SimpleNamespace(**valid)
        )

        for overrides in (
            {"st_uid": 1000},
            {"st_nlink": 2},
            {"st_size": 0},
            {"st_size": -1},
            {"st_mode": stat.S_IFREG | 0o664},
            {"st_mode": stat.S_IFREG | 0o646},
            {"st_mode": stat.S_IFREG | 0o4644},
            {"st_mode": stat.S_IFREG | 0o2644},
            {"st_mode": stat.S_IFREG | 0o1644},
            {"st_mode": stat.S_IFLNK | 0o777},
            {"st_mode": stat.S_IFDIR | 0o755},
            {"st_mode": stat.S_IFIFO | 0o644},
        ):
            with self.subTest(overrides=overrides):
                values = dict(valid)
                values.update(overrides)

                with self.assertRaises(
                    receiver.ReceiverError
                ):
                    receiver.validate_protected_file(
                        SimpleNamespace(**values)
                    )

    def test_expired_deadline_rejected(self):
        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "deadline exceeded",
        ):
            receiver.remaining_time(
                time.monotonic() - 1
            )


@unittest.skipUnless(
    sys.platform == "linux",
    "Requires Linux process lifecycle primitives",
)
class ReceiverStreamTests(unittest.TestCase):

    def launch(self, program):
        return subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", program],
            cwd="/",
            env=receiver.ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

    def emit(self, payload=PAYLOAD):
        return (
            "import sys\n"
            f"sys.stdout.buffer.write({payload!r})\n"
            "sys.stdout.buffer.flush()\n"
        )

    def receive(self, process, output, **overrides):
        options = {
            "expected_size": len(PAYLOAD),
            "expected_sha256": DIGEST,
            "deadline": time.monotonic() + 10,
        }

        options.update(overrides)

        return receiver.receive_stream(
            process, output, **options
        )

    def assert_reaped(self, process):
        self.assertIsNotNone(process.returncode)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

    def assert_rejected(
        self,
        program,
        message,
        *,
        output=None,
        **overrides,
    ):
        if output is None:
            output = io.BytesIO()

        process = self.launch(program)

        try:
            with self.assertRaisesRegex(
                receiver.ReceiverError,
                message,
            ):
                self.receive(
                    process, output, **overrides
                )

            self.assertIsNone(process.returncode)

        finally:
            receiver.stop_process_group(process)

        self.assert_reaped(process)

        return process.returncode

    def test_exact_binary_transfer_and_unreaped_exit(self):
        process = self.launch(self.emit())
        output = io.BytesIO()

        try:
            result = self.receive(process, output)

            self.assertEqual(
                result,
                {
                    "size": len(PAYLOAD),
                    "sha256": DIGEST,
                },
            )

            self.assertEqual(
                output.getvalue(), PAYLOAD
            )

            self.assertIsNone(process.returncode)

            observed = os.waitid(
                os.P_PID,
                process.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )

            self.assertEqual(
                observed.si_code, os.CLD_EXITED
            )

            self.assertEqual(observed.si_status, 0)

        finally:
            receiver.stop_process_group(process)

        self.assert_reaped(process)
        self.assertEqual(process.returncode, 0)

    def test_multichunk_transfer(self):
        payload = b"x" * (
            receiver.CHUNK_BYTES * 2 + 17
        )

        process = self.launch(
            "import sys\n"
            f"sys.stdout.buffer.write(b'x' * {len(payload)})\n"
        )

        output = io.BytesIO()
        digest = hashlib.sha256(payload).hexdigest()

        try:
            result = self.receive(
                process,
                output,
                expected_size=len(payload),
                expected_sha256=digest,
            )

            self.assertEqual(
                result,
                {
                    "size": len(payload),
                    "sha256": digest,
                },
            )

            self.assertEqual(
                output.getvalue(), payload
            )

        finally:
            receiver.stop_process_group(process)

        self.assert_reaped(process)

    def test_nonzero_exit_invalidates_correct_bytes(self):
        output = io.BytesIO()

        status = self.assert_rejected(
            self.emit() + "sys.exit(7)\n",
            "reader failed: 7",
            output=output,
        )

        self.assertEqual(status, 7)
        self.assertEqual(output.getvalue(), PAYLOAD)

    def test_truncated_transfer_rejected(self):
        self.assert_rejected(
            self.emit(PAYLOAD[:-1]),
            "size mismatch",
        )

    def test_oversized_transfer_rejected(self):
        output = io.BytesIO()

        self.assert_rejected(
            self.emit(PAYLOAD + b"x"),
            "exceeds expected size",
            output=output,
        )

        self.assertLessEqual(
            len(output.getvalue()), len(PAYLOAD)
        )

    def test_wrong_digest_rejected(self):
        self.assert_rejected(
            self.emit(),
            "digest mismatch",
            expected_sha256="0" * 64,
        )

    def test_unexpected_diagnostics_rejected(self):
        self.assert_rejected(
            self.emit()
            + "sys.stderr.write('unexpected diagnostic')\n",
            "Unexpected member reader diagnostics",
        )

    def test_diagnostic_limit_enforced(self):
        self.assert_rejected(
            "import sys\n"
            "sys.stderr.buffer.write(b'x' * "
            f"{receiver.MAX_DIAGNOSTIC_BYTES + 1})\n",
            "diagnostics exceed policy",
        )

    def test_short_output_write_rejected(self):
        class ShortOutput:
            def write(self, data):
                return len(data) - 1

        self.assert_rejected(
            self.emit(),
            "Incomplete provisional member write",
            output=ShortOutput(),
        )

    def test_stalled_reader_killed_and_reaped(self):
        status = self.assert_rejected(
            "import time\n"
            "time.sleep(60)\n",
            "deadline exceeded",
            deadline=time.monotonic() + 1,
        )

        self.assertEqual(status, -signal.SIGKILL)

    def test_closed_stream_exit_stall(self):
        status = self.assert_rejected(
            "import os, time\n"
            "os.close(1)\n"
            "os.close(2)\n"
            "time.sleep(60)\n",
            "deadline exceeded",
            deadline=time.monotonic() + 1,
        )

        self.assertEqual(status, -signal.SIGKILL)

    def test_signal_termination_rejected(self):
        self.assert_rejected(
            self.emit()
            + "import os, signal\n"
            + "os.kill(os.getpid(), signal.SIGTERM)\n",
            "reader failed: -15",
        )

    def test_previously_reaped_group_not_signaled(self):
        process = self.launch("pass")
        process.wait(timeout=10)

        with patch.object(
            receiver.os, "killpg"
        ) as kill_group:
            with self.assertRaisesRegex(
                receiver.ReceiverError,
                "previously reaped",
            ):
                receiver.stop_process_group(process)

            kill_group.assert_not_called()

        self.assert_reaped(process)

    def test_lost_child_ownership_prevents_signaling(self):
        process = self.launch("pass")
        os.waitpid(process.pid, 0)

        self.assertIsNone(process.returncode)

        try:
            with patch.object(
                receiver.os, "killpg"
            ) as kill_group:
                with self.assertRaisesRegex(
                    receiver.ReceiverError,
                    "unowned reader group",
                ):
                    receiver.stop_process_group(process)

                kill_group.assert_not_called()

            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)

        finally:
            process.wait()

    def test_descendant_retaining_pipes_is_terminated(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant"

            program = (
                "import os, time\n"
                "from pathlib import Path\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    time.sleep(60)\n"
                "    os._exit(0)\n"
                f"Path({str(marker)!r}).write_text(str(child))\n"
                "os._exit(0)\n"
            )

            process = self.launch(program)

            try:
                # Establish the descendant and leader exit
                # before testing the retained-pipe deadline.
                deadline = time.monotonic() + 10

                while not marker.exists():
                    if time.monotonic() >= deadline:
                        self.fail("Descendant marker missing")

                    time.sleep(0.01)

                observed = receiver.observe_reader_exit(
                    process, deadline
                )

                self.assertEqual(observed, 0)

                descendant = int(marker.read_text())

                self.assertEqual(
                    os.getpgid(descendant), process.pid
                )

                with self.assertRaisesRegex(
                    receiver.ReceiverError,
                    "deadline exceeded",
                ):
                    self.receive(
                        process,
                        io.BytesIO(),
                        deadline=time.monotonic() + 1,
                    )

            finally:
                receiver.stop_process_group(process)

            self.assert_reaped(process)

            # An orphan may briefly remain as a zombie until
            # its adoptive parent reaps it. It must not remain
            # a live, executing process.
            deadline = time.monotonic() + 5

            while True:
                try:
                    status = Path(
                        f"/proc/{descendant}/stat"
                    ).read_text()

                except FileNotFoundError:
                    break

                state = status.rsplit(")", 1)[1].split()[0]

                if state in {"Z", "X"}:
                    break

                if time.monotonic() >= deadline:
                    self.fail(
                        "Reader descendant remains alive"
                    )

                time.sleep(0.01)


class StagedByteVerificationTests(unittest.TestCase):

    def verify(self, output, **overrides):
        options = {
            "expected_size": len(PAYLOAD),
            "expected_sha256": DIGEST,
            "deadline": time.monotonic() + 10,
        }

        options.update(overrides)

        # Portable tests exercise real file bytes and hashing.
        # Native tests must separately establish root ownership.
        with patch.object(
            receiver,
            "validate_protected_file",
        ) as policy:
            result = receiver.verify_staged_bytes(
                output, **options
            )

            policy.assert_called_once()

        return result

    def test_exact_staged_bytes(self):
        with tempfile.TemporaryFile() as output:
            output.write(PAYLOAD)

            self.assertEqual(
                self.verify(output),
                {
                    "size": len(PAYLOAD),
                    "sha256": DIGEST,
                },
            )

    def test_wrong_staged_size_rejected(self):
        with tempfile.TemporaryFile() as output:
            output.write(PAYLOAD[:-1])

            with self.assertRaisesRegex(
                receiver.ReceiverError,
                "Staged member size mismatch",
            ):
                self.verify(output)

    def test_wrong_staged_digest_rejected(self):
        with tempfile.TemporaryFile() as output:
            output.write(b"x" * len(PAYLOAD))

            with self.assertRaisesRegex(
                receiver.ReceiverError,
                "Staged member verification failed",
            ):
                self.verify(output)

    def test_staged_identity_change_rejected(self):
        with tempfile.TemporaryFile() as output:
            output.write(PAYLOAD)

            with patch.object(
                receiver,
                "file_identity",
                side_effect=[("before",), ("after",)],
            ):
                with self.assertRaisesRegex(
                    receiver.ReceiverError,
                    "changed during verification",
                ):
                    self.verify(output)

    def test_staged_verification_deadline(self):
        with tempfile.TemporaryFile() as output:
            output.write(PAYLOAD)

            with self.assertRaisesRegex(
                receiver.ReceiverError,
                "deadline exceeded",
            ):
                self.verify(
                    output,
                    deadline=time.monotonic() - 1,
                )


@unittest.skipUnless(
    sys.platform == "linux",
    "Requires Linux subprocess and filesystem primitives",
)
class TransactionalReceiverTests(unittest.TestCase):

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(
            prefix="receiver-transaction-"
        )

        self.addCleanup(scratch.cleanup)

        self.root = Path(scratch.name)
        self.destination = self.root / "destination"
        self.destination.mkdir()

        self.target = self.destination / "analysis-input"

        self.helper = self.root / "candidate_archive.py"
        self.guard = self.root / "candidate_privileges.py"
        self.package = (
            self.root / "broot-1.0-1-x86_64.pkg.tar.zst"
        )

        for path in (
            self.helper,
            self.guard,
            self.package,
        ):
            path.write_bytes(b"synthetic protected input")

        self.arguments = {
            "uid": 65534,
            "gid": 65534,
            "helper": self.helper,
            "package": self.package,
            "name": "broot",
            "version": "1.0-1",
            "architecture": "x86_64",
            "archive_sha256": "a" * 64,
            "member": "usr/bin/broot",
            "member_size": len(PAYLOAD),
            "member_sha256": DIGEST,
            "destination": self.destination,
            "destination_name": self.target.name,
        }

        self.program = (
            "import sys\n"
            f"sys.stdout.buffer.write({PAYLOAD!r})\n"
            "sys.stdout.buffer.flush()\n"
        )

        self.processes = []

        self.real_popen = subprocess.Popen
        self.real_fstat = os.fstat
        self.real_stat = os.stat
        self.real_fsync = os.fsync

        self.real_receive = receiver.receive_stream
        self.real_verify = receiver.verify_staged_bytes
        self.real_cleanup = receiver.stop_process_group
        self.real_directory_check = (
            receiver.verify_directory_identity
        )

        # Root enforcement remains a native test obligation.
        self.enterContext(
            patch.object(receiver, "require_root")
        )

        self.directory_policy = self.enterContext(
            patch.object(
                receiver,
                "open_protected_directory",
                side_effect=self.open_fixture_directory,
            )
        )

        self.file_policy = self.enterContext(
            patch.object(
                receiver,
                "validate_protected_file",
                side_effect=self.validate_fixture_file,
            )
        )

        self.input_identity = self.enterContext(
            patch.object(
                receiver,
                "protected_file_identity",
                side_effect=self.fixture_input_identity,
            )
        )

        # Only the synthetic provisional file's reported UID
        # is normalized. Its remaining metadata stays real.
        self.enterContext(
            patch.object(
                receiver.os,
                "fstat",
                side_effect=self.fixture_fstat,
            )
        )

        self.enterContext(
            patch.object(
                receiver.os,
                "stat",
                side_effect=self.fixture_stat,
            )
        )

        self.launcher = self.enterContext(
            patch.object(
                receiver.subprocess,
                "Popen",
                side_effect=self.launch_fixture,
            )
        )

        self.addCleanup(self.emergency_cleanup)

    def fixture_metadata(self, info):
        return SimpleNamespace(
            **{
                field: getattr(info, field)
                for field in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_gid",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            },
            st_uid=0,
        )

    def fixture_fstat(self, descriptor):
        return self.fixture_metadata(
            self.real_fstat(descriptor)
        )

    def fixture_stat(self, *args, **kwargs):
        return self.fixture_metadata(
            self.real_stat(*args, **kwargs)
        )

    def open_fixture_directory(self, path):
        self.assertEqual(
            str(path), str(self.destination)
        )

        return os.open(
            path,
            receiver.DIRECTORY_FLAGS,
        )

    def validate_fixture_file(self, info):
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o7022
            or info.st_nlink != 1
            or info.st_size <= 0
        ):
            raise receiver.ReceiverError(
                "Synthetic file outside storage policy"
            )

    def fixture_input_identity(self, path):
        return receiver.file_identity(
            self.real_stat(
                path,
                follow_symlinks=False,
            )
        )

    def launch_fixture(self, command, **options):
        process = self.real_popen(
            [
                sys.executable,
                "-I", "-B",
                "-c", self.program,
            ],
            **options,
        )

        self.processes.append(process)

        return process

    def emergency_cleanup(self):
        for process in self.processes:
            if process.returncode is None:
                self.real_cleanup(process)

    def materialize(self, **overrides):
        arguments = dict(self.arguments)
        arguments.update(overrides)

        return receiver.materialize_verified_member(
            **arguments
        )

    def assert_empty_destination(self):
        self.assertEqual(
            list(self.destination.iterdir()),
            [],
        )

    def assert_children_reaped(self):
        for process in self.processes:
            self.assertIsNotNone(process.returncode)
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)

            with self.assertRaises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)

    def assert_transaction_rejected(
        self,
        message,
        *,
        exception=None,
        **overrides,
    ):
        if exception is None:
            exception = receiver.ReceiverError

        with self.assertRaisesRegex(exception, message):
            self.materialize(**overrides)

        self.assert_empty_destination()
        self.assert_children_reaped()

    def test_exact_transaction_and_receipt(self):
        result = self.materialize()

        self.assertEqual(
            result,
            {
                "package": str(self.package),
                "name": "broot",
                "version": "1.0-1",
                "architecture": "x86_64",
                "archive_sha256": "a" * 64,
                "member": "usr/bin/broot",
                "size": len(PAYLOAD),
                "sha256": DIGEST,
                "path": str(self.target),
            },
        )

        self.assertEqual(
            self.target.read_bytes(), PAYLOAD
        )

        info = self.real_stat(self.target)

        self.assertEqual(
            stat.S_IMODE(info.st_mode), 0o644
        )

        self.assertEqual(info.st_nlink, 1)

        self.assertEqual(
            list(self.destination.iterdir()),
            [self.target],
        )

        self.assert_children_reaped()

    def test_exact_transaction_launcher(self):
        self.materialize()

        self.launcher.assert_called_once()

        command = self.launcher.call_args.args[0]
        options = self.launcher.call_args.kwargs

        self.assertEqual(
            command,
            [
                "/usr/bin/setpriv",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--bounding-set=-all",
                "--no-new-privs",
                "/usr/bin/python",
                "-I", "-B",
                str(self.helper),
                "stream-member",
                "--package=" + str(self.package),
                "--name=broot",
                "--version=1.0-1",
                "--architecture=x86_64",
                "--archive-sha256=" + "a" * 64,
                "--member=usr/bin/broot",
                "--member-size=" + str(len(PAYLOAD)),
                "--member-sha256=" + DIGEST,
            ],
        )

        self.assertEqual(
            options,
            {
                "cwd": "/",
                "env": receiver.ENVIRONMENT,
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "start_new_session": True,
                "close_fds": True,
            },
        )

        self.assert_children_reaped()

    def test_invalid_destination_names(self):
        for name in (
            "", ".", "..", "/absolute",
            "../escape", "sub/file",
            ".hidden", "file name",
            "file\nname", "x" * 256,
        ):
            with self.subTest(name=name):
                self.assert_transaction_rejected(
                    "Invalid materialized destination name",
                    destination_name=name,
                )

        self.launcher.assert_not_called()

    def test_invalid_archive_digest(self):
        self.assert_transaction_rejected(
            "Invalid expected archive digest",
            archive_sha256="invalid",
        )

        self.launcher.assert_not_called()

    def test_existing_file_not_overwritten(self):
        self.target.write_bytes(b"existing")

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "already exists",
        ):
            self.materialize()

        self.assertEqual(
            self.target.read_bytes(), b"existing"
        )

        self.assertEqual(
            list(self.destination.iterdir()),
            [self.target],
        )

        self.launcher.assert_not_called()

    def test_existing_dangling_symlink_not_overwritten(self):
        self.target.symlink_to("absent-target")

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "already exists",
        ):
            self.materialize()

        self.assertTrue(self.target.is_symlink())

        self.assertEqual(
            os.readlink(self.target), "absent-target"
        )

        self.launcher.assert_not_called()

    def test_reader_launch_failure_removes_provisional(self):
        self.launcher.side_effect = OSError(
            "synthetic launch failure"
        )

        self.assert_transaction_rejected(
            "synthetic launch failure",
            exception=OSError,
        )

    def test_failed_reader_removes_correct_bytes(self):
        self.program += "sys.exit(7)\n"

        self.assert_transaction_rejected(
            "reader failed: 7"
        )

    def test_wrong_reader_digest_removes_provisional(self):
        self.assert_transaction_rejected(
            "Transferred member digest mismatch",
            member_sha256="0" * 64,
        )

    def test_oversized_reader_removes_provisional(self):
        self.program += (
            "sys.stdout.buffer.write(b'extra')\n"
        )

        self.assert_transaction_rejected(
            "exceeds expected size"
        )

    def test_reader_diagnostics_remove_provisional(self):
        self.program += (
            "sys.stderr.write('unexpected diagnostic')\n"
        )

        self.assert_transaction_rejected(
            "Unexpected member reader diagnostics"
        )

    def test_reader_timeout_removes_provisional(self):
        self.program = "import time; time.sleep(60)"

        with patch.object(
            receiver, "TRANSFER_TIMEOUT", 1
        ):
            self.assert_transaction_rejected(
                "deadline exceeded"
            )

        self.assertEqual(
            self.processes[0].returncode,
            -signal.SIGKILL,
        )

    def test_cleanup_failure_prevents_materialization(self):
        def cleanup_then_fail(process):
            self.real_cleanup(process)

            raise receiver.ReceiverError(
                "synthetic cleanup failure"
            )

        with patch.object(
            receiver,
            "stop_process_group",
            side_effect=cleanup_then_fail,
        ):
            self.assert_transaction_rejected(
                "synthetic cleanup failure"
            )

    def test_retained_byte_corruption_rejected(self):
        def corrupt_and_verify(output, **options):
            output.flush()
            output.seek(0)
            output.write(b"x")

            return self.real_verify(output, **options)

        with patch.object(
            receiver,
            "verify_staged_bytes",
            side_effect=corrupt_and_verify,
        ):
            self.assert_transaction_rejected(
                "Staged member verification failed"
            )

    def test_changed_protected_input_rejected(self):
        def receive_and_mutate(*args, **kwargs):
            result = self.real_receive(*args, **kwargs)

            self.package.write_bytes(
                b"changed synthetic archive input"
            )

            return result

        with patch.object(
            receiver,
            "receive_stream",
            side_effect=receive_and_mutate,
        ):
            self.assert_transaction_rejected(
                "Protected reader input changed"
            )

    def test_directory_identity_failure_before_publication(self):
        with patch.object(
            receiver,
            "verify_directory_identity",
            side_effect=receiver.ReceiverError(
                "Protected destination directory changed"
            ),
        ):
            self.assert_transaction_rejected(
                "Protected destination directory changed"
            )

    def test_publication_failure_removes_provisional(self):
        with patch.object(
            receiver.os,
            "link",
            side_effect=OSError(
                "synthetic publication failure"
            ),
        ):
            self.assert_transaction_rejected(
                "synthetic publication failure",
                exception=OSError,
            )

    def test_late_destination_collision_preserved(self):
        real_link = os.link

        def competing_destination(*args, **kwargs):
            self.target.write_bytes(
                b"competing destination"
            )

            return real_link(*args, **kwargs)

        with patch.object(
            receiver.os,
            "link",
            side_effect=competing_destination,
        ):
            with self.assertRaises(FileExistsError):
                self.materialize()

        self.assertEqual(
            self.target.read_bytes(),
            b"competing destination",
        )

        self.assertEqual(
            list(self.destination.iterdir()),
            [self.target],
        )

        self.assert_children_reaped()

    def test_post_publication_directory_failure_rolls_back(self):
        checks = 0

        def check_directory(path, descriptor):
            nonlocal checks
            checks += 1

            if checks == 2:
                self.assertTrue(self.target.exists())

                raise receiver.ReceiverError(
                    "synthetic late directory failure"
                )

            self.real_directory_check(
                path, descriptor
            )

        with patch.object(
            receiver,
            "verify_directory_identity",
            side_effect=check_directory,
        ):
            self.assert_transaction_rejected(
                "synthetic late directory failure"
            )

        self.assertEqual(checks, 2)

    def test_directory_sync_failure_rolls_back(self):
        def fail_directory_sync(descriptor):
            info = self.real_fstat(descriptor)

            if stat.S_ISDIR(info.st_mode):
                self.assertTrue(self.target.exists())

                raise OSError(
                    "synthetic directory sync failure"
                )

            return self.real_fsync(descriptor)

        with patch.object(
            receiver.os,
            "fsync",
            side_effect=fail_directory_sync,
        ):
            self.assert_transaction_rejected(
                "synthetic directory sync failure",
                exception=OSError,
            )

    def test_acl_removal_failure_cleans_provisional(self):
        with patch.object(
            receiver,
            "remove_access_acl",
            side_effect=OSError(
                "synthetic ACL removal failure"
            ),
        ):
            self.assert_transaction_rejected(
                "synthetic ACL removal failure",
                exception=OSError,
            )

        self.launcher.assert_not_called()


if __name__ == "__main__":
    unittest.main()
