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
        self.contract = (
            self.root / "package_release_contract.py"
        )
        self.package = (
            self.root / "broot-1.0-1-x86_64.pkg.tar.zst"
        )

        for path in (
            self.helper,
            self.guard,
            self.contract,
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
        self.assertIn(
            str(path),
            {
                str(self.root),
                str(self.destination),
            },
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

            if str(path) != str(self.destination):
                self.real_directory_check(
                    path, descriptor
                )
                return

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



    def test_missing_release_contract_rejected(self):
        self.contract.unlink()

        self.assert_transaction_rejected(
            "No such file",
            exception=FileNotFoundError,
        )

        self.launcher.assert_not_called()

    def test_helper_bytecode_cache_rejected(self):
        (self.root / "__pycache__").mkdir()

        self.assert_transaction_rejected(
            "Protected helper bytecode cache is forbidden"
        )

        self.launcher.assert_not_called()

    def test_helper_bytecode_cache_symlink_rejected(self):
        (self.root / "__pycache__").symlink_to(
            "absent-cache"
        )

        self.assert_transaction_rejected(
            "Protected helper bytecode cache is forbidden"
        )

        self.launcher.assert_not_called()

    def test_changed_release_contract_rejected(self):
        def receive_and_mutate(*args, **kwargs):
            result = self.real_receive(*args, **kwargs)

            self.contract.write_bytes(
                b"changed synthetic release contract"
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

    def test_late_helper_bytecode_cache_rejected(self):
        def receive_and_mutate(*args, **kwargs):
            result = self.real_receive(*args, **kwargs)

            (self.root / "__pycache__").mkdir()

            return result

        with patch.object(
            receiver,
            "receive_stream",
            side_effect=receive_and_mutate,
        ):
            self.assert_transaction_rejected(
                "Protected helper bytecode cache is forbidden"
            )


class LinkageTransportPolicyTests(unittest.TestCase):

    def arguments(self):
        return [
            65534,
            65534,
            "/protected/candidate_linkage.py",
            "/protected/analysis-input",
            4096,
            "a" * 64,
        ]

    def test_linkage_resource_limits(self):
        self.assertEqual(
            receiver.LINKAGE_TIMEOUT, 90
        )

        self.assertEqual(
            receiver.MAX_LINKAGE_RECEIPT_BYTES,
            1024**2,
        )

        self.assertEqual(
            receiver.MAX_LINKAGE_JSON_DEPTH, 8
        )

        self.assertEqual(
            receiver.MAX_DIAGNOSTIC_BYTES,
            64 * 1024,
        )

    def test_exact_restricted_linkage_command(self):
        result = receiver.restricted_linkage_command(
            *self.arguments()
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
                "/protected/candidate_linkage.py",
                "--path=/protected/analysis-input",
                "--expected-size=4096",
                "--expected-sha256=" + "a" * 64,
            ],
        )

    def test_invalid_linkage_launcher_arguments(self):
        for index, value in (
            (0, 0),
            (0, True),
            (1, 0),
            (2, "/protected/candidate_archive.py"),
            (2, "candidate_linkage.py"),
            (3, "/protected/../analysis-input"),
            (3, "relative-input"),
            (4, 0),
            (4, True),
            (4, receiver.MAX_MEMBER_BYTES + 1),
            (5, "A" * 64),
            (5, "a" * 63),
        ):
            arguments = self.arguments()
            arguments[index] = value

            with self.subTest(
                index=index, value=value
            ):
                with self.assertRaises(
                    receiver.ReceiverError
                ):
                    receiver.restricted_linkage_command(
                        *arguments
                    )


class LinkageReceiptDecoderTests(unittest.TestCase):

    def test_valid_json_object(self):
        result = receiver.decode_linkage_receipt(
            b'{"schema":1,'
            b'"static_linkage_validation":true,'
            b'"sha256":"' + b"a" * 64 + b'"}\n'
        )

        self.assertEqual(
            result,
            {
                "schema": 1,
                "static_linkage_validation": True,
                "sha256": "a" * 64,
            },
        )

    def test_duplicate_keys_rejected_at_all_depths(self):
        for data in (
            b'{"schema":1,"schema":2}\n',
            b'{"nested":{"a":1,"a":2}}\n',
            b'{"a":1,"\\u0061":2}\n',
        ):
            with self.subTest(data=data):
                with self.assertRaisesRegex(
                    receiver.ReceiverError,
                    "Duplicate linkage receipt field",
                ):
                    receiver.decode_linkage_receipt(
                        data
                    )

    def test_nonstandard_numeric_constants_rejected(self):
        for value in (
            b"NaN", b"Infinity", b"-Infinity"
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    receiver.ReceiverError,
                    "Nonstandard linkage JSON constant",
                ):
                    receiver.decode_linkage_receipt(
                        b'{"value":' + value + b'}\n'
                    )

    def test_floating_point_values_rejected(self):
        for value in (
            b"1.0", b"-1.5", b"1e3", b"1E-3"
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    receiver.ReceiverError,
                    "Floating-point linkage JSON value",
                ):
                    receiver.decode_linkage_receipt(
                        b'{"value":' + value + b'}\n'
                    )

    def test_integer_length_boundary(self):
        accepted = b"1" * 20

        result = receiver.decode_linkage_receipt(
            b'{"value":' + accepted + b'}\n'
        )

        self.assertEqual(
            result["value"],
            int(accepted),
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Linkage JSON integer exceeds policy",
        ):
            receiver.decode_linkage_receipt(
                b'{"value":' + b"1" * 21 + b'}\n'
            )

    def test_json_framing_rejected(self):
        for data in (
            b"{}",
            b"{}\n\n",
            b"{}\r\n",
            b"{}\n{}\n",
            b'{\n"schema":1}\n',
        ):
            with self.subTest(data=data):
                with self.assertRaisesRegex(
                    receiver.ReceiverError,
                    "Unexpected linkage receipt framing",
                ):
                    receiver.decode_linkage_receipt(
                        data
                    )

    def test_invalid_encoding_and_syntax_rejected(self):
        for data in (
            b'{"value":"\xff"}\n',
            b'{"value":}\n',
            b'{"value":[}\n',
            b'{"value":1,}\n',
            b'{"value":"unterminated}\n',
        ):
            with self.subTest(data=data):
                with self.assertRaises(
                    receiver.ReceiverError
                ):
                    receiver.decode_linkage_receipt(
                        data
                    )

    def test_nonobject_receipts_rejected(self):
        for data in (
            b"[]\n",
            b"null\n",
            b"true\n",
            b"1\n",
            b'"receipt"\n',
        ):
            with self.subTest(data=data):
                with self.assertRaisesRegex(
                    receiver.ReceiverError,
                    "must be a JSON object",
                ):
                    receiver.decode_linkage_receipt(
                        data
                    )

    def test_json_nesting_boundary(self):
        depth = receiver.MAX_LINKAGE_JSON_DEPTH

        accepted = (
            b'{"value":'
            + b"[" * (depth - 1)
            + b"0"
            + b"]" * (depth - 1)
            + b"}\n"
        )

        result = receiver.decode_linkage_receipt(
            accepted
        )

        value = result["value"]

        for _ in range(depth - 1):
            self.assertEqual(len(value), 1)
            value = value[0]

        self.assertEqual(value, 0)

        rejected = (
            b'{"value":'
            + b"[" * depth
            + b"0"
            + b"]" * depth
            + b"}\n"
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Linkage JSON nesting exceeds policy",
        ):
            receiver.decode_linkage_receipt(
                rejected
            )

    def test_quoted_brackets_and_escapes_not_counted(self):
        data = (
            b'{"text":"'
            + b"[" * 32
            + b'\\"'
            + b"{" * 32
            + b'\\\\'
            + b"]" * 32
            + b'"}\n'
        )

        result = receiver.decode_linkage_receipt(
            data
        )

        self.assertEqual(
            result["text"],
            "[" * 32
            + '"'
            + "{" * 32
            + "\\"
            + "]" * 32,
        )

    def test_receipt_byte_size_boundary(self):
        prefix = b'{"value":"'
        suffix = b'"}\n'

        payload_size = (
            receiver.MAX_LINKAGE_RECEIPT_BYTES
            - len(prefix)
            - len(suffix)
        )

        accepted = (
            prefix
            + b"x" * payload_size
            + suffix
        )

        self.assertEqual(
            len(accepted),
            receiver.MAX_LINKAGE_RECEIPT_BYTES,
        )

        result = receiver.decode_linkage_receipt(
            accepted
        )

        self.assertEqual(
            len(result["value"]),
            payload_size,
        )

        rejected = (
            prefix
            + b"x" * (payload_size + 1)
            + suffix
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Linkage receipt outside size policy",
        ):
            receiver.decode_linkage_receipt(
                rejected
            )

    def test_nonbytes_and_empty_receipts_rejected(self):
        for data in (
            None, "", "{}\n", b"",
            bytearray(b"{}\n"),
        ):
            with self.subTest(data=data):
                with self.assertRaisesRegex(
                    receiver.ReceiverError,
                    "Linkage receipt outside size policy",
                ):
                    receiver.decode_linkage_receipt(
                        data
                    )


@unittest.skipUnless(
    sys.platform == "linux",
    "Requires Linux subprocess lifecycle primitives",
)
class LinkageReceiptProcessTests(unittest.TestCase):

    RECEIPT = b'{"schema":1}\n'

    def launch(self, program):
        process = subprocess.Popen(
            [
                sys.executable,
                "-I", "-B",
                "-c", program,
            ],
            cwd="/",
            env=receiver.ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        def cleanup():
            if process.returncode is None:
                receiver.stop_process_group(
                    process
                )

        self.addCleanup(cleanup)

        return process

    def emit(self, payload=None):
        if payload is None:
            payload = self.RECEIPT

        return (
            "import sys\n"
            f"sys.stdout.buffer.write({payload!r})\n"
            "sys.stdout.buffer.flush()\n"
        )

    def receive(self, process, timeout=10):
        return receiver.receive_linkage_receipt(
            process,
            deadline=time.monotonic() + timeout,
        )

    def cleanup_and_verify(self, process):
        self.assertIsNone(process.returncode)

        receiver.stop_process_group(process)

        self.assertIsNotNone(process.returncode)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

        with self.assertRaises(ChildProcessError):
            os.waitpid(
                process.pid,
                os.WNOHANG,
            )

    def assert_rejected(
        self,
        program,
        message,
        *,
        timeout=10,
    ):
        process = self.launch(program)

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            message,
        ):
            self.receive(
                process,
                timeout=timeout,
            )

        self.cleanup_and_verify(process)

        return process

    def test_successful_receipt_preserves_unreaped_leader(self):
        process = self.launch(self.emit())

        result = self.receive(process)

        self.assertEqual(
            result, self.RECEIPT
        )

        self.assertEqual(
            receiver.decode_linkage_receipt(result),
            {"schema": 1},
        )

        self.cleanup_and_verify(process)

        self.assertEqual(process.returncode, 0)

    def test_exact_receipt_output_limit(self):
        limit = receiver.MAX_LINKAGE_RECEIPT_BYTES

        process = self.launch(
            "import sys\n"
            f"sys.stdout.buffer.write(b'x' * {limit})\n"
        )

        result = self.receive(process)

        self.assertEqual(
            result,
            b"x" * limit,
        )

        self.cleanup_and_verify(process)

        self.assertEqual(process.returncode, 0)

    def test_oversized_receipt_rejected(self):
        limit = (
            receiver.MAX_LINKAGE_RECEIPT_BYTES + 1
        )

        self.assert_rejected(
            "import sys\n"
            f"sys.stdout.buffer.write(b'x' * {limit})\n",
            "Linkage receipt exceeds size policy",
        )

    def test_nonzero_exit_invalidates_valid_receipt(self):
        process = self.assert_rejected(
            self.emit() + "sys.exit(7)\n",
            "Restricted linkage inspector failed: 7",
        )

        self.assertEqual(process.returncode, 7)

    def test_unexpected_diagnostics_rejected(self):
        self.assert_rejected(
            self.emit()
            + "sys.stderr.write('warning')\n",
            "Unexpected linkage inspector diagnostics",
        )

    def test_diagnostic_limit_enforced(self):
        limit = receiver.MAX_DIAGNOSTIC_BYTES + 1

        self.assert_rejected(
            self.emit()
            + f"sys.stderr.buffer.write(b'x' * {limit})\n",
            "Linkage diagnostics exceed policy",
        )

    def test_empty_receipt_rejected(self):
        self.assert_rejected(
            "pass\n",
            "Empty linkage inspection receipt",
        )

    def test_stalled_reader_terminated(self):
        process = self.assert_rejected(
            "import time\n"
            "time.sleep(60)\n",
            "deadline exceeded",
            timeout=1,
        )

        self.assertEqual(
            process.returncode,
            -signal.SIGKILL,
        )

    def test_closed_streams_do_not_bypass_deadline(self):
        process = self.assert_rejected(
            self.emit()
            + "import os, time\n"
            + "os.close(1)\n"
            + "os.close(2)\n"
            + "time.sleep(60)\n",
            "deadline exceeded",
            timeout=1,
        )

        self.assertEqual(
            process.returncode,
            -signal.SIGKILL,
        )


class MaterializedIdentityTests(unittest.TestCase):

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(
            prefix="materialized-identity-"
        )

        self.addCleanup(scratch.cleanup)

        self.directory = Path(scratch.name)
        self.path = self.directory / "analysis-input"
        self.payload = b"materialized executable fixture"

        self.path.write_bytes(self.payload)
        self.path.chmod(0o644)

        self.digest = hashlib.sha256(
            self.payload
        ).hexdigest()

        self.real_fstat = os.fstat
        self.real_stat = os.stat

        self.enterContext(
            patch.object(
                receiver,
                "open_protected_directory",
                side_effect=self.open_directory,
            )
        )

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

    def open_directory(self, path):
        self.assertEqual(
            str(path), str(self.directory)
        )

        return os.open(
            path,
            receiver.DIRECTORY_FLAGS,
        )

    def normalize_owner(self, info):
        return SimpleNamespace(
            st_uid=0,
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
        )

    def fixture_fstat(self, descriptor):
        return self.normalize_owner(
            self.real_fstat(descriptor)
        )

    def fixture_stat(self, *args, **kwargs):
        return self.normalize_owner(
            self.real_stat(*args, **kwargs)
        )

    def verify(self, **overrides):
        arguments = {
            "expected_size": len(self.payload),
            "expected_sha256": self.digest,
            "deadline": time.monotonic() + 10,
        }

        arguments.update(overrides)

        return receiver.verify_materialized_identity(
            self.path,
            **arguments,
        )

    def test_exact_materialized_identity(self):
        identity = self.verify()

        expected = receiver.file_identity(
            self.normalize_owner(
                self.real_stat(self.path)
            )
        )

        self.assertEqual(identity, expected)

        self.assertEqual(
            self.path.read_bytes(),
            self.payload,
        )

    def test_wrong_materialized_size_rejected(self):
        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "size or mode mismatch",
        ):
            self.verify(
                expected_size=len(self.payload) + 1
            )

    def test_wrong_materialized_digest_rejected(self):
        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "input digest mismatch",
        ):
            self.verify(
                expected_sha256="0" * 64
            )

    def test_executable_mode_rejected(self):
        self.path.chmod(0o755)

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "size or mode mismatch",
        ):
            self.verify()

    def test_hardlinked_materialized_file_rejected(self):
        os.link(
            self.path,
            self.directory / "additional-link",
        )

        with self.assertRaises(
            receiver.ReceiverError
        ):
            self.verify()

    def test_symlink_materialized_file_rejected(self):
        original = self.directory / "original"

        self.path.rename(original)
        self.path.symlink_to(original.name)

        with self.assertRaises(OSError):
            self.verify()

    def test_materialized_identity_deadline(self):
        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "deadline exceeded",
        ):
            self.verify(
                deadline=time.monotonic() - 1
            )

    def test_materialized_mutation_during_hashing(self):
        original_read = os.read
        mutated = False

        def read_then_mutate(descriptor, count):
            nonlocal mutated

            data = original_read(
                descriptor, count
            )

            if data and not mutated:
                mutated = True

                self.path.write_bytes(
                    b"x" * len(self.payload)
                )

            return data

        with patch.object(
            receiver.os,
            "read",
            side_effect=read_then_mutate,
        ):
            with self.assertRaisesRegex(
                receiver.ReceiverError,
                "input changed",
            ):
                self.verify()

        self.assertTrue(mutated)

    def test_materialized_path_replacement_rejected(self):
        original_read = os.read
        replaced = False

        def read_then_replace(descriptor, count):
            nonlocal replaced

            data = original_read(
                descriptor, count
            )

            if data and not replaced:
                replaced = True

                replacement = (
                    self.directory / "replacement"
                )

                replacement.write_bytes(
                    self.payload
                )

                replacement.chmod(0o644)
                replacement.replace(self.path)

            return data

        with patch.object(
            receiver.os,
            "read",
            side_effect=read_then_replace,
        ):
            with self.assertRaisesRegex(
                receiver.ReceiverError,
                "input changed",
            ):
                self.verify()

        self.assertTrue(replaced)

    def test_directory_identity_failure_rejected(self):
        with patch.object(
            receiver,
            "verify_directory_identity",
            side_effect=receiver.ReceiverError(
                "Synthetic directory identity failure"
            ),
        ):
            with self.assertRaisesRegex(
                receiver.ReceiverError,
                "Synthetic directory identity failure",
            ):
                self.verify()


class LinkageCoordinatorTests(unittest.TestCase):

    def setUp(self):
        self.events = []

        self.helper = (
            "/protected/helpers/candidate_linkage.py"
        )

        self.executable = (
            "/protected/members/analysis-input"
        )

        self.size = 4096
        self.digest = "a" * 64

        self.result = {
            "schema": 1,
            "static_linkage_validation": True,
            "sha256": self.digest,
        }

        self.raw = (
            b'{"schema":1,'
            b'"static_linkage_validation":true,'
            b'"sha256":"' + b"a" * 64 + b'"}\n'
        )

        self.process = SimpleNamespace(
            returncode=None,
        )

        self.helper_identity = {
            self.helper: ("helper", 1),
        }

        self.member_identity = ("member", 1)

        self.root_check = self.enterContext(
            patch.object(
                receiver,
                "require_root",
                side_effect=self.check_root,
            )
        )

        self.helpers = self.enterContext(
            patch.object(
                receiver,
                "protected_helper_identities",
                side_effect=self.check_helpers,
            )
        )

        self.member = self.enterContext(
            patch.object(
                receiver,
                "verify_materialized_identity",
                side_effect=self.check_member,
            )
        )

        self.launcher = self.enterContext(
            patch.object(
                receiver.subprocess,
                "Popen",
                side_effect=self.launch,
            )
        )

        self.collector = self.enterContext(
            patch.object(
                receiver,
                "receive_linkage_receipt",
                side_effect=self.collect,
            )
        )

        self.cleanup = self.enterContext(
            patch.object(
                receiver,
                "stop_process_group",
                side_effect=self.clean,
            )
        )

        self.decoder = self.enterContext(
            patch.object(
                receiver,
                "decode_linkage_receipt",
                wraps=receiver.decode_linkage_receipt,
            )
        )

    def check_root(self):
        self.events.append("root")

    def check_helpers(self, helper, dependencies):
        self.events.append("helpers")

        self.assertEqual(helper, self.helper)

        self.assertEqual(
            dependencies,
            ("candidate_privileges.py",),
        )

        return dict(self.helper_identity)

    def check_member(self, path, **arguments):
        self.events.append("member")

        self.assertEqual(path, self.executable)

        self.assertEqual(
            arguments["expected_size"],
            self.size,
        )

        self.assertEqual(
            arguments["expected_sha256"],
            self.digest,
        )

        self.assertGreater(
            arguments["deadline"],
            time.monotonic(),
        )

        return self.member_identity

    def launch(self, command, **options):
        self.events.append("launch")

        self.assertEqual(
            command,
            receiver.restricted_linkage_command(
                65534,
                65534,
                self.helper,
                self.executable,
                self.size,
                self.digest,
            ),
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

        return self.process

    def collect(self, process, *, deadline):
        self.events.append("collect")

        self.assertIs(process, self.process)
        self.assertIsNone(process.returncode)

        self.assertGreater(
            deadline, time.monotonic()
        )

        return self.raw

    def clean(self, process):
        self.events.append("cleanup")

        self.assertIs(process, self.process)

        process.returncode = 0

    def validate(self, receipt, **arguments):
        self.events.append("validate")

        self.assertEqual(
            self.process.returncode, 0
        )

        self.assertEqual(
            receipt, self.result
        )

        self.assertEqual(
            arguments,
            {
                "expected_size": self.size,
                "expected_sha256": self.digest,
            },
        )

        return dict(receipt)

    def inspect(self, **overrides):
        arguments = {
            "uid": 65534,
            "gid": 65534,
            "helper": self.helper,
            "executable": self.executable,
            "expected_size": self.size,
            "expected_sha256": self.digest,
            "receipt_validator": self.validate,
        }

        arguments.update(overrides)

        return receiver.inspect_materialized_member(
            **arguments
        )

    def assert_no_receipt_acceptance(self):
        self.assertNotIn(
            "validate", self.events
        )

    def test_exact_coordination_order(self):
        self.assertEqual(
            self.inspect(), self.result
        )

        self.assertEqual(
            self.events,
            [
                "root",
                "helpers",
                "member",
                "launch",
                "collect",
                "cleanup",
                "helpers",
                "member",
                "validate",
            ],
        )

        self.decoder.assert_called_once_with(
            self.raw
        )

    def test_root_rejection_prevents_launch(self):
        self.root_check.side_effect = (
            receiver.ReceiverError(
                "Synthetic root rejection"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic root rejection",
        ):
            self.inspect()

        self.helpers.assert_not_called()
        self.launcher.assert_not_called()
        self.decoder.assert_not_called()

    def test_noncallable_validator_prevents_launch(self):
        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Trusted linkage receipt validator required",
        ):
            self.inspect(
                receipt_validator=None
            )

        self.launcher.assert_not_called()

    def test_initial_helper_failure_prevents_launch(self):
        self.helpers.side_effect = (
            receiver.ReceiverError(
                "Synthetic helper rejection"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic helper rejection",
        ):
            self.inspect()

        self.member.assert_not_called()
        self.launcher.assert_not_called()

    def test_initial_member_failure_prevents_launch(self):
        self.member.side_effect = (
            receiver.ReceiverError(
                "Synthetic member rejection"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic member rejection",
        ):
            self.inspect()

        self.launcher.assert_not_called()

    def test_launch_failure_propagates(self):
        self.launcher.side_effect = OSError(
            "Synthetic launch failure"
        )

        with self.assertRaisesRegex(
            OSError,
            "Synthetic launch failure",
        ):
            self.inspect()

        self.collector.assert_not_called()
        self.cleanup.assert_not_called()
        self.decoder.assert_not_called()

    def test_collection_failure_still_cleans_up(self):
        self.collector.side_effect = (
            receiver.ReceiverError(
                "Synthetic collection failure"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic collection failure",
        ):
            self.inspect()

        self.cleanup.assert_called_once_with(
            self.process
        )

        self.decoder.assert_not_called()

    def test_cleanup_failure_prevents_acceptance(self):
        self.cleanup.side_effect = (
            receiver.ReceiverError(
                "Synthetic cleanup failure"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic cleanup failure",
        ):
            self.inspect()

        self.decoder.assert_not_called()
        self.assert_no_receipt_acceptance()

    def test_unsuccessful_final_exit_rejected(self):
        def failed_cleanup(process):
            process.returncode = 7

        self.cleanup.side_effect = failed_cleanup

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "did not terminate successfully",
        ):
            self.inspect()

        self.decoder.assert_not_called()

    def test_changed_helper_identity_rejected(self):
        self.helpers.side_effect = [
            self.helper_identity,
            {self.helper: ("helper", 2)},
        ]

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Protected linkage helper changed",
        ):
            self.inspect()

        self.cleanup.assert_called_once()
        self.decoder.assert_not_called()

    def test_changed_member_identity_rejected(self):
        self.member.side_effect = [
            self.member_identity,
            ("member", 2),
        ]

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Protected linkage input changed",
        ):
            self.inspect()

        self.cleanup.assert_called_once()
        self.decoder.assert_not_called()

    def test_post_inspection_hash_failure_rejected(self):
        self.member.side_effect = [
            self.member_identity,
            receiver.ReceiverError(
                "Synthetic post-inspection digest failure"
            ),
        ]

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic post-inspection digest failure",
        ):
            self.inspect()

        self.cleanup.assert_called_once()
        self.decoder.assert_not_called()

    def test_invalid_json_rejected_after_cleanup(self):
        self.raw = b'{"schema":1,"schema":2}\n'

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Duplicate linkage receipt field",
        ):
            self.inspect()

        self.cleanup.assert_called_once()
        self.assert_no_receipt_acceptance()

    def test_schema_validator_failure_propagates(self):
        def reject(receipt, **arguments):
            raise ValueError(
                "Synthetic schema rejection"
            )

        with self.assertRaisesRegex(
            ValueError,
            "Synthetic schema rejection",
        ):
            self.inspect(
                receipt_validator=reject,
            )

        self.cleanup.assert_called_once()

    def test_disagreeing_validated_digest_rejected(self):
        def disagree(receipt, **arguments):
            result = dict(receipt)
            result["sha256"] = "0" * 64

            return result

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Validated linkage receipt identity disagreement",
        ):
            self.inspect(
                receipt_validator=disagree,
            )

    def test_invalid_validated_marker_rejected(self):
        def disagree(receipt, **arguments):
            result = dict(receipt)

            result[
                "static_linkage_validation"
            ] = False

            return result

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Validated linkage receipt identity disagreement",
        ):
            self.inspect(
                receipt_validator=disagree,
            )

    def test_expired_deadline_prevents_launch(self):
        with patch.object(
            receiver,
            "LINKAGE_TIMEOUT",
            -1,
        ):
            # Bypass the fixture's deadline assertion so
            # the actual coordinator deadline check runs.
            self.member.side_effect = None

            self.member.return_value = (
                self.member_identity
            )

            with self.assertRaisesRegex(
                receiver.ReceiverError,
                "deadline exceeded",
            ):
                self.inspect()

        self.launcher.assert_not_called()

    def test_expired_deadline_after_validation_rejected(self):
        def late_validator(receipt, **arguments):
            self.expired = True

            return dict(receipt)

        self.expired = False
        original_remaining = receiver.remaining_time

        def check_deadline(deadline):
            if self.expired:
                raise receiver.ReceiverError(
                    "Synthetic deadline exceeded"
                )

            return original_remaining(deadline)

        with patch.object(
            receiver,
            "remaining_time",
            side_effect=check_deadline,
        ):
            with self.assertRaisesRegex(
                receiver.ReceiverError,
                "Synthetic deadline exceeded",
            ):
                self.inspect(
                    receipt_validator=late_validator,
                )

        self.cleanup.assert_called_once()


class ProtectedFamilyCoordinatorTests(unittest.TestCase):

    VERSION = "1.0-1"
    ARCHITECTURE = "x86_64"
    ARCHIVE_DIGEST = "a" * 64
    MEMBER_DIGEST = "b" * 64

    def setUp(self):
        import json

        self.json = json

        linkage_path = Path(
            receiver.__file__
        ).with_name("candidate_linkage.py")

        spec = importlib.util.spec_from_file_location(
            "_family_coordinator_linkage_policy",
            linkage_path,
        )

        self.linkage = (
            importlib.util.module_from_spec(spec)
        )

        spec.loader.exec_module(self.linkage)

        self.helper = (
            "/protected/helpers/candidate_archive.py"
        )

        self.manifest = "/protected/checksums"

        self.events = []

        self.process = SimpleNamespace(
            returncode=None,
        )

        self.helper_identity = {
            self.helper: ("helper", 1),
        }

        self.configure_family(
            "noctalia-custom",
            (
                "noctalia-custom",
                "noctalia-custom-debug",
            ),
        )

        self.root_check = self.enterContext(
            patch.object(receiver, "require_root")
        )

        self.helpers = self.enterContext(
            patch.object(
                receiver,
                "protected_helper_identities",
                side_effect=self.check_helpers,
            )
        )

        self.files = self.enterContext(
            patch.object(
                receiver,
                "protected_file_identity",
                side_effect=self.check_file,
            )
        )

        self.launcher = self.enterContext(
            patch.object(
                receiver.subprocess,
                "Popen",
                side_effect=self.launch,
            )
        )

        self.collector = self.enterContext(
            patch.object(
                receiver,
                "receive_linkage_receipt",
                side_effect=self.collect,
            )
        )

        self.cleanup = self.enterContext(
            patch.object(
                receiver,
                "stop_process_group",
                side_effect=self.clean,
            )
        )

        self.decoder = self.enterContext(
            patch.object(
                receiver,
                "decode_linkage_receipt",
                wraps=receiver.decode_linkage_receipt,
            )
        )

    def configure_family(self, family, names):
        self.family = family
        self.names = {}
        self.checksums = {}
        self.packages = {}

        self.receipt = {
            "schema": 1,
            "family": family,
            "version": self.VERSION,
            "architecture": self.ARCHITECTURE,
            "structural_and_identity_validation": True,
            "packages": {},
        }

        for name in names:
            filename = (
                f"{name}-{self.VERSION}-"
                f"{self.ARCHITECTURE}.pkg.tar.zst"
            )

            self.names[filename] = name

            self.checksums[filename] = (
                self.ARCHIVE_DIGEST
            )

            self.packages[filename] = (
                "/protected/packages/" + filename
            )

            package = {
                "identity": {
                    "pkgname": name,
                    "pkgver": self.VERSION,
                    "arch": self.ARCHITECTURE,
                    "filename": filename,
                    "sha256": self.ARCHIVE_DIGEST,
                },
            }

            members = (
                self.linkage.REQUIRED_EXECUTABLES.get(
                    name, ()
                )
            )

            if members:
                package["selected_members"] = {
                    member: {
                        "size": 4096,
                        "sha256": self.MEMBER_DIGEST,
                    }
                    for member in members
                }

                package["entries"] = {
                    member: {
                        "type": "file",
                        "size": 4096,
                    }
                    for member in members
                }

            self.receipt["packages"][name] = package

        self.identities = {
            self.manifest: (
                1, 1, 0o100644, 0, 0, 1, 256, 1, 1
            ),
        }

        for index, package in enumerate(
            self.packages.values(), start=2
        ):
            self.identities[package] = (
                1, index, 0o100644, 0, 0, 1,
                8192, 1, 1,
            )

    def check_helpers(self, helper, dependencies):
        self.events.append("helpers")

        self.assertEqual(helper, self.helper)

        self.assertEqual(
            dependencies,
            (
                "candidate_privileges.py",
                "package_release_contract.py",
            ),
        )

        return dict(self.helper_identity)

    def check_file(self, path):
        self.events.append(("file", str(path)))

        return self.identities[str(path)]

    def read_manifest(self, path):
        self.events.append("manifest")

        self.assertEqual(path, self.manifest)

        return dict(self.checksums)

    def launch(self, command, **options):
        self.events.append("launch")

        self.assertEqual(
            command,
            receiver.restricted_family_command(
                uid=65534,
                gid=65534,
                helper=self.helper,
                family=self.family,
                version=self.VERSION,
                checksums=self.manifest,
                packages=self.packages,
                requests=(
                    self.linkage.build_family_linkage_requests(
                        self.names
                    )
                ),
            ),
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

        return self.process

    def collect(self, process, *, deadline):
        self.events.append("collect")

        self.assertIs(process, self.process)
        self.assertIsNone(process.returncode)

        self.assertGreater(
            deadline, time.monotonic()
        )

        return (
            self.json.dumps(
                self.receipt,
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n"
        ).encode("ascii")

    def clean(self, process):
        self.events.append("cleanup")

        self.assertIs(process, self.process)

        process.returncode = 0

    def bind(self, receipt, **arguments):
        self.events.append("bind")

        self.assertEqual(
            self.process.returncode, 0
        )

        self.assertEqual(
            receipt, self.receipt
        )

        return (
            self.linkage.bind_family_linkage_members(
                receipt,
                **arguments,
            )
        )

    def inspect(self, **overrides):
        arguments = {
            "uid": 65534,
            "gid": 65534,
            "helper": self.helper,
            "family": self.family,
            "version": self.VERSION,
            "architecture": self.ARCHITECTURE,
            "checksums": self.manifest,
            "packages": self.packages,
            "expected_names": self.names,
            "expected_checksums": self.checksums,
            "request_builder": (
                self.linkage.build_family_linkage_requests
            ),
            "evidence_binder": self.bind,
            "manifest_reader": self.read_manifest,
        }

        arguments.update(overrides)

        return receiver.inspect_protected_family(
            **arguments
        )

    def assert_not_accepted(self):
        self.assertNotIn("bind", self.events)

    def test_exact_family_evidence_and_order(self):
        result = self.inspect()

        self.assertEqual(
            result["archive_receipt"],
            self.receipt,
        )

        self.assertEqual(
            len(result["member_plan"]), 2
        )

        self.assertEqual(
            [
                record["member"]
                for record in result["member_plan"]
            ],
            [
                "usr/bin/noctalia",
                "usr/libexec/noctalia/noctalia-pam-helper",
            ],
        )

        for record in result["member_plan"]:
            self.assertEqual(
                record["archive_sha256"],
                self.ARCHIVE_DIGEST,
            )

            self.assertEqual(
                record["sha256"],
                self.MEMBER_DIGEST,
            )

            self.assertEqual(record["size"], 4096)

        self.assertEqual(
            self.events,
            [
                "helpers",
                ("file", self.manifest),
                *[
                    ("file", self.packages[name])
                    for name in sorted(self.packages)
                ],
                "manifest",
                ("file", self.manifest),
                "launch",
                "collect",
                "cleanup",
                "helpers",
                ("file", self.manifest),
                "manifest",
                ("file", self.manifest),
                *[
                    ("file", self.packages[name])
                    for name in sorted(self.packages)
                ],
                "bind",
            ],
        )

    def test_greeter_requires_all_three_executables(self):
        self.configure_family(
            "noctalia-greeter-t4t3z0r",
            ("noctalia-greeter-t4t3z0r",),
        )

        result = self.inspect()

        self.assertEqual(
            [
                record["member"]
                for record in result["member_plan"]
            ],
            [
                "usr/bin/noctalia-greeter",
                "usr/bin/noctalia-greeter-apply-appearance",
                "usr/bin/noctalia-greeter-compositor",
            ],
        )

    def test_unrelated_family_has_no_linkage_requests(self):
        self.configure_family(
            "broot",
            ("broot",),
        )

        result = self.inspect()

        self.assertEqual(
            result["member_plan"], []
        )

        command = (
            self.launcher.call_args.args[0]
        )

        self.assertNotIn(
            "--select-member", command
        )

    def test_root_rejection_prevents_launch(self):
        self.root_check.side_effect = (
            receiver.ReceiverError(
                "Synthetic root rejection"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic root rejection",
        ):
            self.inspect()

        self.launcher.assert_not_called()

    def test_missing_trusted_callbacks_rejected(self):
        for name in (
            "request_builder",
            "evidence_binder",
            "manifest_reader",
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    receiver.ReceiverError,
                    "Trusted family policy callbacks required",
                ):
                    self.inspect(**{name: None})

        self.launcher.assert_not_called()

    def test_mismatched_expected_inventory_rejected(self):
        for overrides in (
            {"expected_names": {}},
            {"expected_checksums": {}},
            {"packages": {}},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(
                    receiver.ReceiverError,
                    "Expected family input inventory mismatch",
                ):
                    self.inspect(**overrides)

        self.launcher.assert_not_called()

    def test_invalid_expected_archive_digest_rejected(self):
        checksums = dict(self.checksums)

        checksums[next(iter(checksums))] = "invalid"

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Invalid expected family archive digest",
        ):
            self.inspect(
                expected_checksums=checksums
            )

        self.launcher.assert_not_called()

    def test_manifest_disagreement_prevents_launch(self):
        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Protected checksum manifest disagreement",
        ):
            self.inspect(
                manifest_reader=lambda path: {}
            )

        self.launcher.assert_not_called()

    def test_oversized_manifest_prevents_launch(self):
        identity = list(
            self.identities[self.manifest]
        )

        identity[6] = (
            receiver.MAX_FAMILY_MANIFEST_BYTES + 1
        )

        self.identities[self.manifest] = (
            tuple(identity)
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "manifest outside size policy",
        ):
            self.inspect()

        self.launcher.assert_not_called()

    def test_initial_helper_rejection_prevents_launch(self):
        self.helpers.side_effect = (
            receiver.ReceiverError(
                "Synthetic helper rejection"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic helper rejection",
        ):
            self.inspect()

        self.launcher.assert_not_called()

    def test_initial_archive_rejection_prevents_launch(self):
        rejected = next(iter(
            self.packages.values()
        ))

        def check(path):
            if str(path) == rejected:
                raise receiver.ReceiverError(
                    "Synthetic archive rejection"
                )

            return self.check_file(path)

        self.files.side_effect = check

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic archive rejection",
        ):
            self.inspect()

        self.launcher.assert_not_called()

    def test_launch_failure_propagates(self):
        self.launcher.side_effect = OSError(
            "Synthetic launch failure"
        )

        with self.assertRaisesRegex(
            OSError,
            "Synthetic launch failure",
        ):
            self.inspect()

        self.collector.assert_not_called()
        self.cleanup.assert_not_called()
        self.decoder.assert_not_called()

    def test_collection_failure_still_cleans_up(self):
        self.collector.side_effect = (
            receiver.ReceiverError(
                "Synthetic receipt collection failure"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic receipt collection failure",
        ):
            self.inspect()

        self.cleanup.assert_called_once_with(
            self.process
        )

        self.decoder.assert_not_called()

    def test_cleanup_failure_prevents_acceptance(self):
        self.cleanup.side_effect = (
            receiver.ReceiverError(
                "Synthetic cleanup failure"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic cleanup failure",
        ):
            self.inspect()

        self.decoder.assert_not_called()
        self.assert_not_accepted()

    def test_unsuccessful_final_exit_rejected(self):
        def failed_cleanup(process):
            process.returncode = 7

        self.cleanup.side_effect = failed_cleanup

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "did not terminate successfully",
        ):
            self.inspect()

        self.decoder.assert_not_called()

    def test_changed_helper_rejected(self):
        self.helpers.side_effect = [
            self.helper_identity,
            {self.helper: ("helper", 2)},
        ]

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Protected family helper changed",
        ):
            self.inspect()

        self.cleanup.assert_called_once()
        self.decoder.assert_not_called()

    def test_changed_manifest_identity_rejected(self):
        def mutate_manifest(process):
            self.clean(process)

            identity = list(
                self.identities[self.manifest]
            )

            identity[-1] += 1

            self.identities[self.manifest] = (
                tuple(identity)
            )

        self.cleanup.side_effect = mutate_manifest

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Protected checksum manifest changed",
        ):
            self.inspect()

        self.decoder.assert_not_called()

    def test_changed_manifest_contents_rejected(self):
        manifests = iter([
            dict(self.checksums),
            {},
        ])

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Protected checksum manifest changed",
        ):
            self.inspect(
                manifest_reader=lambda path: next(
                    manifests
                )
            )

        self.decoder.assert_not_called()

    def test_changed_archive_identity_rejected(self):
        def mutate_archive(process):
            self.clean(process)

            package = next(iter(
                self.packages.values()
            ))

            identity = list(
                self.identities[package]
            )

            identity[-1] += 1

            self.identities[package] = (
                tuple(identity)
            )

        self.cleanup.side_effect = mutate_archive

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Protected family archive changed",
        ):
            self.inspect()

        self.decoder.assert_not_called()

    def test_invalid_json_rejected_after_cleanup(self):
        self.collector.side_effect = None

        self.collector.return_value = (
            b'{"schema":1,"schema":2}\n'
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Duplicate linkage receipt field",
        ):
            self.inspect()

        self.cleanup.assert_called_once()
        self.assert_not_accepted()

    def test_unexpected_top_level_receipt_field_rejected(self):
        self.receipt["unexpected"] = True

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Unexpected compact family receipt fields",
        ):
            self.inspect()

        self.assert_not_accepted()

    def test_missing_package_receipt_rejected(self):
        del self.receipt["packages"][
            "noctalia-custom-debug"
        ]

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Compact family package inventory mismatch",
        ):
            self.inspect()

        self.assert_not_accepted()

    def test_unexpected_package_fields_rejected(self):
        self.receipt["packages"][
            "noctalia-custom-debug"
        ]["selected_members"] = {}

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Unexpected compact package receipt fields",
        ):
            self.inspect()

        self.assert_not_accepted()

    def test_missing_selected_entry_rejected(self):
        del self.receipt["packages"][
            "noctalia-custom"
        ]["entries"]["usr/bin/noctalia"]

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Unexpected compact member inventory",
        ):
            self.inspect()

        self.assert_not_accepted()

    def test_unexpected_entry_field_rejected(self):
        self.receipt["packages"][
            "noctalia-custom"
        ]["entries"]["usr/bin/noctalia"][
            "unexpected"
        ] = 1

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Unexpected compact member fields",
        ):
            self.inspect()

        self.assert_not_accepted()

    def test_actual_binder_rejects_wrong_archive_digest(self):
        self.receipt["packages"][
            "noctalia-custom"
        ]["identity"]["sha256"] = "0" * 64

        with self.assertRaisesRegex(
            self.linkage.LinkageError,
            "Archive package identity disagreement",
        ):
            self.inspect()

        self.cleanup.assert_called_once()

    def test_actual_binder_rejects_missing_member(self):
        del self.receipt["packages"][
            "noctalia-custom"
        ]["selected_members"]["usr/bin/noctalia"]

        with self.assertRaisesRegex(
            self.linkage.LinkageError,
            "Required archive member inventory mismatch",
        ):
            self.inspect()

        self.cleanup.assert_called_once()

    def test_incomplete_bound_plan_rejected(self):
        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Bound family member plan disagreement",
        ):
            self.inspect(
                evidence_binder=lambda *args, **kw: []
            )

        self.cleanup.assert_called_once()

    def test_wrong_bound_archive_identity_rejected(self):
        def wrong_identity(receipt, **arguments):
            plan = self.bind(
                receipt, **arguments
            )

            plan[0]["archive_sha256"] = "0" * 64

            return plan

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Bound family archive identity disagreement",
        ):
            self.inspect(
                evidence_binder=wrong_identity
            )

    def test_invalid_bound_member_digest_rejected(self):
        def wrong_digest(receipt, **arguments):
            plan = self.bind(
                receipt, **arguments
            )

            plan[0]["sha256"] = "invalid"

            return plan

        with self.assertRaises(
            receiver.ReceiverError
        ):
            self.inspect(
                evidence_binder=wrong_digest
            )

    def test_deadline_expiry_prevents_launch(self):
        with patch.object(
            receiver,
            "FAMILY_ARCHIVE_TIMEOUT",
            -1,
        ):
            with self.assertRaisesRegex(
                receiver.ReceiverError,
                "deadline exceeded",
            ):
                self.inspect()

        self.launcher.assert_not_called()


class FamilyLauncherPolicyTests(unittest.TestCase):

    def arguments(self):
        filename = (
            "broot-1.0-1-x86_64.pkg.tar.zst"
        )

        return {
            "uid": 65534,
            "gid": 65534,
            "helper":
                "/protected/helpers/candidate_archive.py",
            "family": "broot",
            "version": "1.0-1",
            "checksums": "/protected/checksums",
            "packages": {
                filename: "/protected/" + filename,
            },
            "requests": {
                filename: ("usr/bin/broot",),
            },
        }

    def test_exact_restricted_family_launcher(self):
        arguments = self.arguments()

        filename = next(iter(
            arguments["packages"]
        ))

        command = receiver.restricted_family_command(
            **arguments
        )

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
                "-I",
                "-B",
                arguments["helper"],
                "validate-family",
                "--restricted-receipt",
                "--family=broot",
                "--version=1.0-1",
                "--checksums=/protected/checksums",
                "--package=/protected/" + filename,
                "--select-member",
                filename,
                "usr/bin/broot",
            ],
        )

    def test_invalid_family_identity_rejected(self):
        for value in (
            "", None, "--option", "../family",
            "family name", "x" * 256,
        ):
            for field in ("family", "version"):
                with self.subTest(
                    field=field, value=value
                ):
                    arguments = self.arguments()
                    arguments[field] = value

                    with self.assertRaises(
                        receiver.ReceiverError
                    ):
                        receiver.restricted_family_command(
                            **arguments
                        )

    def test_archive_filename_disagreement_rejected(self):
        arguments = self.arguments()

        arguments["packages"] = {
            "wrong.pkg.tar.zst": (
                "/protected/broot-1.0-1-x86_64.pkg.tar.zst"
            ),
        }

        with self.assertRaises(
            receiver.ReceiverError
        ):
            receiver.restricted_family_command(
                **arguments
            )

    def test_unexpected_package_request_rejected(self):
        arguments = self.arguments()

        arguments["requests"] = {
            "unexpected.pkg.tar.zst": (
                "usr/bin/broot",
            ),
        }

        with self.assertRaises(
            receiver.ReceiverError
        ):
            receiver.restricted_family_command(
                **arguments
            )

    def test_duplicate_member_requests_rejected(self):
        arguments = self.arguments()

        filename = next(iter(
            arguments["packages"]
        ))

        arguments["requests"][filename] = (
            "usr/bin/broot",
            "usr/bin/broot",
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Duplicate family member request",
        ):
            receiver.restricted_family_command(
                **arguments
            )

    def test_invalid_member_paths_rejected(self):
        for member in (
            "", "/usr/bin/broot",
            "../usr/bin/broot",
            "usr//bin/broot",
            "usr/./bin/broot",
            "--option",
            "usr/bin/with space",
        ):
            with self.subTest(member=member):
                arguments = self.arguments()

                filename = next(iter(
                    arguments["packages"]
                ))

                arguments["requests"][filename] = (
                    member,
                )

                with self.assertRaises(
                    receiver.ReceiverError
                ):
                    receiver.restricted_family_command(
                        **arguments
                    )

    def test_member_request_limit_enforced(self):
        arguments = self.arguments()

        filename = next(iter(
            arguments["packages"]
        ))

        arguments["requests"][filename] = tuple(
            f"usr/bin/fixture{i}"
            for i in range(
                receiver.MAX_FAMILY_REQUESTS + 1
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "request count exceeds policy",
        ):
            receiver.restricted_family_command(
                **arguments
            )

    def test_archive_count_limit_enforced(self):
        arguments = self.arguments()

        arguments["packages"] = {
            f"fixture{i}.pkg.tar.zst":
                f"/protected/fixture{i}.pkg.tar.zst"
            for i in range(
                receiver.MAX_FAMILY_ARCHIVES + 1
            )
        }

        arguments["requests"] = {}

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Family package inventory outside policy",
        ):
            receiver.restricted_family_command(
                **arguments
            )

    def test_manifest_cannot_overlap_archive(self):
        arguments = self.arguments()

        arguments["checksums"] = next(iter(
            arguments["packages"].values()
        ))

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Checksum manifest overlaps package input",
        ):
            receiver.restricted_family_command(
                **arguments
            )


class CombinedFamilyExecutionTests(unittest.TestCase):

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(
            prefix="combined-family-"
        )

        self.addCleanup(scratch.cleanup)

        self.workspace = Path(scratch.name)
        self.events = []

        self.archive_helper = (
            "/protected/helpers/candidate_archive.py"
        )

        self.linkage_helper = (
            "/protected/helpers/candidate_linkage.py"
        )

        self.manifest = "/protected/checksums"

        self.version = "1.0-1"
        self.architecture = "x86_64"
        self.archive_digest = "a" * 64

        self.payload = b"x" * 4096

        self.member_digest = hashlib.sha256(
            self.payload
        ).hexdigest()

        linkage_path = Path(
            receiver.__file__
        ).with_name("candidate_linkage.py")

        spec = importlib.util.spec_from_file_location(
            "_combined_execution_linkage_policy",
            linkage_path,
        )

        self.policy = importlib.util.module_from_spec(
            spec
        )

        spec.loader.exec_module(self.policy)

        self.configure_family(
            "noctalia-custom"
        )

        self.root = self.enterContext(
            patch.object(receiver, "require_root")
        )

        self.helpers = self.enterContext(
            patch.object(
                receiver,
                "protected_helper_identities",
                side_effect=self.helper_identity,
            )
        )

        self.files = self.enterContext(
            patch.object(
                receiver,
                "protected_file_identity",
                side_effect=self.file_identity,
            )
        )

        self.acquire = self.enterContext(
            patch.object(
                receiver,
                "inspect_protected_family",
                side_effect=self.acquire_family,
            )
        )

        self.open_directory = self.enterContext(
            patch.object(
                receiver,
                "open_protected_directory",
                side_effect=self.open_fixture_directory,
            )
        )

        self.enterContext(
            patch.object(
                receiver,
                "validate_protected_directory",
                side_effect=self.validate_fixture_directory,
            )
        )

        self.materialize = self.enterContext(
            patch.object(
                receiver,
                "materialize_verified_member",
                side_effect=self.materialize_fixture,
            )
        )

        self.inspect_member = self.enterContext(
            patch.object(
                receiver,
                "inspect_materialized_member",
                side_effect=self.inspect_fixture,
            )
        )

    def configure_family(self, family):
        self.family = family

        filename = (
            f"{family}-{self.version}-"
            f"{self.architecture}.pkg.tar.zst"
        )

        self.names = {filename: family}

        self.checksums = {
            filename: self.archive_digest,
        }

        self.packages = {
            filename: "/protected/packages/" + filename,
        }

        package = {
            "identity": {
                "pkgname": family,
                "pkgver": self.version,
                "arch": self.architecture,
                "filename": filename,
                "sha256": self.archive_digest,
            },
        }

        required = (
            self.policy.REQUIRED_EXECUTABLES.get(
                family, ()
            )
        )

        if required:
            package["entries"] = {
                member: {
                    "type": "file",
                    "size": len(self.payload),
                }
                for member in required
            }

            package["selected_members"] = {
                member: {
                    "size": len(self.payload),
                    "sha256": self.member_digest,
                }
                for member in required
            }

        self.archive_receipt = {
            "schema": 1,
            "family": family,
            "version": self.version,
            "architecture": self.architecture,
            "structural_and_identity_validation": True,
            "packages": {family: package},
        }

        self.plan = (
            self.policy.bind_family_linkage_members(
                self.archive_receipt,
                expected_names=self.names,
                expected_checksums=self.checksums,
                family=self.family,
                version=self.version,
                architecture=self.architecture,
            )
        )

        self.helper_identities = {
            self.archive_helper: {
                self.archive_helper: ("archive-helper", 1),
            },
            self.linkage_helper: {
                self.linkage_helper: ("linkage-helper", 1),
            },
        }

        self.file_identities = {
            self.manifest: ("manifest", 1),
            **{
                package: ("archive", 1)
                for package in self.packages.values()
            },
        }

    def helper_identity(self, helper, dependencies):
        if helper == self.archive_helper:
            self.assertEqual(
                dependencies,
                (
                    "candidate_privileges.py",
                    "package_release_contract.py",
                ),
            )
        else:
            self.assertEqual(
                helper, self.linkage_helper
            )

            self.assertEqual(
                dependencies,
                ("candidate_privileges.py",),
            )

        return dict(
            self.helper_identities[helper]
        )

    def file_identity(self, path):
        return self.file_identities[str(path)]

    def manifest_reader(self, path):
        self.assertEqual(path, self.manifest)

        return dict(self.checksums)

    def acquire_family(self, **arguments):
        self.events.append("acquire")

        self.assertEqual(
            arguments["helper"],
            self.archive_helper,
        )

        self.assertEqual(
            arguments["packages"],
            self.packages,
        )

        self.assertEqual(
            arguments["expected_checksums"],
            self.checksums,
        )

        self.assertEqual(
            arguments["expected_names"],
            self.names,
        )

        self.assertEqual(
            arguments["family"],
            self.family,
        )

        return {
            "archive_receipt": self.archive_receipt,
            "member_plan": [
                dict(record)
                for record in self.plan
            ],
        }

    def open_fixture_directory(self, path):
        path = Path(path)

        self.assertTrue(
            path == self.workspace
            or path.parent == self.workspace
        )

        return os.open(
            path,
            receiver.DIRECTORY_FLAGS,
        )

    def validate_fixture_directory(self, info):
        # Ownership is substituted for this portable fixture.
        # Directory type and write permissions remain real.
        self.assertTrue(
            stat.S_ISDIR(info.st_mode)
        )

        self.assertEqual(
            info.st_mode & 0o022,
            0,
        )

    def materialize_fixture(self, **arguments):
        from pathlib import Path

        index = self.materialize.call_count - 1
        record = self.plan[index]

        self.events.append(
            ("materialize", record["member"])
        )

        destination = Path(
            arguments["destination"]
        )

        self.assertEqual(
            destination.parent,
            self.workspace,
        )

        self.assertTrue(
            destination.name.startswith(
                ".candidate-family-"
            )
        )

        self.assertEqual(
            stat.S_IMODE(destination.stat().st_mode),
            0o755,
        )

        # Earlier members must already have been removed.
        self.assertEqual(
            list(destination.iterdir()),
            [],
        )

        name = f"member-{index:04d}"

        self.assertEqual(
            arguments["destination_name"], name
        )

        self.assertEqual(
            arguments,
            {
                "uid": 65534,
                "gid": 65534,
                "helper": self.archive_helper,
                "package":
                    self.packages[record["filename"]],
                "name": record["name"],
                "version": record["version"],
                "architecture": record["architecture"],
                "archive_sha256": record["archive_sha256"],
                "member": record["member"],
                "member_size": record["size"],
                "member_sha256": record["sha256"],
                "destination": str(destination),
                "destination_name": name,
            },
        )

        path = destination / name

        with path.open("xb") as output:
            output.write(self.payload)

        path.chmod(0o644)

        return {
            "package":
                self.packages[record["filename"]],
            "name": record["name"],
            "version": record["version"],
            "architecture": record["architecture"],
            "archive_sha256": record["archive_sha256"],
            "member": record["member"],
            "size": record["size"],
            "sha256": record["sha256"],
            "path": str(path),
        }

    def inspect_fixture(self, **arguments):
        index = self.inspect_member.call_count - 1
        record = self.plan[index]

        self.events.append(
            ("inspect", record["member"])
        )

        path = Path(arguments["executable"])

        self.assertEqual(
            path.name,
            f"member-{index:04d}",
        )

        self.assertEqual(
            path.read_bytes(),
            self.payload,
        )

        self.assertEqual(
            stat.S_IMODE(path.stat().st_mode),
            0o644,
        )

        self.assertEqual(
            arguments["helper"],
            self.linkage_helper,
        )

        self.assertEqual(
            arguments["expected_size"],
            record["size"],
        )

        self.assertEqual(
            arguments["expected_sha256"],
            record["sha256"],
        )

        receipt = {
            "schema": 1,
            "static_linkage_validation": True,
            "sha256": record["sha256"],
            "architecture": "x86_64",
            "interpreter":
                "/lib64/ld-linux-x86-64.so.2",
            "needed": ["libc.so.6"],
            "program_headers": 3,
            "section_headers": 4,
            "dynamic_bytes": 80,
            "dynamic_string_bytes": 11,
            "interpreter_path":
                "/usr/lib/ld-linux-x86-64.so.2",
            "libraries": {
                "libc.so.6": "/usr/lib/libc.so.6",
            },
        }

        return arguments["receipt_validator"](
            receipt,
            expected_size=record["size"],
            expected_sha256=record["sha256"],
        )

    def validate(self, **overrides):
        arguments = {
            "uid": 65534,
            "gid": 65534,
            "archive_helper": self.archive_helper,
            "linkage_helper": self.linkage_helper,
            "family": self.family,
            "version": self.version,
            "architecture": self.architecture,
            "checksums": self.manifest,
            "packages": self.packages,
            "expected_names": self.names,
            "expected_checksums": self.checksums,
            "workspace": str(self.workspace),
            "request_builder":
                self.policy.build_family_linkage_requests,
            "evidence_binder":
                self.policy.bind_family_linkage_members,
            "manifest_reader": self.manifest_reader,
            "receipt_validator":
                self.policy.validate_linkage_receipt,
        }

        arguments.update(overrides)

        return receiver.validate_combined_family(
            **arguments
        )

    def assert_workspace_empty(self):
        self.assertEqual(
            list(self.workspace.iterdir()),
            [],
        )

    def assert_success(self, result, count):
        self.assertEqual(
            result["archive_receipt"],
            self.archive_receipt,
        )

        self.assertIs(
            result[
                "structural_and_identity_validation"
            ],
            True,
        )

        self.assertEqual(
            result["required_linkage_validation"],
            {
                "applicable": bool(count),
                "required_member_count": count,
                "validated_member_count": count,
            },
        )

        self.assertEqual(
            len(result["linkage_members"]),
            count,
        )

        for record, evidence in zip(
            self.plan,
            result["linkage_members"],
        ):
            self.assertEqual(
                {
                    key: value
                    for key, value in evidence.items()
                    if key != "linkage"
                },
                record,
            )

            self.assertEqual(
                evidence["linkage"]["sha256"],
                record["sha256"],
            )

            self.assertIs(
                evidence["linkage"][
                    "static_linkage_validation"
                ],
                True,
            )

        self.assert_workspace_empty()

    def test_complete_noctalia_family(self):
        result = self.validate()

        self.assert_success(result, 2)

        self.assertEqual(
            self.events,
            [
                "acquire",
                *[
                    event
                    for record in self.plan
                    for event in (
                        ("materialize", record["member"]),
                        ("inspect", record["member"]),
                    )
                ],
            ],
        )

    def test_complete_greeter_family(self):
        self.configure_family(
            "noctalia-greeter-t4t3z0r"
        )

        result = self.validate()

        self.assert_success(result, 3)

        self.assertEqual(
            self.materialize.call_count, 3
        )

        self.assertEqual(
            self.inspect_member.call_count, 3
        )

    def test_unrelated_family_requires_no_workspace(self):
        self.configure_family("broot")

        result = self.validate()

        self.assert_success(result, 0)

        self.open_directory.assert_not_called()
        self.materialize.assert_not_called()
        self.inspect_member.assert_not_called()

        self.assertFalse(
            any(
                call.args[0] == self.linkage_helper
                for call in self.helpers.call_args_list
            )
        )

    def test_archive_failure_prevents_materialization(self):
        self.acquire.side_effect = (
            receiver.ReceiverError(
                "Synthetic family rejection"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic family rejection",
        ):
            self.validate()

        self.open_directory.assert_not_called()
        self.materialize.assert_not_called()
        self.assert_workspace_empty()

    def test_missing_member_plan_rejected_before_workspace(self):
        self.acquire.return_value = {
            "archive_receipt": self.archive_receipt,
            "member_plan": [],
        }

        self.acquire.side_effect = None

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Combined family member inventory disagreement",
        ):
            self.validate()

        self.open_directory.assert_not_called()
        self.materialize.assert_not_called()

    def test_wrong_member_digest_rejected_before_workspace(self):
        plan = [
            dict(record)
            for record in self.plan
        ]

        plan[0]["sha256"] = "0" * 64

        self.acquire.side_effect = None

        self.acquire.return_value = {
            "archive_receipt": self.archive_receipt,
            "member_plan": plan,
        }

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Combined family member evidence disagreement",
        ):
            self.validate()

        self.open_directory.assert_not_called()
        self.materialize.assert_not_called()

    def test_first_materialization_failure_cleans_workspace(self):
        self.materialize.side_effect = (
            receiver.ReceiverError(
                "Synthetic materialization failure"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic materialization failure",
        ):
            self.validate()

        self.inspect_member.assert_not_called()
        self.assert_workspace_empty()

    def test_wrong_transfer_receipt_cleans_member(self):
        def wrong_transfer(**arguments):
            transfer = self.materialize_fixture(
                **arguments
            )

            transfer["sha256"] = "0" * 64

            return transfer

        self.materialize.side_effect = wrong_transfer

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Combined member transfer disagreement",
        ):
            self.validate()

        self.inspect_member.assert_not_called()
        self.assert_workspace_empty()

    def test_second_member_linkage_failure_rejects_family(self):
        self.configure_family(
            "noctalia-greeter-t4t3z0r"
        )

        def inspect(**arguments):
            if self.inspect_member.call_count == 2:
                raise receiver.ReceiverError(
                    "Synthetic second linkage failure"
                )

            return self.inspect_fixture(
                **arguments
            )

        self.inspect_member.side_effect = inspect

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic second linkage failure",
        ):
            self.validate()

        self.assertEqual(
            self.materialize.call_count, 2
        )

        self.assertEqual(
            self.inspect_member.call_count, 2
        )

        self.assert_workspace_empty()

    def test_third_member_linkage_failure_rejects_family(self):
        self.configure_family(
            "noctalia-greeter-t4t3z0r"
        )

        def inspect(**arguments):
            if self.inspect_member.call_count == 3:
                raise receiver.ReceiverError(
                    "Synthetic third linkage failure"
                )

            return self.inspect_fixture(
                **arguments
            )

        self.inspect_member.side_effect = inspect

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic third linkage failure",
        ):
            self.validate()

        self.assertEqual(
            self.materialize.call_count, 3
        )

        self.assert_workspace_empty()

    def test_linkage_schema_failure_cleans_workspace(self):
        def reject(receipt, **arguments):
            raise self.policy.LinkageError(
                "Synthetic linkage schema failure"
            )

        with self.assertRaisesRegex(
            self.policy.LinkageError,
            "Synthetic linkage schema failure",
        ):
            self.validate(
                receipt_validator=reject
            )

        self.assertEqual(
            self.materialize.call_count, 1
        )

        self.assert_workspace_empty()

    def test_archive_change_between_members_rejected(self):
        def inspect(**arguments):
            result = self.inspect_fixture(
                **arguments
            )

            package = next(iter(
                self.packages.values()
            ))

            self.file_identities[package] = (
                "archive", 2
            )

            return result

        self.inspect_member.side_effect = inspect

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Combined family archive identity changed",
        ):
            self.validate()

        self.assertEqual(
            self.materialize.call_count, 1
        )

        self.assert_workspace_empty()

    def test_linkage_helper_change_rejected(self):
        def inspect(**arguments):
            result = self.inspect_fixture(
                **arguments
            )

            self.helper_identities[
                self.linkage_helper
            ][self.linkage_helper] = (
                "linkage-helper", 2
            )

            return result

        self.inspect_member.side_effect = inspect

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Combined family linkage helper changed",
        ):
            self.validate()

        self.assert_workspace_empty()

    def test_final_manifest_disagreement_rejected(self):
        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Final combined family manifest disagreement",
        ):
            self.validate(
                manifest_reader=lambda path: {}
            )

        self.assertEqual(
            self.inspect_member.call_count, 2
        )

        self.assert_workspace_empty()

    def test_directory_cleanup_failure_prevents_acceptance(self):
        with patch.object(
            receiver.os,
            "rmdir",
            side_effect=OSError(
                "Synthetic directory cleanup failure"
            ),
        ):
            with self.assertRaisesRegex(
                OSError,
                "Synthetic directory cleanup failure",
            ):
                self.validate()

        self.assertEqual(
            self.inspect_member.call_count, 2
        )

        directories = list(
            self.workspace.iterdir()
        )

        self.assertEqual(len(directories), 1)

        self.assertEqual(
            list(directories[0].iterdir()),
            [],
        )

        directories[0].rmdir()

        self.assert_workspace_empty()

    def test_root_rejection_prevents_family_execution(self):
        self.root.side_effect = (
            receiver.ReceiverError(
                "Synthetic root rejection"
            )
        )

        with self.assertRaisesRegex(
            receiver.ReceiverError,
            "Synthetic root rejection",
        ):
            self.validate()

        self.acquire.assert_not_called()
        self.materialize.assert_not_called()

        self.assert_workspace_empty()


if __name__ == "__main__":
    unittest.main()
