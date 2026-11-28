"""Native Arch privilege-boundary tests for candidate intake."""

import hashlib
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

HELPER = (
    ROOT
    / "scripts"
    / "package-pipeline"
    / "candidate_intake.py"
)

NATIVE = (
    os.environ.get("PACKAGE_PIPELINE_NATIVE_TESTS") == "1"
)

PACKAGE = "example-1.0-1-x86_64.pkg.tar.zst"

PAYLOAD = bytes(range(256)) * 8193


@unittest.skipUnless(
    NATIVE,
    "Native candidate intake tests require explicit opt-in",
)
class NativeCandidateIntakeTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.getuid() != 0 or os.geteuid() != 0:
            raise RuntimeError("Native intake tests require root")

        release = Path("/etc/os-release").read_text()

        if "ID=arch\n" not in release:
            raise RuntimeError("Native intake tests require Arch")

        for tool in (
            "python3",
            "runuser",
            "useradd",
            "userdel",
            "usermod",
            "gpasswd",
            "setfacl",
            "getfacl",
        ):
            if not shutil.which(tool):
                raise RuntimeError(
                    f"Required native tool missing: {tool}"
                )

        for name in ("builder", "builduser"):
            try:
                pwd.getpwnam(name)
            except KeyError:
                continue

            raise RuntimeError(
                f"Refusing existing build account: {name}"
            )

        cls.user = "builduser"

        subprocess.run(
            ["useradd", "--create-home", cls.user],
            check=True,
            timeout=30,
        )

        cls.addClassCleanup(
            subprocess.run,
            ["userdel", "-r", cls.user],
            check=True,
            timeout=30,
        )

        cls.account = pwd.getpwnam(cls.user)

        if (
            cls.account.pw_uid == 0
            or cls.account.pw_gid == 0
        ):
            raise RuntimeError("Invalid test account identity")

        cls.host_account = pwd.getpwnam("nobody")

        if (
            cls.host_account.pw_uid == 0
            or cls.host_account.pw_uid == cls.account.pw_uid
            or cls.host_account.pw_gid == 0
        ):
            raise RuntimeError(
                "Invalid distinct runner fixture identity"
            )

    def setUp(self):
        # Destination intake deliberately rejects writable
        # ancestors, including world-writable /tmp.
        self.fixture = tempfile.TemporaryDirectory(
            prefix="native-candidate-intake-",
            dir="/",
        )

        self.addCleanup(self.fixture.cleanup)

        self.root = Path(self.fixture.name)
        self.root.chmod(0o755)

        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o755)

        self.build = self.workspace / "build"
        self.build.mkdir(mode=0o755)

        self.leaf = self.build / "example"
        self.leaf.mkdir(mode=0o755)

        os.chown(
            self.leaf,
            self.account.pw_uid,
            self.account.pw_gid,
        )

        self.destination = self.workspace / "candidate"
        self.destination.mkdir(mode=0o755)

        self.trusted = self.workspace / "trusted"
        self.trusted.mkdir(mode=0o755)

        self.helper = self.trusted / "candidate_intake.py"
        shutil.copyfile(HELPER, self.helper)
        self.helper.chmod(0o644)

        self.source = self.leaf / PACKAGE

        self.source.write_bytes(PAYLOAD)

        os.chown(
            self.source,
            self.account.pw_uid,
            self.account.pw_gid,
        )

        self.source.chmod(0o600)

        self.target = self.destination / PACKAGE

    def stage(self, *, source=None, destination=None):
        return subprocess.run(
            [
                sys.executable,
                "-I",
                str(self.helper),
                "stage",
                "--user",
                self.user,
                "--source",
                str(source or self.source),
                "--destination",
                str(destination or self.destination),
            ],
            cwd="/",
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def as_builder(self, *command):
        return subprocess.run(
            [
                "runuser",
                "-u",
                self.user,
                "--",
                "env",
                "-i",
                f"HOME={self.account.pw_dir}",
                "PATH=/usr/bin:/bin",
                "LANG=C.UTF-8",
                *map(str, command),
            ],
            cwd="/",
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def assert_empty_destination(self):
        self.assertEqual(
            list(self.destination.iterdir()),
            [],
        )

    def assert_rejected(self, result, message=None):
        self.assertNotEqual(
            result.returncode,
            0,
            result.stdout,
        )

        self.assertEqual(result.stdout, "")

        if message:
            self.assertIn(message, result.stderr)

        self.assert_empty_destination()

    def assert_staged(self, result):
        self.assertEqual(
            result.returncode,
            0,
            result.stderr,
        )

        digest = hashlib.sha256(PAYLOAD).hexdigest()

        self.assertEqual(
            result.stdout,
            f"{digest}  {PACKAGE}\n",
        )

        info = self.target.lstat()

        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(info.st_uid, 0)
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(
            stat.S_IMODE(info.st_mode),
            0o644,
        )

        self.assertEqual(self.target.read_bytes(), PAYLOAD)

        self.assertEqual(
            list(self.destination.iterdir()),
            [self.target],
        )

        self.assertEqual(
            self.as_builder("test", "-r", self.target).returncode,
            0,
        )

        self.assertNotEqual(
            self.as_builder("test", "-w", self.target).returncode,
            0,
        )

    def test_stage_exact_bytes(self):
        self.assert_staged(self.stage())

        self.assertEqual(
            self.source.read_bytes(),
            PAYLOAD,
        )

    def test_stage_with_distinct_runner_owned_ancestors(self):
        for path in (self.root, self.workspace):
            os.chown(
                path,
                self.host_account.pw_uid,
                self.host_account.pw_gid,
            )

        self.assert_staged(self.stage())

    def test_source_permissions_not_preserved(self):
        self.source.chmod(0o700)

        self.assert_staged(self.stage())

        self.assertEqual(
            stat.S_IMODE(self.source.stat().st_mode),
            0o700,
        )

    def test_staged_bytes_independent_of_builder_source(self):
        self.assert_staged(self.stage())

        result = self.as_builder(
            "bash",
            "-c",
            'printf changed > "$1"',
            "_",
            self.source,
        )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr,
        )

        self.assertEqual(
            self.source.read_bytes(),
            b"changed",
        )

        self.assertEqual(
            self.target.read_bytes(),
            PAYLOAD,
        )

    def test_builder_cannot_replace_staged_candidate(self):
        self.assert_staged(self.stage())

        for operation in (
            ("chmod", "0777", self.target),
            ("rm", "-f", self.target),
            ("mv", self.source, self.target),
            (
                "bash",
                "-c",
                'printf changed > "$1"',
                "_",
                self.target,
            ),
        ):
            with self.subTest(operation=operation):
                result = self.as_builder(*operation)

                self.assertNotEqual(
                    result.returncode,
                    0,
                    result.stdout,
                )

                self.assertEqual(
                    self.target.read_bytes(),
                    PAYLOAD,
                )

    def test_reject_root_owned_source(self):
        os.chown(self.source, 0, 0)
        self.source.chmod(0o644)

        self.assert_rejected(
            self.stage(),
            "owner mismatch",
        )

    def test_reject_source_symlink(self):
        protected = self.trusted / "protected"
        protected.write_bytes(b"protected-data")
        protected.chmod(0o600)

        self.source.unlink()
        self.source.symlink_to(protected)

        self.assert_rejected(self.stage(), "not regular")

        self.assertEqual(
            protected.read_bytes(),
            b"protected-data",
        )

    def test_reject_source_directory_symlink(self):
        alias = self.leaf / "alias"
        alias.symlink_to(
            self.leaf,
            target_is_directory=True,
        )

        self.assert_rejected(
            self.stage(source=alias / PACKAGE),
        )

    def test_reject_multiple_source_hardlinks(self):
        alias = self.leaf / "alias"

        os.link(self.source, alias)

        self.assert_rejected(
            self.stage(),
            "multiple links",
        )

    def test_reject_empty_source(self):
        self.source.write_bytes(b"")

        self.assert_rejected(
            self.stage(),
            "size outside policy",
        )

    def test_reject_fifo_source(self):
        self.source.unlink()
        os.mkfifo(self.source, 0o600)

        os.chown(
            self.source,
            self.account.pw_uid,
            self.account.pw_gid,
        )

        self.assert_rejected(
            self.stage(),
            "not regular",
        )

    def test_reject_directory_source(self):
        self.source.unlink()
        self.source.mkdir(mode=0o755)

        self.assert_rejected(
            self.stage(),
            "not regular",
        )

    def test_reject_unreadable_source(self):
        self.source.chmod(0)

        self.assert_rejected(self.stage())

    def test_reject_existing_destination_file(self):
        self.target.write_bytes(b"existing")

        result = self.stage()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

        self.assertIn(
            "destination already exists",
            result.stderr,
        )

        self.assertEqual(
            self.target.read_bytes(),
            b"existing",
        )

        self.assertEqual(
            list(self.destination.iterdir()),
            [self.target],
        )

    def test_reject_existing_destination_symlink(self):
        missing = self.trusted / "missing"

        self.target.symlink_to(missing)

        result = self.stage()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

        self.assertIn(
            "destination already exists",
            result.stderr,
        )

        self.assertTrue(self.target.is_symlink())
        self.assertFalse(missing.exists())

        self.assertEqual(
            list(self.destination.iterdir()),
            [self.target],
        )

    def test_reject_destination_directory_symlink(self):
        alias = self.workspace / "alias"

        alias.symlink_to(
            self.destination,
            target_is_directory=True,
        )

        self.assert_rejected(
            self.stage(destination=alias),
        )

    def test_reject_builder_owned_destination(self):
        os.chown(
            self.destination,
            self.account.pw_uid,
            self.account.pw_gid,
        )

        self.assert_rejected(
            self.stage(),
            "Builder-owned protected directory ancestor",
        )

    def test_reject_builder_owned_destination_ancestor(self):
        os.chown(
            self.workspace,
            self.account.pw_uid,
            self.account.pw_gid,
        )

        self.workspace.chmod(0o755)

        self.assert_rejected(
            self.stage(),
            "Builder-owned protected directory ancestor",
        )

    def test_reject_group_writable_destination_ancestor(self):
        self.workspace.chmod(0o775)

        self.assert_rejected(
            self.stage(),
            "Writable protected directory ancestor",
        )

    def test_reject_world_writable_destination_ancestor(self):
        self.workspace.chmod(0o777)

        self.assert_rejected(
            self.stage(),
            "Writable protected directory ancestor",
        )

    def test_reject_inaccessible_destination(self):
        self.destination.chmod(0o700)

        self.assert_rejected(
            self.stage(),
            "Protected ancestor is inaccessible",
        )


    def test_reject_destination_access_acl(self):
        subprocess.run(
            [
                "setfacl",
                "-m",
                f"u:{self.user}:rwx",
                str(self.destination),
            ],
            check=True,
            timeout=30,
        )

        # Confirm the fixture actually grants effective access.
        self.assertEqual(
            self.as_builder(
                "test", "-w", self.destination
            ).returncode,
            0,
        )

        self.assert_rejected(self.stage())

    def test_remove_inherited_default_acl(self):
        subprocess.run(
            [
                "setfacl",
                "-m",
                f"d:u:{self.user}:rwx",
                str(self.destination),
            ],
            check=True,
            timeout=30,
        )

        # Prove the default ACL is inherited by ordinary files.
        probe = self.destination / "acl-probe"
        probe.write_bytes(b"probe")
        probe.chmod(0o660)

        try:
            self.assertIn(
                "system.posix_acl_access",
                os.listxattr(probe),
            )

            self.assertEqual(
                self.as_builder(
                    "test", "-w", probe
                ).returncode,
                0,
            )
        finally:
            probe.unlink()

        self.assert_staged(self.stage())

        self.assertNotIn(
            "system.posix_acl_access",
            os.listxattr(self.target),
        )

        result = subprocess.run(
            [
                "getfacl",
                "-cp",
                str(self.target),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertNotIn(
            f"user:{self.user}:",
            result.stdout,
        )

    def inject_reader_failure(self, body, *, timeout=None):
        # Modify only the protected disposable helper fixture.
        # The repository implementation is never modified here.
        source = self.helper.read_text()

        anchor = "def stream_source(source):\n"

        self.assertEqual(source.count(anchor), 1)

        replacement = anchor + body

        updated = source.replace(
            anchor,
            replacement,
            1,
        )

        if timeout is not None:
            original = "TRANSFER_TIMEOUT = 600"

            self.assertEqual(
                updated.count(original),
                1,
            )

            updated = updated.replace(
                original,
                f"TRANSFER_TIMEOUT = {timeout}",
                1,
            )

        compile(
            updated,
            str(self.helper),
            "exec",
        )

        self.helper.write_text(updated)

    def test_partial_transfer_failure_cleanup(self):
        self.inject_reader_failure(
            "    sys.stdout.buffer.write("
            "b'partial-data' * 16384)\n"
            "    sys.stdout.buffer.flush()\n"
            "    raise IntakeError("
            "'Injected reader failure after partial transfer')\n"
        )

        result = self.stage()

        self.assert_rejected(
            result,
            "Unprivileged candidate reader failed",
        )

        self.assertIn(
            "Injected reader failure after partial transfer",
            result.stderr,
        )

    def test_reader_timeout_terminates_process(self):
        marker = self.leaf / "reader.pid"

        body = (
            "    import time\n"
            f"    Path({str(marker)!r}).write_text("
            "str(os.getpid()))\n"
            "    sys.stdout.buffer.write(b'partial-data')\n"
            "    sys.stdout.buffer.flush()\n"
            "    time.sleep(120)\n"
        )

        self.inject_reader_failure(
            body,
            timeout=5,
        )

        result = self.stage()

        self.assert_rejected(
            result,
            "Candidate transfer timed out",
        )

        self.assertTrue(
            marker.is_file(),
            "Reader never reached the injected timeout fixture",
        )

        pid = int(marker.read_text())

        self.assertGreater(pid, 1)

        self.assertFalse(
            Path(f"/proc/{pid}").exists(),
            "Timed-out reader process was not reaped",
        )

    def test_reject_privileged_supplementary_group(self):
        subprocess.run(
            [
                "usermod",
                "-aG",
                "root",
                self.user,
            ],
            check=True,
            timeout=30,
        )

        try:
            self.assertIn(
                0,
                os.getgrouplist(
                    self.user,
                    self.account.pw_gid,
                ),
            )

            self.assert_rejected(
                self.stage(),
                "Builder has privileged supplementary group",
            )
        finally:
            subprocess.run(
                [
                    "gpasswd",
                    "-d",
                    self.user,
                    "root",
                ],
                check=True,
                timeout=30,
            )

        self.assertNotIn(
            0,
            os.getgrouplist(
                self.user,
                self.account.pw_gid,
            ),
        )



if __name__ == "__main__":
    unittest.main()
