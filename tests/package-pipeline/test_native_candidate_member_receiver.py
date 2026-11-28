"""Native Arch restricted reader and protected receiver tests."""

import hashlib
import importlib.util
import os
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

SCRIPTS = ROOT / "scripts/package-pipeline"

NATIVE_ENABLED = (
    os.environ.get("PACKAGE_PIPELINE_NATIVE_TESTS") == "1"
)

ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "HOME": "/tmp",
}

FILENAME = "broot-1.0-1-x86_64.pkg.tar.zst"
MEMBER = "usr/bin/broot"
PAYLOAD = b"fixture"

HELPERS = (
    "candidate_archive.py",
    "candidate_privileges.py",
    "candidate_member_receiver.py",
    "package_release_contract.py",
)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(
        name, path
    )

    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)

    return module


def digest(data):
    return hashlib.sha256(data).hexdigest()


@unittest.skipUnless(
    NATIVE_ENABLED,
    "Requires disposable native Arch CI container",
)
class NativeMemberReceiverTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.getresuid() != (0, 0, 0):
            raise RuntimeError(
                "Native receiver harness requires root"
            )

        if os.getresgid() != (0, 0, 0):
            raise RuntimeError(
                "Native receiver harness requires root group"
            )

        if os.environ.get("GITHUB_ACTIONS") != "true":
            raise RuntimeError(
                "Native receiver tests restricted to GitHub CI"
            )

        release = Path("/etc/os-release").read_text()

        if not re.search(
            r"^ID=arch$", release, re.MULTILINE
        ):
            raise RuntimeError(
                "Native receiver tests require Arch Linux"
            )

        for tool in (
            "python",
            "setpriv",
            "zstd",
            "bsdtar",
            "setfacl",
            "getfacl",
        ):
            if shutil.which(tool) is None:
                raise RuntimeError(
                    f"Required native tool missing: {tool}"
                )

        account = pwd.getpwnam("nobody")

        cls.uid = account.pw_uid
        cls.gid = account.pw_gid

        if cls.uid == 0 or cls.gid == 0:
            raise RuntimeError(
                "Invalid inspection account"
            )

        cls.receiver = load_module(
            "_native_member_receiver",
            SCRIPTS / "candidate_member_receiver.py",
        )

        cls.fixtures = load_module(
            "_native_member_receiver_fixtures",
            ROOT
            / "tests/package-pipeline/test_candidate_archive.py",
        )

    def setUp(self):
        # Do not use /tmp: its writable ancestor is
        # intentionally rejected by the receiver.
        scratch = tempfile.TemporaryDirectory(
            prefix="native-member-receiver-",
            dir="/var/lib",
        )

        self.addCleanup(scratch.cleanup)

        self.root = Path(scratch.name)
        self.root.chmod(0o755)

        self.helpers = self.root / "helpers"
        self.helpers.mkdir(mode=0o755)
        self.helpers.chmod(0o755)

        self.destination = self.root / "destination"
        self.destination.mkdir(mode=0o755)
        self.destination.chmod(0o755)

        self.target = self.destination / "analysis-input"

        for name in HELPERS:
            source = SCRIPTS / name
            target = self.helpers / name

            shutil.copyfile(source, target)
            target.chmod(0o644)

            self.assertEqual(
                digest(source.read_bytes()),
                digest(target.read_bytes()),
            )

        self.helper = self.helpers / "candidate_archive.py"

        self.guard = (
            self.helpers / "candidate_privileges.py"
        )

        self.package = self.root / FILENAME

        tar = self.fixtures.body() + bytes(1024)

        self.compressed = subprocess.run(
            ["/usr/bin/zstd", "-q", "-c"],
            input=tar,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env=ENVIRONMENT,
            timeout=30,
            check=True,
        ).stdout

        self.package.write_bytes(self.compressed)
        self.package.chmod(0o644)

        self.archive_digest = digest(self.compressed)
        self.member_digest = digest(PAYLOAD)

        # Independently establish the fixture member bytes.
        native = subprocess.check_output(
            [
                "/usr/bin/bsdtar",
                "-xOf",
                str(self.package),
                "--",
                MEMBER,
            ],
            cwd="/",
            env=ENVIRONMENT,
            timeout=30,
        )

        self.assertEqual(native, PAYLOAD)

        for path in (
            self.root,
            self.helpers,
            self.destination,
        ):
            descriptor = (
                self.receiver.open_protected_directory(path)
            )
            os.close(descriptor)

    def reader_arguments(self, **overrides):
        options = {
            "package": str(self.package),
            "name": "broot",
            "version": "1.0-1",
            "architecture": "x86_64",
            "archive-sha256": self.archive_digest,
            "member": MEMBER,
            "member-size": str(len(PAYLOAD)),
            "member-sha256": self.member_digest,
        }

        options.update(overrides)

        return [
            "stream-member",
            *[
                f"--{name}={value}"
                for name, value in options.items()
            ],
        ]

    def run_reader(self, command, **options):
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env=ENVIRONMENT,
            start_new_session=True,
            **options,
        )

        try:
            stdout, stderr = process.communicate(
                timeout=60
            )

        except subprocess.TimeoutExpired:
            os.killpg(
                process.pid, signal.SIGKILL
            )

            process.communicate(timeout=10)

            self.fail("Native member reader timed out")

        return process.returncode, stdout, stderr

    def restricted_reader(self, **overrides):
        command = self.receiver.restricted_command(
            self.uid,
            self.gid,
            self.helper,
            self.reader_arguments(**overrides),
        )

        return self.run_reader(command)

    def materialize(self, **overrides):
        options = {
            "uid": self.uid,
            "gid": self.gid,
            "helper": self.helper,
            "package": self.package,
            "name": "broot",
            "version": "1.0-1",
            "architecture": "x86_64",
            "archive_sha256": self.archive_digest,
            "member": MEMBER,
            "member_size": len(PAYLOAD),
            "member_sha256": self.member_digest,
            "destination": self.destination,
            "destination_name": self.target.name,
        }

        options.update(overrides)

        return self.receiver.materialize_verified_member(
            **options
        )

    def assert_empty_destination(self):
        self.assertEqual(
            list(self.destination.iterdir()),
            [],
        )

    def assert_reader_rejected(self, result):
        status, stdout, stderr = result

        self.assertNotEqual(status, 0)
        self.assertEqual(stdout, b"")
        self.assertTrue(stderr)

    def assert_materialization_rejected(self, **overrides):
        with self.assertRaises(
            (self.receiver.ReceiverError, OSError)
        ):
            self.materialize(**overrides)

        self.assert_empty_destination()

    def test_actual_restricted_binary_reader(self):
        status, stdout, stderr = (
            self.restricted_reader()
        )

        self.assertEqual(status, 0, stderr)
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout, PAYLOAD)
        self.assertEqual(
            digest(stdout), self.member_digest
        )

        self.assertEqual(
            self.package.read_bytes(),
            self.compressed,
        )

    def test_root_reader_rejected(self):
        result = self.run_reader([
            "/usr/bin/python",
            "-I", "-B",
            str(self.helper),
            *self.reader_arguments(),
        ])

        self.assert_reader_rejected(result)

    def test_incomplete_privilege_boundary_rejected(self):
        result = self.run_reader(
            [
                "/usr/bin/python",
                "-I", "-B",
                str(self.helper),
                *self.reader_arguments(),
            ],
            user=self.uid,
            group=self.gid,
            extra_groups=[],
        )

        self.assert_reader_rejected(result)

    def test_missing_guard_rejected(self):
        self.guard.unlink()

        self.assert_reader_rejected(
            self.restricted_reader()
        )

    def test_writable_guard_rejected(self):
        self.guard.chmod(0o666)

        self.assert_reader_rejected(
            self.restricted_reader()
        )

    def test_symlink_guard_rejected(self):
        original = self.guard.with_name(
            "guard-original.py"
        )

        self.guard.rename(original)
        self.guard.symlink_to(original.name)

        self.assert_reader_rejected(
            self.restricted_reader()
        )

    def test_actual_materialization(self):
        receipt = self.materialize()

        self.assertEqual(
            receipt,
            {
                "package": str(self.package),
                "name": "broot",
                "version": "1.0-1",
                "architecture": "x86_64",
                "archive_sha256": self.archive_digest,
                "member": MEMBER,
                "size": len(PAYLOAD),
                "sha256": self.member_digest,
                "path": str(self.target),
            },
        )

        self.assertEqual(
            self.target.read_bytes(),
            PAYLOAD,
        )

        info = self.target.lstat()

        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(info.st_uid, 0)
        self.assertEqual(info.st_nlink, 1)

        self.assertEqual(
            stat.S_IMODE(info.st_mode), 0o644
        )

        self.assertEqual(
            list(self.destination.iterdir()),
            [self.target],
        )

        self.assertEqual(
            self.package.read_bytes(),
            self.compressed,
        )

    def test_wrong_archive_digest_rejected(self):
        self.assert_materialization_rejected(
            archive_sha256="0" * 64,
        )

    def test_wrong_member_digest_rejected(self):
        self.assert_materialization_rejected(
            member_sha256="0" * 64,
        )

    def test_wrong_member_size_rejected(self):
        self.assert_materialization_rejected(
            member_size=len(PAYLOAD) + 1,
        )

    def test_missing_member_rejected(self):
        self.assert_materialization_rejected(
            member="usr/bin/absent",
        )

    def test_nonregular_member_rejected(self):
        self.assert_materialization_rejected(
            member="usr/bin",
        )

    def test_malformed_archive_rejected(self):
        self.package.write_bytes(
            b"not a compressed archive"
        )

        self.assert_materialization_rejected(
            archive_sha256=digest(
                self.package.read_bytes()
            ),
        )

    def test_archive_symlink_rejected(self):
        original = self.package.with_name(
            "original.pkg.tar.zst"
        )

        self.package.rename(original)
        self.package.symlink_to(original.name)

        self.assert_materialization_rejected()

    def test_archive_hardlink_rejected(self):
        os.link(
            self.package,
            self.root / "additional-link",
        )

        self.assert_materialization_rejected()

    def test_inspector_owned_archive_rejected(self):
        os.chown(
            self.package,
            self.uid,
            self.gid,
        )

        self.assert_materialization_rejected()

    def test_writable_helper_rejected(self):
        self.helper.chmod(0o666)

        self.assert_materialization_rejected()

    def test_writable_destination_rejected(self):
        self.destination.chmod(0o777)

        self.assert_materialization_rejected()

    def test_writable_ancestor_rejected(self):
        self.root.chmod(0o777)

        self.assert_materialization_rejected()

    def test_existing_destination_preserved(self):
        self.target.write_bytes(b"existing")

        with self.assertRaises(
            self.receiver.ReceiverError
        ):
            self.materialize()

        self.assertEqual(
            self.target.read_bytes(),
            b"existing",
        )

        self.assertEqual(
            list(self.destination.iterdir()),
            [self.target],
        )

    def test_default_acl_removed(self):
        subprocess.run(
            [
                "/usr/bin/setfacl",
                "-m",
                f"d:u:{self.uid}:rw-",
                str(self.destination),
            ],
            cwd="/",
            env=ENVIRONMENT,
            timeout=15,
            check=True,
        )

        self.materialize()

        acl = subprocess.check_output(
            [
                "/usr/bin/getfacl",
                "-cpn",
                str(self.target),
            ],
            cwd="/",
            env=ENVIRONMENT,
            timeout=15,
            text=True,
        )

        records = {
            line
            for line in acl.splitlines()
            if line
        }

        self.assertEqual(
            records,
            {
                "user::rw-",
                "group::r--",
                "other::r--",
            },
        )

    def test_inspector_cannot_modify_materialized_file(self):
        self.materialize()

        command = [
            "/usr/bin/setpriv",
            f"--reuid={self.uid}",
            f"--regid={self.gid}",
            "--clear-groups",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            "/usr/bin/python",
            "-I", "-B", "-c",
            (
                "import os, sys\n"
                "from pathlib import Path\n"
                "p = Path(sys.argv[1])\n"
                "assert os.access(p, os.R_OK)\n"
                "assert not os.access(p, os.W_OK)\n"
                "assert not os.access(p, os.X_OK)\n"
                "assert not os.access(p.parent, os.W_OK)\n"
                "try:\n"
                "    p.write_bytes(b'changed')\n"
                "except PermissionError:\n"
                "    pass\n"
                "else:\n"
                "    raise AssertionError('Writable member')\n"
            ),
            str(self.target),
        ]

        result = subprocess.run(
            command,
            cwd="/",
            env=ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )

        self.assertEqual(
            result.returncode, 0, result.stderr
        )

        self.assertEqual(
            self.target.read_bytes(),
            PAYLOAD,
        )


if __name__ == "__main__":
    unittest.main()
