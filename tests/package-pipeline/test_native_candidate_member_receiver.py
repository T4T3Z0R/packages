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


@unittest.skipUnless(
    NATIVE_ENABLED,
    "Requires disposable native Arch CI container",
)
class NativeCombinedFamilyTests(unittest.TestCase):

    VERSION = "1.0-1"

    @classmethod
    def setUpClass(cls):
        if (
            os.getresuid() != (0, 0, 0)
            or os.getresgid() != (0, 0, 0)
        ):
            raise RuntimeError(
                "Native combined harness requires root"
            )

        if os.environ.get("GITHUB_ACTIONS") != "true":
            raise RuntimeError(
                "Native combined tests restricted to GitHub CI"
            )

        if not re.search(
            r"^ID=arch$",
            Path("/etc/os-release").read_text(),
            re.MULTILINE,
        ):
            raise RuntimeError(
                "Native combined tests require Arch Linux"
            )

        for tool in (
            "python", "cc", "readelf", "lddtree",
            "setpriv", "zstd", "bsdtar",
            "setfacl", "getfacl",
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
            "_native_combined_receiver",
            SCRIPTS / "candidate_member_receiver.py",
        )

        cls.archive = load_module(
            "_native_combined_archive",
            SCRIPTS / "candidate_archive.py",
        )

        cls.linkage = load_module(
            "_native_combined_linkage",
            SCRIPTS / "candidate_linkage.py",
        )

        cls.registry = load_module(
            "_native_combined_registry",
            SCRIPTS / "package_release_contract.py",
        )

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(
            prefix="native-combined-family-",
            dir="/var/lib",
        )

        self.addCleanup(scratch.cleanup)

        self.root = Path(scratch.name)
        self.root.chmod(0o755)

        self.helpers = self.root / "helpers"
        self.workspace = self.root / "workspace"
        self.packages_dir = self.root / "packages"

        for directory in (
            self.helpers,
            self.workspace,
            self.packages_dir,
        ):
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)

        for name in (
            "candidate_archive.py",
            "candidate_linkage.py",
            "candidate_privileges.py",
            "package_release_contract.py",
        ):
            original = SCRIPTS / name
            target = self.helpers / name

            shutil.copyfile(original, target)
            target.chmod(0o644)

            self.assertEqual(
                digest(original.read_bytes()),
                digest(target.read_bytes()),
            )

        self.archive_helper = (
            self.helpers / "candidate_archive.py"
        )

        self.linkage_helper = (
            self.helpers / "candidate_linkage.py"
        )

        self.manifest = self.root / "candidate-SHA256SUMS"

        # Writable only by the inspection account. An ELF
        # execution would leave evidence in this directory.
        marker_area = self.root / "marker-area"

        marker_area.mkdir(mode=0o700)

        os.chown(
            marker_area, self.uid, self.gid
        )

        marker_area.chmod(0o700)

        self.marker = marker_area / "executed"

        self.addCleanup(self.assert_not_executed)

    def assert_not_executed(self):
        self.assertFalse(
            self.marker.exists(),
            "Candidate executable was executed",
        )

    def native_run(self, arguments, **options):
        defaults = {
            "cwd": "/",
            "env": ENVIRONMENT,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "timeout": 30,
            "check": True,
        }

        defaults.update(options)

        return subprocess.run(
            arguments,
            **defaults,
        )

    def compile_executable(self, index, *, bad=False):
        import json

        source = self.root / f"fixture-{index}.c"
        binary = self.root / f"fixture-{index}"

        source.write_text(
            "#include <stdio.h>\n"
            "int main(void) {\n"
            f" FILE *f = fopen({json.dumps(str(self.marker))},"
            ' "w");\n'
            " if (f) fclose(f);\n"
            f" return {index};\n"
            "}\n",
            encoding="ascii",
        )

        arguments = [
            "/usr/bin/cc",
            "-O0",
            "-fPIE",
            "-pie",
        ]

        if bad:
            arguments.extend([
                "-Wl,--enable-new-dtags",
                "-Wl,-rpath,$ORIGIN",
            ])

        arguments.extend([
            "-o", str(binary),
            str(source),
        ])

        self.native_run(arguments)

        binary.chmod(0o644)

        metadata = self.native_run([
            "/usr/bin/readelf",
            "-h", "-l", "-d",
            str(binary),
        ]).stdout

        self.assertIn(
            b"libc.so.6", metadata
        )

        self.assertIn(
            b"/lib64/ld-linux-x86-64.so.2",
            metadata,
        )

        if bad:
            self.assertIn(
                b"RUNPATH", metadata
            )
        else:
            self.assertNotIn(
                b"RUNPATH", metadata
            )

        return binary.read_bytes()

    def build_archive(
        self,
        name,
        architecture,
        members,
    ):
        import io
        import tarfile

        filename = (
            f"{name}-{self.VERSION}-"
            f"{architecture}.pkg.tar.zst"
        )

        path = self.packages_dir / filename

        pkginfo = (
            f"pkgname = {name}\n"
            f"pkgbase = {name}\n"
            f"pkgver = {self.VERSION}\n"
            "pkgdesc = Native combined fixture\n"
            "url = https://example.invalid\n"
            "builddate = 1\n"
            "packager = Native CI fixture\n"
            f"size = {sum(map(len, members.values()))}\n"
            f"arch = {architecture}\n"
            "license = MIT\n"
        ).encode("ascii")

        buffer = io.BytesIO()

        with tarfile.open(
            fileobj=buffer,
            mode="w",
            format=tarfile.USTAR_FORMAT,
        ) as tar:

            def add(name, data=None, mode=0o644):
                entry = tarfile.TarInfo(name)

                entry.uid = 0
                entry.gid = 0
                entry.uname = "root"
                entry.gname = "root"
                entry.mtime = 1
                entry.mode = mode

                if data is None:
                    entry.type = tarfile.DIRTYPE
                    entry.size = 0

                    tar.addfile(entry)
                else:
                    entry.size = len(data)

                    tar.addfile(
                        entry,
                        io.BytesIO(data),
                    )

            add(".PKGINFO", pkginfo)
            add(".BUILDINFO", b"format = 2\n")
            add(".MTREE", b"fixture")

            parents = {
                parent.as_posix()
                for member in members
                for parent in Path(member).parents
                if parent.as_posix() != "."
            }

            for parent in sorted(
                parents,
                key=lambda value: (
                    value.count("/"),
                    value,
                ),
            ):
                add(parent, mode=0o755)

            for member, payload in sorted(
                members.items()
            ):
                add(
                    member,
                    payload,
                    mode=0o755,
                )

        # Establish structural fixture validity before
        # invoking any restricted family inspection.
        inventory = self.archive.inspect_tar_stream(
            io.BytesIO(buffer.getvalue())
        )

        self.assertTrue(
            inventory["structural_inventory_only"]
        )

        self.assertTrue(
            self.archive.REQUIRED_METADATA
            <= inventory["entries"].keys()
        )

        for member, payload in members.items():
            self.assertEqual(
                inventory["entries"][member]["type"],
                "file",
            )

            self.assertEqual(
                inventory["entries"][member]["size"],
                len(payload),
            )

        compressed = self.native_run(
            ["/usr/bin/zstd", "-q", "-c"],
            input=buffer.getvalue(),
        ).stdout

        path.write_bytes(compressed)
        path.chmod(0o644)

        # Independently confirm the selected archive bytes
        # through native libarchive extraction.
        for member, payload in members.items():
            extracted = self.native_run([
                "/usr/bin/bsdtar",
                "-xOf",
                str(path),
                "--",
                member,
            ]).stdout

            self.assertEqual(
                extracted,
                payload,
            )

        return filename, path

    def prepare_family(
        self,
        family,
        *,
        missing=None,
        malformed=None,
        bad_linkage=None,
    ):
        self.family = family

        contract = self.registry.output_contract(
            family
        )

        self.architecture = contract.architecture

        self.names = {}
        self.packages = {}
        self.checksums = {}
        self.member_payloads = {}

        for name in contract.required:
            required = sorted(
                self.linkage.REQUIRED_EXECUTABLES.get(
                    name, ()
                )
            )

            members = {}

            if required:
                for index, member in enumerate(
                    required
                ):
                    if member == missing:
                        continue

                    if member == malformed:
                        payload = b"not an ELF executable"
                    else:
                        payload = self.compile_executable(
                            index,
                            bad=(member == bad_linkage),
                        )

                    members[member] = payload

                    self.member_payloads[
                        (name, member)
                    ] = payload

            else:
                members[
                    f"usr/bin/{name}"
                ] = b"non-ELF structural fixture\n"

            if not members:
                members[
                    "usr/share/native-fixture"
                ] = b"fixture\n"

            filename, path = self.build_archive(
                name,
                contract.architecture,
                members,
            )

            self.names[filename] = name
            self.packages[filename] = str(path)

            self.checksums[filename] = digest(
                path.read_bytes()
            )

        self.registry.validate_output_names(
            family,
            self.names.values(),
        )

        self.assertEqual(
            self.archive.expected_batch_names(
                contract,
                self.VERSION,
                self.checksums,
            ),
            self.names,
        )

        self.manifest.write_text(
            "".join(
                f"{checksum}  {filename}\n"
                for filename, checksum in sorted(
                    self.checksums.items()
                )
            ),
            encoding="ascii",
        )

        self.manifest.chmod(0o644)

        self.assertEqual(
            self.archive.read_checksum_manifest(
                self.manifest
            ),
            self.checksums,
        )

    def validate(self, **overrides):
        arguments = {
            "uid": self.uid,
            "gid": self.gid,
            "archive_helper": self.archive_helper,
            "linkage_helper": self.linkage_helper,
            "family": self.family,
            "version": self.VERSION,
            "architecture": self.architecture,
            "checksums": self.manifest,
            "packages": self.packages,
            "expected_names": self.names,
            "expected_checksums": self.checksums,
            "workspace": self.workspace,
            "request_builder":
                self.linkage.build_family_linkage_requests,
            "evidence_binder":
                self.linkage.bind_family_linkage_members,
            "manifest_reader":
                self.archive.read_checksum_manifest,
            "receipt_validator":
                self.linkage.validate_linkage_receipt,
        }

        arguments.update(overrides)

        from unittest.mock import patch

        real_read = os.read
        real_collect = self.receiver.receive_linkage_receipt

        # Retain bounded rejection evidence for synthetic
        # native fixtures without printing child stderr.
        # The actual collector still enforces every
        # transport and validation requirement.
        self.inspector_diagnostics = []

        def collect_with_diagnostics(process, *, deadline):
            diagnostic_fd = process.stderr.fileno()
            diagnostics = bytearray()

            def capture_read(fd, size):
                data = real_read(fd, size)

                if fd == diagnostic_fd:
                    remaining = (
                        self.receiver.MAX_DIAGNOSTIC_BYTES
                        - len(diagnostics)
                    )

                    if remaining > 0:
                        diagnostics.extend(data[:remaining])

                return data

            try:
                with patch.object(
                    self.receiver.os,
                    "read",
                    side_effect=capture_read,
                ):
                    return real_collect(
                        process,
                        deadline=deadline,
                    )

            except self.receiver.ReceiverError:
                self.inspector_diagnostics.append(
                    bytes(diagnostics)
                )

                raise

        with patch.object(
            self.receiver,
            "receive_linkage_receipt",
            side_effect=collect_with_diagnostics,
        ):
            return self.receiver.validate_combined_family(
                **arguments
            )

    def assert_workspace_empty(self):
        self.assertEqual(
            list(self.workspace.iterdir()),
            [],
        )

        self.assert_not_executed()

    def assert_success(self, result, count):
        self.assertEqual(
            result["family"], self.family
        )

        self.assertEqual(
            result["version"], self.VERSION
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

        evidence = result["linkage_members"]

        self.assertEqual(len(evidence), count)

        self.assertEqual(
            {
                (record["name"], record["member"])
                for record in evidence
            },
            set(self.member_payloads),
        )

        for record in evidence:
            payload = self.member_payloads[
                (record["name"], record["member"])
            ]

            self.assertEqual(
                record["size"], len(payload)
            )

            self.assertEqual(
                record["sha256"],
                digest(payload),
            )

            self.assertEqual(
                record["archive_sha256"],
                self.checksums[
                    record["filename"]
                ],
            )

            linkage = record["linkage"]

            self.assertIs(
                linkage["static_linkage_validation"],
                True,
            )

            self.assertEqual(
                linkage["sha256"],
                digest(payload),
            )

            self.assertIn(
                "libc.so.6",
                linkage["needed"],
            )

        for filename, package in self.packages.items():
            self.assertEqual(
                digest(Path(package).read_bytes()),
                self.checksums[filename],
            )

        self.assert_workspace_empty()

    def assert_rejected(self, **overrides):
        with self.assertRaises((
            self.receiver.ReceiverError,
            self.archive.ArchiveError,
            self.linkage.LinkageError,
            OSError,
        )):
            self.validate(**overrides)

        self.assert_workspace_empty()

    def test_native_complete_noctalia_family(self):
        self.prepare_family("noctalia-custom")

        self.assert_success(
            self.validate(),
            2,
        )

    def test_native_complete_greeter_family(self):
        self.prepare_family(
            "noctalia-greeter-t4t3z0r"
        )

        self.assert_success(
            self.validate(),
            3,
        )

    def test_native_unrelated_non_elf_family(self):
        self.prepare_family("broot")

        # An unrelated family must not require the
        # linkage helper to exist.
        self.linkage_helper.unlink()

        self.assert_success(
            self.validate(),
            0,
        )

    def test_native_missing_required_member(self):
        self.prepare_family(
            "noctalia-custom",
            missing="usr/bin/noctalia",
        )

        self.assert_rejected()

        self.assertEqual(
            len(self.inspector_diagnostics), 1
        )

        self.assertIn(
            b"Missing selected archive members:",
            self.inspector_diagnostics[0],
        )

        self.assertIn(
            b"usr/bin/noctalia",
            self.inspector_diagnostics[0],
        )

    def test_native_malformed_required_elf(self):
        from unittest.mock import patch

        self.prepare_family(
            "noctalia-custom",
            malformed="usr/bin/noctalia",
        )

        with patch.object(
            self.receiver,
            "inspect_materialized_member",
            wraps=self.receiver.inspect_materialized_member,
        ) as inspector:
            self.assert_rejected()

        # The family must reach actual ELF inspection.
        # An earlier archive rejection is not sufficient.
        inspector.assert_called_once()

        self.assertEqual(
            inspector.call_args.kwargs["expected_sha256"],
            digest(b"not an ELF executable"),
        )

        self.assertEqual(
            len(self.inspector_diagnostics), 1
        )

        self.assertIn(
            b"ELF range outside file bounds",
            self.inspector_diagnostics[0],
        )

    def test_native_later_linkage_failure(self):
        from unittest.mock import patch

        self.prepare_family(
            "noctalia-greeter-t4t3z0r",
            bad_linkage=(
                "usr/bin/noctalia-greeter-compositor"
            ),
        )

        accepted = []

        real_inspector = (
            self.receiver.inspect_materialized_member
        )

        def record_inspection(**arguments):
            result = real_inspector(**arguments)

            accepted.append(
                result["sha256"]
            )

            return result

        # Observe the actual inspector calls without
        # replacing their execution or validation.
        with patch.object(
            self.receiver,
            "inspect_materialized_member",
            side_effect=record_inspection,
        ):
            self.assert_rejected()

        self.assertEqual(
            len(accepted),
            2,
        )

        self.assertEqual(
            len(self.inspector_diagnostics), 1
        )

        self.assertIn(
            b"Unsupported candidate dynamic tag: DT_RUNPATH",
            self.inspector_diagnostics[0],
        )

    def test_native_manifest_disagreement(self):
        self.prepare_family("broot")

        self.manifest.write_text(
            "".join(
                f"{'0' * 64}  {filename}\n"
                for filename in sorted(self.checksums)
            ),
            encoding="ascii",
        )

        self.assert_rejected()

    def test_native_writable_manifest_rejected(self):
        self.prepare_family("broot")

        self.manifest.chmod(0o666)

        self.assert_rejected()

    def test_native_writable_archive_rejected(self):
        self.prepare_family("broot")

        package = Path(next(iter(
            self.packages.values()
        )))

        package.chmod(0o666)

        self.assert_rejected()

    def test_native_writable_contract_rejected(self):
        self.prepare_family("broot")

        contract = (
            self.helpers
            / "package_release_contract.py"
        )

        contract.chmod(0o666)

        self.assert_rejected()

    def test_native_symlink_contract_rejected(self):
        self.prepare_family("broot")

        contract = (
            self.helpers
            / "package_release_contract.py"
        )

        original = contract.with_name(
            "contract-original.py"
        )

        contract.rename(original)
        contract.symlink_to(original.name)

        self.assert_rejected()

    def test_native_helper_bytecode_cache_rejected(self):
        self.prepare_family("broot")

        (
            self.helpers / "__pycache__"
        ).mkdir(mode=0o755)

        self.assert_rejected()

    def test_native_inspector_owned_contract_rejected(self):
        self.prepare_family("broot")

        os.chown(
            self.helpers
            / "package_release_contract.py",
            self.uid,
            self.gid,
        )

        self.assert_rejected()

    def test_native_root_family_cli_rejected(self):
        self.prepare_family("broot")

        arguments = [
            "/usr/bin/python",
            "-I", "-B",
            str(self.archive_helper),
            "validate-family",
            "--restricted-receipt",
            "--family=" + self.family,
            "--version=" + self.VERSION,
            "--checksums=" + str(self.manifest),
            *[
                "--package=" + path
                for path in self.packages.values()
            ],
        ]

        result = self.native_run(
            arguments,
            check=False,
        )

        self.assertNotEqual(
            result.returncode, 0
        )

        self.assertEqual(
            result.stdout, b""
        )

        self.assertTrue(result.stderr)

    def test_native_incomplete_family_privileges_rejected(self):
        self.prepare_family("broot")

        result = self.native_run(
            [
                "/usr/bin/python",
                "-I", "-B",
                str(self.archive_helper),
                "validate-family",
                "--restricted-receipt",
                "--family=" + self.family,
                "--version=" + self.VERSION,
                "--checksums=" + str(self.manifest),
                *[
                    "--package=" + path
                    for path in self.packages.values()
                ],
            ],
            check=False,
            user=self.uid,
            group=self.gid,
            extra_groups=[],
        )

        self.assertNotEqual(
            result.returncode, 0
        )

        self.assertEqual(
            result.stdout, b""
        )

        self.assertTrue(result.stderr)


if __name__ == "__main__":
    unittest.main()
