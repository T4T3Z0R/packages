"""Native archive, process and privilege boundary regressions."""

import ctypes
import ctypes.util
import hashlib
import importlib.util
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]

HELPER = Path(
    "scripts/package-pipeline/candidate_archive.py"
)

CONTRACT = Path(
    "scripts/package-pipeline/package_release_contract.py"
)

PORTABLE = Path(
    "tests/package-pipeline/test_candidate_archive.py"
)

NATIVE = Path(
    "tests/package-pipeline/test_native_candidate_archive.py"
)

FILENAME = "broot-1.0-1-x86_64.pkg.tar.zst"

ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "HOME": "/tmp",
}

NATIVE_ENABLED = (
    os.environ.get("PACKAGE_PIPELINE_NATIVE_TESTS") == "1"
)


def load_fixtures():
    path = ROOT / PORTABLE

    spec = importlib.util.spec_from_file_location(
        "_native_archive_fixtures",
        path,
    )

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    return module


def native_inventory(path):
    """Read independent member metadata through native libarchive."""
    library = ctypes.util.find_library("archive")

    if not library:
        raise RuntimeError("Native libarchive unavailable")

    lib = ctypes.CDLL(library)
    pointer = ctypes.c_void_p
    integer = ctypes.c_int
    string = ctypes.c_char_p
    integer64 = ctypes.c_int64

    def bind(name, arguments, result):
        function = getattr(lib, name)
        function.argtypes = arguments
        function.restype = result
        return function

    create = bind(
        "archive_read_new",
        [],
        pointer,
    )

    support_filter = bind(
        "archive_read_support_filter_zstd",
        [pointer],
        integer,
    )

    support_format = bind(
        "archive_read_support_format_tar",
        [pointer],
        integer,
    )

    open_archive = bind(
        "archive_read_open_filename",
        [pointer, string, ctypes.c_size_t],
        integer,
    )

    next_header = bind(
        "archive_read_next_header",
        [pointer, ctypes.POINTER(pointer)],
        integer,
    )

    skip_data = bind(
        "archive_read_data_skip",
        [pointer],
        integer,
    )

    free = bind(
        "archive_read_free",
        [pointer],
        integer,
    )

    error_string = bind(
        "archive_error_string",
        [pointer],
        string,
    )

    fields = {
        "name": bind(
            "archive_entry_pathname", [pointer], string
        ),
        "type": bind(
            "archive_entry_filetype", [pointer], integer
        ),
        "mode": bind(
            "archive_entry_perm", [pointer], integer
        ),
        "uid": bind(
            "archive_entry_uid", [pointer], integer64
        ),
        "gid": bind(
            "archive_entry_gid", [pointer], integer64
        ),
        "uname": bind(
            "archive_entry_uname", [pointer], string
        ),
        "gname": bind(
            "archive_entry_gname", [pointer], string
        ),
        "size": bind(
            "archive_entry_size", [pointer], integer64
        ),
        "target": bind(
            "archive_entry_symlink", [pointer], string
        ),
        "hardlink": bind(
            "archive_entry_hardlink", [pointer], string
        ),
    }

    reader = create()

    if not reader:
        raise RuntimeError("Cannot allocate native archive reader")

    def check(status):
        if status != 0:
            raise RuntimeError(
                f"Native archive error {status}: "
                f"{error_string(reader)!r}"
            )

    records = []

    try:
        check(support_filter(reader))
        check(support_format(reader))

        check(open_archive(
            reader,
            os.fsencode(path),
            10240,
        ))

        while True:
            entry = pointer()
            status = next_header(
                reader,
                ctypes.byref(entry),
            )

            if status == 1:  # ARCHIVE_EOF
                break

            check(status)

            records.append({
                name: function(entry)
                for name, function in fields.items()
            })

            if len(records) > 100:
                raise RuntimeError(
                    "Unexpected native fixture member count"
                )

            check(skip_data(reader))

    finally:
        free(reader)

    return records


class WorkerCases:
    """Test methods executed under a real non-root identity."""

    def setUp(self):
        self.fixtures = load_fixtures()
        self.archive = self.fixtures.archive

        self.archive.require_unprivileged()

        self.assertNotEqual(os.getuid(), 0)
        self.assertEqual(os.getuid(), os.geteuid())
        self.assertEqual(os.getgid(), os.getegid())
        self.assertNotIn(0, os.getgroups())

        scratch = tempfile.TemporaryDirectory(
            prefix="native-archive-worker-"
        )

        self.addCleanup(scratch.cleanup)

        self.root = Path(scratch.name)
        self.package = self.root / FILENAME
        self.manifest = self.root / "candidate-SHA256SUMS"

        self.tar = (
            self.fixtures.body()
            + self.fixtures.member(
                "usr/bin/alias",
                kind=tarfile.SYMTYPE,
                target="broot",
            )
            + bytes(1024)
        )

        self.compressed = self.compress(self.tar)

        self.package.write_bytes(self.compressed)

        self.digest = hashlib.sha256(
            self.compressed
        ).hexdigest()

        self.manifest.write_text(
            f"{self.digest}  {FILENAME}\n",
            encoding="ascii",
        )

    def compress(self, data):
        return subprocess.run(
            ["/usr/bin/zstd", "-q", "-c"],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=True,
            env=ENVIRONMENT,
        ).stdout

    def cli(self, arguments, environment=None):
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(ROOT / HELPER),
                *arguments,
            ],
            cwd=self.root,
            env=environment or ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )

    def family_args(self):
        return [
            "validate-family",
            "--family", "broot",
            "--version", "1.0-1",
            "--checksums", str(self.manifest),
            "--package", str(self.package),
        ]

    def assert_cli_rejected(self, arguments):
        result = self.cli(arguments)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertTrue(result.stderr)

    def test_real_compressed_archive(self):
        result = self.archive.inspect_package(
            self.package
        )

        self.assertEqual(result["sha256"], self.digest)
        self.assertEqual(result["member_count"], 7)
        self.assertEqual(result["symlink_count"], 1)
        self.assertEqual(result["expanded_bytes"], len(self.tar))
        self.assertEqual(
            self.package.read_bytes(),
            self.compressed,
        )

    def test_native_member_metadata_parity(self):
        result = self.archive.inspect_package(
            self.package
        )

        entries = result["entries"]
        records = native_inventory(self.package)

        kinds = {
            stat.S_IFREG: "file",
            stat.S_IFDIR: "directory",
            stat.S_IFLNK: "symlink",
        }

        observed = {}

        for record in records:
            kind = kinds[record["type"]]

            name = self.archive.normalize_member_path(
                record["name"].decode("utf-8"),
                directory=(kind == "directory"),
            )

            self.assertNotIn(name, observed)

            self.assertEqual(record["uid"], 0)
            self.assertEqual(record["gid"], 0)
            self.assertEqual(record["uname"], b"root")
            self.assertEqual(record["gname"], b"root")
            self.assertIsNone(record["hardlink"])

            entry = {
                "type": kind,
                "mode": record["mode"],
                "size": record["size"],
            }

            if kind == "symlink":
                entry["target"] = (
                    record["target"].decode("utf-8")
                )
            else:
                self.assertIsNone(record["target"])

            observed[name] = entry

        self.assertEqual(observed, entries)

        metadata = subprocess.run(
            [
                "/usr/bin/bsdtar",
                "-xOf",
                str(self.package),
                "--",
                ".PKGINFO",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=True,
            env=ENVIRONMENT,
        )

        self.assertEqual(metadata.stderr, b"")
        self.assertEqual(
            metadata.stdout,
            result["metadata"][".PKGINFO"].encode("utf-8"),
        )

    def test_real_family_cli(self):
        environment = dict(ENVIRONMENT)
        environment["PYTHONPATH"] = str(self.root)

        (
            self.root / "package_release_contract.py"
        ).write_text(
            'raise RuntimeError("UNTRUSTED MODULE LOADED")\n'
        )

        result = self.cli(
            self.family_args(),
            environment,
        )

        self.assertEqual(
            result.returncode, 0, result.stderr
        )
        self.assertEqual(result.stderr, b"")

        receipt = json.loads(result.stdout)

        self.assertTrue(
            receipt["structural_and_identity_validation"]
        )

        self.assertEqual(
            receipt["packages"]["broot"]["identity"]["sha256"],
            self.digest,
        )

        diagnostic = self.cli([
            "--package", str(self.package),
        ])

        self.assertEqual(
            diagnostic.returncode, 0, diagnostic.stderr
        )

        inventory = json.loads(diagnostic.stdout)

        self.assertTrue(inventory["structural_inventory_only"])

        self.assertNotIn(
            "structural_and_identity_validation",
            inventory,
        )

    def test_failed_cli_has_no_receipt(self):
        self.manifest.write_text(
            f"{'b' * 64}  {FILENAME}\n",
            encoding="ascii",
        )

        self.assert_cli_rejected(self.family_args())

        self.manifest.write_text(
            f"{self.digest}  {FILENAME}\n" * 2,
            encoding="ascii",
        )

        self.assert_cli_rejected(self.family_args())

        self.manifest.write_text(
            f"{self.digest}  {FILENAME}\n",
            encoding="ascii",
        )

        self.assert_cli_rejected(
            self.family_args()
            + ["--package", str(self.package)]
        )

    def test_nonregular_package_inputs(self):
        link = self.root / "package-link"
        link.symlink_to(self.package)

        fifo = self.root / "package-fifo"
        os.mkfifo(fifo)

        with self.assertRaises(OSError):
            self.archive.inspect_package(link)

        for path in (fifo, self.root):
            with self.subTest(path=path):
                with self.assertRaises(
                    self.archive.ArchiveError
                ):
                    self.archive.inspect_package(path)

    def test_invalid_compressed_streams(self):
        cases = {
            "invalid compression": b"not a compressed archive",
            "truncated compression": self.compressed[:-1],
            "truncated tar": self.compress(self.tar[:-1024]),
            "concatenated tar": self.compress(self.tar * 2),
            "nonzero trailing tar data": self.compress(
                self.tar + b"unexpected"
            ),
        }

        for label, data in cases.items():
            with self.subTest(label=label):
                self.package.write_bytes(data)

                with self.assertRaises(
                    self.archive.ArchiveError
                ):
                    self.archive.inspect_package(self.package)

    def test_mutation_during_inspection(self):
        original_inspect = self.archive.inspect_tar_stream

        replacement = bytearray(self.compressed)
        replacement[-1] ^= 1

        cases = {
            "same-length mutation": (
                bytes(replacement),
                "changed during inspection",
            ),
            "growth": (
                self.compressed + b"x",
                "grew during hashing",
            ),
            "truncation": (
                self.compressed[:-1],
                "shortened during hashing",
            ),
        }

        for label, (data, message) in cases.items():
            with self.subTest(label=label):
                self.package.write_bytes(self.compressed)

                def inspect_and_mutate(stream):
                    result = original_inspect(stream)

                    self.package.write_bytes(data)

                    return result

                with patch.object(
                    self.archive,
                    "inspect_tar_stream",
                    side_effect=inspect_and_mutate,
                ):
                    with self.assertRaisesRegex(
                        self.archive.ArchiveError,
                        message,
                    ):
                        self.archive.inspect_package(
                            self.package
                        )

    def assert_child_cleanup(self, program):
        real_popen = subprocess.Popen
        children = []

        def spawn_replacement(arguments, **options):
            process = real_popen(
                [sys.executable, "-I", "-B", "-c", program],
                **options,
            )

            children.append(process)
            return process

        started = time.monotonic()

        with patch.object(
            self.archive, "INSPECTION_TIMEOUT", 2
        ), patch.object(
            self.archive.subprocess,
            "Popen",
            side_effect=spawn_replacement,
        ):
            with self.assertRaisesRegex(
                self.archive.ArchiveError,
                "timed out|deadline",
            ):
                self.archive.inspect_package(self.package)

        self.assertLess(
            time.monotonic() - started, 12
        )

        self.assertEqual(len(children), 1)

        process = children[0]

        self.assertIsNotNone(process.returncode)
        self.assertLess(process.returncode, 0)
        self.assertTrue(process.stdout.closed)

        # waitpid must fail because the child was reaped.
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

    def test_stalled_decompressor_killed_and_reaped(self):
        self.assert_child_cleanup(
            "import time; time.sleep(60)"
        )

    def test_decompressor_exit_timeout_killed_and_reaped(self):
        program = (
            "import os, sys, time\n"
            f"sys.stdout.buffer.write(bytes.fromhex('{self.tar.hex()}'))\n"
            "sys.stdout.buffer.flush()\n"
            "os.close(1)\n"
            "time.sleep(60)\n"
        )

        self.assert_child_cleanup(program)


    def test_selected_member_native_byte_parity(self):
        names = ("usr/bin/broot",)

        result = self.archive.inspect_package(
            self.package,
            expected_sha256=self.digest,
            requested_members=names,
        )

        native_bytes = subprocess.check_output(
            [
                "/usr/bin/bsdtar",
                "-xOf",
                str(self.package),
                "--",
                names[0],
            ],
            cwd="/",
            env=ENVIRONMENT,
            timeout=15,
        )

        self.assertEqual(
            set(result["selected_members"]),
            set(names),
        )

        self.assertEqual(
            result["selected_members"][names[0]],
            {
                "size": len(native_bytes),
                "sha256": hashlib.sha256(
                    native_bytes
                ).hexdigest(),
            },
        )

        self.assertEqual(
            result["sha256"], self.digest
        )

        self.assertEqual(
            self.package.read_bytes(),
            self.compressed,
        )

        print("PASS: Selected member bytes match native bsdtar.")

    def test_selected_members_survive_family_validation(self):
        name = "usr/bin/broot"

        registry = self.archive.load_release_registry()

        checksums = {
            FILENAME: self.digest,
        }

        ordinary = self.archive.inspect_family(
            "broot",
            "1.0-1",
            [self.package],
            checksums,
            registry=registry,
        )

        selected = self.archive.inspect_family(
            "broot",
            "1.0-1",
            [self.package],
            checksums,
            registry=registry,
            requested_members={
                FILENAME: (name,),
            },
        )

        self.assertTrue(
            selected["structural_and_identity_validation"]
        )

        package = selected["packages"]["broot"]

        self.assertEqual(
            package["identity"]["sha256"],
            self.digest,
        )

        native_bytes = subprocess.check_output(
            [
                "/usr/bin/bsdtar",
                "-xOf",
                str(self.package),
                "--",
                name,
            ],
            cwd="/",
            env=ENVIRONMENT,
            timeout=15,
        )

        self.assertEqual(
            package.pop("selected_members"),
            {
                name: {
                    "size": len(native_bytes),
                    "sha256": hashlib.sha256(
                        native_bytes
                    ).hexdigest(),
                },
            },
        )

        self.assertEqual(selected, ordinary)

        print("PASS: Selected member identity bound to validated family.")

    def test_selected_missing_and_nonregular_members(self):
        registry = self.archive.load_release_registry()

        cases = (
            (
                "usr/bin/missing",
                "Missing selected archive members",
            ),
            (
                "usr/bin",
                "Selected member is not regular",
            ),
            (
                "usr/bin/alias",
                "Selected member is not regular",
            ),
        )

        for name, message in cases:
            with self.subTest(member=name):
                with self.assertRaisesRegex(
                    self.archive.ArchiveError,
                    message,
                ):
                    self.archive.inspect_family(
                        "broot",
                        "1.0-1",
                        [self.package],
                        {FILENAME: self.digest},
                        registry=registry,
                        requested_members={
                            FILENAME: (name,),
                        },
                    )

    def test_family_digest_rejected_before_decompression(self):
        registry = self.archive.load_release_registry()

        incorrect = (
            "0" if self.digest[0] != "0" else "1"
        ) + self.digest[1:]

        for requests in (
            None,
            {FILENAME: ("usr/bin/broot",)},
        ):
            with self.subTest(requests=requests):
                with patch.object(
                    self.archive.subprocess,
                    "Popen",
                ) as decompressor:
                    with self.assertRaisesRegex(
                        self.archive.ArchiveError,
                        "Package digest does not match protected intake",
                    ):
                        self.archive.inspect_family(
                            "broot",
                            "1.0-1",
                            [self.package],
                            {FILENAME: incorrect},
                            registry=registry,
                            requested_members=requests,
                        )

                    decompressor.assert_not_called()

    def test_mutation_after_selected_member_hashing(self):
        original_inspect = self.archive.inspect_tar_stream

        def inspect_and_mutate(stream, **options):
            result = original_inspect(
                stream, **options
            )

            self.assertIn(
                "usr/bin/broot",
                result["selected_members"],
            )

            modified = bytearray(self.compressed)
            modified[-1] ^= 1

            self.package.write_bytes(modified)

            return result

        with patch.object(
            self.archive,
            "inspect_tar_stream",
            side_effect=inspect_and_mutate,
        ):
            with self.assertRaisesRegex(
                self.archive.ArchiveError,
                "Package changed during inspection",
            ):
                self.archive.inspect_package(
                    self.package,
                    expected_sha256=self.digest,
                    requested_members=("usr/bin/broot",),
                )

    def test_failed_decompressor_after_valid_selected_member(self):
        real_popen = subprocess.Popen
        children = []

        program = (
            "import sys\n"
            f"sys.stdout.buffer.write(bytes.fromhex('{self.tar.hex()}'))\n"
            "sys.stdout.buffer.flush()\n"
            "sys.exit(7)\n"
        )

        def spawn_replacement(arguments, **options):
            process = real_popen(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    program,
                ],
                **options,
            )

            children.append(process)
            return process

        with patch.object(
            self.archive.subprocess,
            "Popen",
            side_effect=spawn_replacement,
        ):
            with self.assertRaisesRegex(
                self.archive.ArchiveError,
                "Package decompression failed",
            ):
                self.archive.inspect_package(
                    self.package,
                    expected_sha256=self.digest,
                    requested_members=("usr/bin/broot",),
                )

        self.assertEqual(len(children), 1)

        process = children[0]

        self.assertEqual(process.returncode, 7)
        self.assertTrue(process.stdout.closed)

        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

        self.assertEqual(
            self.package.read_bytes(),
            self.compressed,
        )

        print("PASS: Failed decompressor cannot produce member results.")


@unittest.skipUnless(
    NATIVE_ENABLED,
    "Native package-pipeline tests not enabled",
)
class NativeArchiveTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.getuid() != 0 or os.geteuid() != 0:
            raise RuntimeError(
                "Native archive harness requires root"
            )

        cls.account = pwd.getpwnam("nobody")

        if (
            cls.account.pw_uid == 0
            or cls.account.pw_gid == 0
        ):
            raise RuntimeError(
                "Invalid unprivileged test account"
            )

        for tool in (
            "/usr/bin/zstd",
            "/usr/bin/bsdtar",
        ):
            if not os.access(tool, os.X_OK):
                raise RuntimeError(
                    f"Required native tool missing: {tool}"
                )

        scratch = tempfile.TemporaryDirectory(
            prefix="native-archive-harness-"
        )

        cls.addClassCleanup(scratch.cleanup)

        cls.protected = Path(scratch.name)
        cls.protected.chmod(0o755)

        for relative in (
            HELPER, CONTRACT, PORTABLE, NATIVE
        ):
            target = cls.protected / relative

            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            shutil.copyfile(ROOT / relative, target)
            target.chmod(0o644)

            for parent in target.parents:
                if parent == cls.protected:
                    break

                parent.chmod(0o755)

        for path in cls.protected.rglob("*"):
            info = path.lstat()

            if info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError(
                    f"Unprotected native test input: {path}"
                )

    def run_worker(self, method):
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(self.protected / NATIVE),
                "--worker",
                method,
            ],
            user=self.account.pw_uid,
            group=self.account.pw_gid,
            extra_groups=[],
            cwd="/",
            env=ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
        )

        output = result.stdout.decode(
            "utf-8", errors="replace"
        )

        print(output, end="", flush=True)

        self.assertEqual(result.returncode, 0, output)
        self.assertIn("Ran 1 test", output)
        self.assertTrue(output.rstrip().endswith("OK"))

    def test_root_inspection_rejected(self):
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(self.protected / HELPER),
                "--package",
                "/nonexistent-package.pkg.tar.zst",
            ],
            cwd="/",
            env=ENVIRONMENT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(
            b"unprivileged identity",
            result.stderr,
        )

    def test_privileged_group_rejected(self):
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(self.protected / HELPER),
                "--package",
                "/nonexistent-package.pkg.tar.zst",
            ],
            user=self.account.pw_uid,
            group=0,
            extra_groups=[],
            cwd="/",
            env=ENVIRONMENT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(
            b"privileged group",
            result.stderr,
        )

    def test_actual_compressed_archive(self):
        self.run_worker("test_real_compressed_archive")

    def test_actual_native_metadata_parity(self):
        self.run_worker("test_native_member_metadata_parity")

    def test_actual_family_cli(self):
        self.run_worker("test_real_family_cli")

    def test_actual_failed_cli(self):
        self.run_worker("test_failed_cli_has_no_receipt")

    def test_actual_nonregular_inputs(self):
        self.run_worker("test_nonregular_package_inputs")

    def test_actual_invalid_compression(self):
        self.run_worker("test_invalid_compressed_streams")

    def test_actual_file_mutations(self):
        self.run_worker("test_mutation_during_inspection")

    def test_actual_stalled_decompressor_cleanup(self):
        self.run_worker(
            "test_stalled_decompressor_killed_and_reaped"
        )

    def test_actual_decompressor_exit_cleanup(self):
        self.run_worker(
            "test_decompressor_exit_timeout_killed_and_reaped"
        )


    def test_actual_selected_member_native_byte_parity(self):
        self.run_worker(
            "test_selected_member_native_byte_parity"
        )

    def test_actual_selected_members_survive_family_validation(self):
        self.run_worker(
            "test_selected_members_survive_family_validation"
        )

    def test_actual_selected_missing_and_nonregular_members(self):
        self.run_worker(
            "test_selected_missing_and_nonregular_members"
        )

    def test_actual_family_digest_rejected_before_decompression(self):
        self.run_worker(
            "test_family_digest_rejected_before_decompression"
        )

    def test_actual_mutation_after_selected_member_hashing(self):
        self.run_worker(
            "test_mutation_after_selected_member_hashing"
        )

    def test_actual_failed_decompressor_after_valid_selected_member(self):
        self.run_worker(
            "test_failed_decompressor_after_valid_selected_member"
        )


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        method = sys.argv[2]

        WorkerTests = type(
            "WorkerTests",
            (WorkerCases, unittest.TestCase),
            {},
        )

        unittest.main(
            argv=[
                sys.argv[0],
                f"WorkerTests.{method}",
                "-v",
            ]
        )
    else:
        unittest.main()
