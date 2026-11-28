"""Native Arch candidate linkage and privilege-boundary regressions."""

import hashlib
import importlib.util
import json
import os
import pwd
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid

from pathlib import Path
from unittest.mock import patch


NATIVE_ENABLED = (
    os.environ.get("PACKAGE_PIPELINE_NATIVE_TESTS") == "1"
)

ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "HOME": "/tmp",
}

HERE = Path(__file__).resolve().parent

SCRIPTS = (
    HERE.parents[1] / "scripts" / "package-pipeline"
    if __name__ != "__main__"
    else HERE
)


def load_module(name, directory):
    spec = importlib.util.spec_from_file_location(
        name, directory / f"{name}.py"
    )

    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)

    return module


def digest(path):
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def run(arguments, *, cwd="/", timeout=30):
    return subprocess.run(
        arguments,
        cwd=cwd,
        env=ENVIRONMENT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=True,
    )


class WorkerCases:

    def inspect(self, name):
        return self.linkage.inspect_executable(
            self.root / name,
            privilege_guard=(
                self.privileges.require_inspection_identity
            ),
        )

    def test_actual_privilege_boundary(self):
        result = (
            self.privileges.require_inspection_identity()
        )

        self.assertEqual(result["uid"], os.getuid())
        self.assertEqual(result["gid"], os.getgid())
        self.assertNotEqual(result["uid"], 0)
        self.assertEqual(os.getgroups(), [])

        self.assertTrue(result["capabilities_cleared"])
        self.assertTrue(result["bounding_set_cleared"])
        self.assertTrue(result["no_new_privs"])

        self.assertFalse(
            os.access(self.root, os.W_OK)
        )

        self.assertFalse(
            os.access(
                self.root / "fixture",
                os.W_OK,
            )
        )

        self.assertTrue(
            os.access(
                self.root / "marker-area",
                os.W_OK,
            )
        )

        print("PASS: Actual Linux privilege boundary.")

    def test_complete_dependency_tree(self):
        path = self.root / "fixture"

        before = digest(path)

        result = self.inspect("fixture")

        self.assertTrue(
            result["static_linkage_validation"]
        )

        self.assertEqual(result["sha256"], before)
        self.assertEqual(
            result["architecture"], "x86_64"
        )

        self.assertEqual(
            result["interpreter"],
            self.linkage.INTERPRETER,
        )

        self.assertIn(
            self.names["middle"],
            result["needed"],
        )

        self.assertNotIn(
            self.names["leaf"],
            result["needed"],
        )

        for key in ("middle", "leaf"):
            name = self.names[key]

            self.assertEqual(
                result["libraries"][name],
                f"/usr/lib/{name}",
            )

        output = run([
            "/usr/bin/readelf",
            "-dW",
            "--",
            str(path),
        ]).stdout

        needed = []

        for line in output.splitlines():
            if "(NEEDED)" in line:
                match = re.search(
                    r"\[([^\]]+)\]", line
                )

                self.assertIsNotNone(match)
                needed.append(match.group(1))

        self.assertEqual(
            tuple(needed), result["needed"]
        )

        self.assertEqual(digest(path), before)

        self.assertFalse(
            (self.root / "marker-area" / "executed").exists()
        )

        print(
            "PASS: Real ELF parser, readelf and recursive "
            "resolver agree."
        )

    def test_missing_direct_dependency(self):
        with self.assertRaisesRegex(
            self.linkage.LinkageError,
            "Unresolved runtime dependency: "
            + re.escape(self.names["middle"]),
        ):
            self.inspect("fixture")

    def test_missing_transitive_dependency(self):
        with self.assertRaisesRegex(
            self.linkage.LinkageError,
            "Unresolved runtime dependency: "
            + re.escape(self.names["leaf"]),
        ):
            self.inspect("fixture")

    def test_reject_candidate_runpath(self):
        with self.assertRaisesRegex(
            self.linkage.LinkageError,
            "Unsupported candidate dynamic tag: DT_RUNPATH",
        ):
            self.inspect("runpath")

    def test_reject_candidate_interpreter(self):
        with self.assertRaisesRegex(
            self.linkage.LinkageError,
            "Unexpected physical ELF interpreter",
        ):
            self.inspect("wrong-interpreter")

    def test_reject_malformed_dynamic_segment(self):
        with self.assertRaisesRegex(
            self.linkage.LinkageError,
            "Dynamic termination outside segment",
        ):
            self.inspect("unterminated")

    def test_reject_non_elf(self):
        with self.assertRaises(
            self.linkage.LinkageError
        ):
            self.inspect("not-elf")

    def test_reject_nonregular_inputs(self):
        for name in ("directory", "fifo"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    self.linkage.LinkageError,
                    "Candidate ELF file outside storage policy",
                ):
                    self.inspect(name)

        with self.assertRaises(OSError):
            self.inspect("symlink")

    def test_reject_unprotected_file(self):
        path = self.root / "marker-area" / "unprotected"

        shutil.copyfile(
            self.root / "fixture", path
        )

        with self.assertRaisesRegex(
            self.linkage.LinkageError,
            "Candidate ELF file outside storage policy",
        ):
            self.inspect("marker-area/unprotected")

    def test_actual_resolver_resource_limits(self):
        program = (
            "import json, resource;"
            "print(json.dumps({"
            "'as':resource.getrlimit(resource.RLIMIT_AS),"
            "'fsize':resource.getrlimit(resource.RLIMIT_FSIZE),"
            "'cpu':resource.getrlimit(resource.RLIMIT_CPU),"
            "'core':resource.getrlimit(resource.RLIMIT_CORE)"
            "}))"
        )

        result = subprocess.run(
            [
                "/usr/bin/python",
                "-I", "-B", "-c", program,
            ],
            cwd="/",
            env=ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            preexec_fn=self.linkage.resolver_limits,
            check=True,
        )

        limits = json.loads(result.stdout)

        self.assertEqual(
            limits["as"],
            [self.linkage.RESOLVER_ADDRESS_SPACE] * 2,
        )

        self.assertEqual(
            limits["fsize"],
            [self.linkage.MAX_RESOLVER_OUTPUT] * 2,
        )

        self.assertEqual(
            limits["cpu"],
            [self.linkage.RESOLVER_TIMEOUT] * 2,
        )

        self.assertEqual(limits["core"], [0, 0])
        self.assertEqual(result.stderr, "")

        print("PASS: Kernel resource limits verified.")

    def test_actual_resolver_timeout(self):
        with (
            patch.object(
                self.linkage,
                "RESOLVER",
                str(self.root / "slow-resolver.py"),
            ),
            patch.object(
                self.linkage,
                "RESOLVER_TIMEOUT",
                2,
            ),
        ):
            with self.assertRaisesRegex(
                self.linkage.LinkageError,
                "Static dependency resolver timed out",
            ):
                self.linkage.resolve_dependencies(
                    self.root / "fixture",
                    ("libc.so.6",),
                )

    def test_actual_resolver_output_limit(self):
        with (
            patch.object(
                self.linkage,
                "RESOLVER",
                str(self.root / "large-resolver.py"),
            ),
            patch.object(
                self.linkage,
                "MAX_RESOLVER_OUTPUT",
                4096,
            ),
        ):
            with self.assertRaisesRegex(
                self.linkage.LinkageError,
                "Static resolver failed|output exceeds policy",
            ):
                self.linkage.resolve_dependencies(
                    self.root / "fixture",
                    ("libc.so.6",),
                )

    def test_trusted_runtime_path_boundary(self):
        result = self.linkage.validate_runtime_path(
            self.linkage.INTERPRETER
        )

        self.assertTrue(
            Path(result).is_relative_to("/usr/lib")
        )

        with self.assertRaisesRegex(
            self.linkage.LinkageError,
            "Untrusted runtime library",
        ):
            self.linkage.validate_runtime_path(
                str(self.root / "fixture")
            )


@unittest.skipUnless(
    NATIVE_ENABLED,
    "Requires disposable native Arch CI container",
)
class NativeLinkageTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.getuid() != 0 or os.geteuid() != 0:
            raise RuntimeError(
                "Native fixture harness requires container root"
            )

        if os.environ.get("GITHUB_ACTIONS") != "true":
            raise RuntimeError(
                "Native linkage fixtures restricted to GitHub CI"
            )

        release = Path("/etc/os-release").read_text()

        if not re.search(
            r"^ID=arch$", release, re.MULTILINE
        ):
            raise RuntimeError(
                "Native linkage tests require Arch Linux"
            )

        for tool in (
            "cc", "readelf", "lddtree", "setpriv",
            "python", "pacman",
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

        cls.scratch = tempfile.TemporaryDirectory(
            prefix="native-linkage-"
        )

        cls.addClassCleanup(cls.scratch.cleanup)

        cls.root = Path(cls.scratch.name)
        cls.root.chmod(0o755)

        for name in (
            "candidate_linkage.py",
            "candidate_privileges.py",
        ):
            destination = cls.root / name

            shutil.copyfile(
                SCRIPTS / name,
                destination,
            )

            destination.chmod(0o644)

            if digest(destination) != digest(
                SCRIPTS / name
            ):
                raise RuntimeError(
                    f"Protected helper copy mismatch: {name}"
                )

        worker = cls.root / "worker.py"

        shutil.copyfile(
            Path(__file__).resolve(),
            worker,
        )

        worker.chmod(0o644)

        marker = cls.root / "marker-area"
        marker.mkdir(mode=0o700)

        os.chown(marker, cls.uid, cls.gid)
        marker.chmod(0o700)

        token = uuid.uuid4().hex

        cls.names = {
            "leaf": f"libw01b2_leaf_{token}.so",
            "middle": f"libw01b2_middle_{token}.so",
        }

        (cls.root / "names.json").write_text(
            json.dumps(cls.names),
            encoding="ascii",
        )

        cls.paths = {
            key: Path("/usr/lib") / name
            for key, name in cls.names.items()
        }

        cls.build_fixtures()
        cls.verify_protected_fixtures()

    @classmethod
    def install_fixture_library(cls, source, target):
        descriptor = os.open(
            target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o644,
        )

        cls.addClassCleanup(
            target.unlink, missing_ok=True
        )

        with os.fdopen(descriptor, "wb") as stream:
            with source.open("rb") as original:
                shutil.copyfileobj(
                    original, stream
                )

            os.fchmod(stream.fileno(), 0o644)

        if digest(source) != digest(target):
            raise RuntimeError(
                "Fixture library copy mismatch"
            )

    @classmethod
    def build_fixtures(cls):
        root = cls.root

        marker = str(
            root / "marker-area" / "executed"
        )

        (root / "leaf.c").write_text(
            "int leaf(void) { return 7; }\n"
        )

        (root / "middle.c").write_text(
            "extern int leaf(void);\n"
            "int middle(void) { return leaf(); }\n"
        )

        (root / "main.c").write_text(
            "#include <stdio.h>\n"
            "extern int middle(void);\n"
            "int main(void) {\n"
            f" FILE *f = fopen({json.dumps(marker)},"
            ' "w");\n'
            " if (f) fclose(f);\n"
            " return middle();\n"
            "}\n"
        )

        leaf = root / cls.names["leaf"]
        middle = root / cls.names["middle"]

        run([
            "/usr/bin/cc",
            "-shared", "-fPIC",
            f"-Wl,-soname,{leaf.name}",
            "-o", str(leaf),
            str(root / "leaf.c"),
        ])

        run([
            "/usr/bin/cc",
            "-shared", "-fPIC",
            f"-Wl,-soname,{middle.name}",
            "-o", str(middle),
            str(root / "middle.c"),
            "-L" + str(root),
            "-l:" + leaf.name,
        ])

        for filename, options in (
            ("fixture", []),
            (
                "runpath",
                ["-Wl,--enable-new-dtags",
                 "-Wl,-rpath,$ORIGIN"],
            ),
            (
                "wrong-interpreter",
                ["-Wl,--dynamic-linker=/invalid/loader"],
            ),
        ):
            run([
                "/usr/bin/cc",
                *options,
                "-Wl,-rpath-link," + str(root),
                "-o", str(root / filename),
                str(root / "main.c"),
                "-L" + str(root),
                "-l:" + middle.name,
            ])

        cls.install_fixture_library(
            leaf, cls.paths["leaf"]
        )

        cls.install_fixture_library(
            middle, cls.paths["middle"]
        )

        # Construct a malformed dynamic table without
        # executing the fixture or changing production files.

        data = bytearray(
            (root / "fixture").read_bytes()
        )

        header = struct.unpack_from(
            "<16sHHIQQQIHHHHHH", data
        )

        phoff = header[5]
        phentsize = header[9]
        phnum = header[10]

        dynamic_segments = []

        for index in range(phnum):
            segment = struct.unpack_from(
                "<IIQQQQQQ",
                data,
                phoff + index * phentsize,
            )

            if segment[0] == 2:
                dynamic_segments.append(segment)

        if len(dynamic_segments) != 1:
            raise RuntimeError(
                "Unexpected compiled fixture layout"
            )

        segment = dynamic_segments[0]

        replacements = 0

        for offset in range(
            segment[2],
            segment[2] + segment[5],
            16,
        ):
            tag, value = struct.unpack_from(
                "<qQ", data, offset
            )

            if tag == 0:
                struct.pack_into(
                    "<qQ", data, offset, 21, 0
                )

                replacements += 1

        if not replacements:
            raise RuntimeError(
                "Compiled fixture lacks DT_NULL"
            )

        (root / "unterminated").write_bytes(data)

        (root / "not-elf").write_bytes(
            b"not an ELF file\n" + b"\0" * 64
        )

        (root / "directory").mkdir(mode=0o755)
        os.mkfifo(root / "fifo", mode=0o644)

        (root / "symlink").symlink_to("fixture")

        (root / "slow-resolver.py").write_text(
            "import time\n"
            "time.sleep(60)\n"
        )

        (root / "large-resolver.py").write_text(
            "import os\n"
            "os.write(1, b'x' * 8192)\n"
            "os.write(1, b'y' * 8192)\n"
        )

        for path in root.iterdir():
            if (
                not path.is_symlink()
                and path.is_file()
            ):
                path.chmod(0o644)

    @classmethod
    def verify_protected_fixtures(cls):
        for path in (
            cls.root,
            *cls.root.parents,
        ):
            info = path.stat()

            if info.st_uid != 0:
                raise RuntimeError(
                    f"Untrusted fixture ancestor: {path}"
                )

            # Permit the normal root-owned sticky /tmp.
            if info.st_mode & 0o022:
                if (
                    path != Path("/tmp")
                    or not info.st_mode & stat.S_ISVTX
                ):
                    raise RuntimeError(
                        f"Writable fixture ancestor: {path}"
                    )

        for name in (
            "worker.py",
            "candidate_linkage.py",
            "candidate_privileges.py",
            "fixture",
            "names.json",
        ):
            path = cls.root / name
            info = path.lstat()

            if (
                info.st_uid != 0
                or not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o022
            ):
                raise RuntimeError(
                    f"Unprotected fixture: {path}"
                )

    def worker(self, method):
        arguments = [
            "/usr/bin/setpriv",
            f"--reuid={self.uid}",
            f"--regid={self.gid}",
            "--clear-groups",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            "/usr/bin/python",
            "-I", "-B",
            str(self.root / "worker.py"),
            "--worker",
            method,
        ]

        process = subprocess.Popen(
            arguments,
            cwd="/",
            env=ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
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

            self.fail(
                f"Native worker timed out: {method}"
            )

        print(stdout, end="")
        print(stderr, end="")

        self.assertEqual(
            process.returncode, 0,
            stdout + stderr,
        )

        self.assertRegex(
            stderr, r"Ran 1 test in "
        )

        self.assertTrue(
            stderr.rstrip().endswith("OK")
        )

        self.assertFalse(
            (self.root / "marker-area" / "executed").exists()
        )

    def test_actual_privilege_boundary(self):
        self.worker(
            "test_actual_privilege_boundary"
        )

    def test_complete_dependency_tree(self):
        self.worker(
            "test_complete_dependency_tree"
        )

    def test_missing_direct_dependency(self):
        path = self.paths["middle"]
        hidden = self.root / "middle.hidden"

        # Use unlink and exact-byte restoration instead
        # of rename across potentially distinct mounts.

        shutil.copyfile(path, hidden)
        path.unlink()

        try:
            self.worker(
                "test_missing_direct_dependency"
            )
        finally:
            self.install_fixture_library(
                hidden, path
            )

    def test_missing_transitive_dependency(self):
        path = self.paths["leaf"]
        hidden = self.root / "leaf.hidden"

        shutil.copyfile(path, hidden)
        path.unlink()

        try:
            self.worker(
                "test_missing_transitive_dependency"
            )
        finally:
            self.install_fixture_library(
                hidden, path
            )

    def test_reject_candidate_runpath(self):
        self.worker(
            "test_reject_candidate_runpath"
        )

    def test_reject_candidate_interpreter(self):
        self.worker(
            "test_reject_candidate_interpreter"
        )

    def test_reject_malformed_dynamic_segment(self):
        self.worker(
            "test_reject_malformed_dynamic_segment"
        )

    def test_reject_non_elf(self):
        self.worker("test_reject_non_elf")

    def test_reject_nonregular_inputs(self):
        self.worker(
            "test_reject_nonregular_inputs"
        )

    def test_reject_unprotected_file(self):
        self.worker(
            "test_reject_unprotected_file"
        )

    def test_actual_resolver_resource_limits(self):
        self.worker(
            "test_actual_resolver_resource_limits"
        )

    def test_actual_resolver_timeout(self):
        self.worker(
            "test_actual_resolver_timeout"
        )

    def test_actual_resolver_output_limit(self):
        self.worker(
            "test_actual_resolver_output_limit"
        )

    def test_trusted_runtime_path_boundary(self):
        self.worker(
            "test_trusted_runtime_path_boundary"
        )

    def test_root_execution_rejected(self):
        privileges = load_module(
            "candidate_privileges",
            self.root,
        )

        linkage = load_module(
            "candidate_linkage",
            self.root,
        )

        with self.assertRaises(
            privileges.PrivilegeError
        ):
            linkage.inspect_executable(
                self.root / "fixture",
                privilege_guard=(
                    privileges.require_inspection_identity
                ),
            )


def worker_main(method):
    if not re.fullmatch(
        r"test_[a-z_]+", method
    ):
        raise RuntimeError("Invalid worker method")

    privileges = load_module(
        "candidate_privileges", HERE
    )

    linkage = load_module(
        "candidate_linkage", HERE
    )

    privileges.require_inspection_identity()

    case_type = type(
        "NativeLinkageWorker",
        (WorkerCases, unittest.TestCase),
        {},
    )

    case = case_type(method)

    case.root = HERE
    case.privileges = privileges
    case.linkage = linkage

    case.names = json.loads(
        (HERE / "names.json").read_text(
            encoding="ascii"
        )
    )

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(
        unittest.TestSuite([case])
    )

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--worker":
        raise SystemExit(
            "Expected explicit native worker invocation"
        )

    raise SystemExit(worker_main(sys.argv[2]))
