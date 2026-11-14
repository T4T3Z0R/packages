import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/package-pipeline/assemble-repository.sh"


class AssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.root / "package-output").mkdir()

        self.make_stub("bsdtar", "echo \"pkgname = yazi\"")
        self.make_stub("gpg", "exit 0")
        self.make_stub(
            "gh",
            "echo called > \"$TEST_ROOT/gh-called\"; exit 99"
        )

    def make_stub(self, name, body):
        p = self.bin / name
        p.write_text("#!/bin/sh\n" + body + "\n")
        p.chmod(0o755)

    def run_script(self, name="yazi", filename="yazi-1-1-x86_64.pkg.tar.zst"):
        env = os.environ.copy()
        env.update({
            "PATH": str(self.bin) + os.pathsep + env["PATH"],
            "PACKAGE_NAME": name,
            "PACKAGE_FILE": filename,
            "TEST_ROOT": str(self.root),
        })
        return subprocess.run(
            ["bash", str(SCRIPT)],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
        )

    def make_candidate(self, filename="yazi-1-1-x86_64.pkg.tar.zst"):
        p = self.root / "package-output" / filename
        p.write_bytes(b"test package")
        Path(str(p) + ".sig").write_bytes(b"test signature")

    def assert_no_remote_access(self):
        self.assertFalse((self.root / "gh-called").exists())

    def test_missing_candidate(self):
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_remote_access()

    def test_invalid_package_name(self):
        self.make_candidate()
        result = self.run_script(name="../escape")
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_remote_access()

    def test_package_identity_mismatch(self):
        self.make_candidate()
        result = self.run_script(name="ghostty")
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_remote_access()

    def test_missing_signature(self):
        self.make_candidate()
        (self.root / "package-output/yazi-1-1-x86_64.pkg.tar.zst.sig").unlink()
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_remote_access()

    def test_rejected_signature(self):
        self.make_candidate()
        self.make_stub("gpg", "exit 1")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_remote_access()


if __name__ == "__main__":
    unittest.main()
