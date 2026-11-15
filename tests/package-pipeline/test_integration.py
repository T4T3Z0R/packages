import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASSEMBLER = ROOT / "scripts/package-pipeline/assemble-repository.sh"


class RepositoryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = self.root / "fixtures"
        self.fixture.mkdir()
        (self.root / "package-output").mkdir()
        (self.root / "bin").mkdir()
        (self.root / "gnupg").mkdir(mode=0o700)

        self.env = os.environ.copy()
        self.env.update({
            "GNUPGHOME": str(self.root / "gnupg"),
            "GITHUB_WORKSPACE": str(self.root),
            "FIXTURE_DIR": str(self.fixture),
            "PACKAGE_NAME": "yazi",
            "PACKAGE_FILE": "yazi-2.0-1-any.pkg.tar.zst",
            "RELEASE_TAG": "test-release",
            "REPO_NAME": "test-repo",
            "ARCH_REPO_SIGNING_PASSPHRASE": "test-only",
            "PATH": str(self.root / "bin") + os.pathsep + self.env["PATH"],
        })

        self.run_command([
            "gpg", "--batch", "--pinentry-mode", "loopback",
            "--passphrase", "", "--quick-generate-key",
            "Package Test <test@example.invalid>",
            "ed25519", "sign", "0",
        ], check=True)

        keys = self.run_command([
            "gpg", "--with-colons", "--list-secret-keys"
        ], check=True).stdout

        self.key = next(
            line.split(":")[4]
            for line in keys.splitlines()
            if line.startswith("sec:")
        )
        self.env["SIGNING_SUBKEY"] = self.key

        keydir = self.root / "arch/keys"
        keydir.mkdir(parents=True)

        public = self.run_command([
            "gpg", "--armor", "--export", self.key
        ], check=True).stdout

        (keydir / "t4t3z0r-package-signing.asc").write_text(public)

        self.make_package("yazi", "1.0", self.fixture)
        self.make_package("yazi-extra", "1.0", self.fixture)
        self.make_package("broot", "1.0", self.fixture)
        self.make_package("yazi", "2.0", self.root / "package-output")

        stub = self.root / "bin/gh"
        stub.write_text("\n".join([
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "if [[ \"$1 $2\" == \"release view\" ]]; then exit 0; fi",
            "if [[ \"$1 $2\" == \"release download\" ]]; then",
            "  cp \"$FIXTURE_DIR/\"*.pkg.tar.zst* repo-output/",
            "  exit 0",
            "fi",
            "exit 99",
            "",
        ]))
        stub.chmod(0o755)

    def run_command(self, args, check=False, cwd=None):
        return subprocess.run(
            args, cwd=cwd or self.root, env=self.env,
            capture_output=True, text=True, check=check,
        )

    def make_package(self, name, version, destination):
        build = self.root / "build" / name / version
        build.mkdir(parents=True)

        metadata = "\n".join([
            f"pkgname = {name}",
            f"pkgbase = {name}",
            f"pkgver = {version}-1",
            "pkgdesc = Disposable integration test package",
            "url = https://example.invalid",
            "builddate = 1",
            "packager = Pipeline Test",
            "size = 0",
            "arch = any",
            "license = MIT",
            "",
        ])
        (build / ".PKGINFO").write_text(metadata)

        package = destination / f"{name}-{version}-1-any.pkg.tar.zst"

        self.run_command([
            "bsdtar", "-c", "--zstd", "-f", str(package), ".PKGINFO"
        ], check=True, cwd=build)

        self.run_command([
            "gpg", "--batch", "--yes",
            "--local-user", self.key + "!",
            "--output", str(package) + ".sig",
            "--detach-sign", str(package),
        ], check=True)

        return package

    def assemble(self):
        return self.run_command(["bash", str(ASSEMBLER)])

    def test_successful_replacement(self):
        result = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

        output = self.root / "repo-output"
        actual = {p.name for p in output.glob("*.pkg.tar.zst")}

        self.assertEqual(actual, {
            "yazi-2.0-1-any.pkg.tar.zst",
            "yazi-extra-1.0-1-any.pkg.tar.zst",
            "broot-1.0-1-any.pkg.tar.zst",
        })

        for name in ("test-repo.db", "test-repo.files"):
            file = output / name
            self.assertTrue(file.is_file(), name)
            self.run_command([
                "gpg", "--verify", str(file) + ".sig", str(file)
            ], check=True)

        entries = self.run_command([
            "bsdtar", "-tf", str(output / "test-repo.db")
        ], check=True).stdout

        self.assertIn("yazi-2.0-1/desc", entries)
        self.assertIn("yazi-extra-1.0-1/desc", entries)
        self.assertIn("broot-1.0-1/desc", entries)
        self.assertNotIn("yazi-1.0-1/desc", entries)

    def test_corrupted_existing_signature(self):
        signature = self.fixture / "broot-1.0-1-any.pkg.tar.zst.sig"
        signature.write_bytes(b"invalid signature")

        result = self.assemble()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            (self.root / "repo-output/test-repo.db").exists()
        )

    def test_corrupted_candidate_signature(self):
        signature = self.root / (
            "package-output/yazi-2.0-1-any.pkg.tar.zst.sig"
        )
        signature.write_bytes(b"invalid signature")

        result = self.assemble()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            (self.root / "repo-output/test-repo.db").exists()
        )


if __name__ == "__main__":
    unittest.main()
