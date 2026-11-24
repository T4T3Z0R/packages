import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASSEMBLER = ROOT / "scripts/package-pipeline/assemble-repository.sh"
ARCHIVER = ROOT / "scripts/package-pipeline/archive-repository.py"


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
            "TEST_ROOT": str(self.root),
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
            line.split(":")[9]
            for line in keys.splitlines()
            if line.startswith("fpr:")
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
            "echo unexpected > \"$TEST_ROOT/gh-mutation\"",
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

    def make_unauthorized_signature(self, package):
        identity = "Unauthorized Test <unauthorized@example.invalid>"

        self.run_command([
            "gpg", "--batch", "--pinentry-mode", "loopback",
            "--passphrase", "", "--quick-generate-key",
            identity, "ed25519", "sign", "0",
        ], check=True)

        keys = self.run_command([
            "gpg", "--with-colons", "--list-secret-keys", identity
        ], check=True).stdout

        wrong_key = next(
            line.split(":")[9]
            for line in keys.splitlines()
            if line.startswith("fpr:")
        )

        self.assertNotEqual(wrong_key, self.key)

        self.run_command([
            "gpg", "--batch", "--yes",
            "--local-user", wrong_key + "!",
            "--output", str(package) + ".sig",
            "--detach-sign", str(package),
        ], check=True)

    def assemble(self):
        return self.run_command(["bash", str(ASSEMBLER)])

    def test_history_release_failure_blocks_live_publication(self):
        self.env["PACKAGE_NAME"] = "gameshell"
        self.env["PACKAGE_FILE"] = (
            "gameshell-2.0-1-any.pkg.tar.zst"
        )
        self.env["REPO_NAME"] = "t4t3z0r"
        self.env["GH_TOKEN"] = "offline-test-token"
        self.env["GH_REPO"] = "fixture/offline"

        self.make_package("gameshell", "1.0", self.fixture)
        self.make_package(
            "gameshell", "2.0", self.root / "package-output"
        )

        assembled = self.assemble()
        self.assertEqual(
            assembled.returncode, 0,
            assembled.stdout + assembled.stderr
        )

        stub = self.root / "bin/gh"
        original = stub.read_text()
        anchor = "if [[ \"$1 $2\" == \"release view\" ]]; then exit 0; fi"
        replacement = "\n".join([
            "if [[ \"$1 $2\" == \"release view\" && \"${3:-}\" == \"arch-history-gameshell\" ]]; then",
            "  echo attempted > \"$TEST_ROOT/history-attempt\"",
            "  exit 17",
            "fi",
            anchor,
        ])
        assert original.count(anchor) == 1
        stub.write_text(original.replace(anchor, replacement, 1))

        publisher = (
            ROOT / "scripts/package-pipeline/publish-repository.sh"
        )
        published = self.run_command(["bash", str(publisher)])

        self.assertNotEqual(published.returncode, 0)
        self.assertIn(
            "Archive authorization failed", published.stderr
        )
        self.assertTrue(
            (self.root / "history-attempt").exists()
        )
        self.assertFalse(
            (self.root / "gh-mutation").exists()
        )

    def prepare_family_update(
        self, name, required=(), existing_optional=(),
        omitted=(),
    ):
        output = self.root / "package-output"
        extras = []

        for member in (name, *required, *existing_optional):
            self.make_package(member, "1.0", self.fixture)

            if member in omitted:
                continue

            candidate = self.make_package(
                member, "2.0", output
            )

            if member == name:
                self.env["PACKAGE_NAME"] = name
                self.env["PACKAGE_FILE"] = candidate.name
            else:
                extras.append(candidate.name)

        self.env["ADDITIONAL_PACKAGE_FILES"] = " ".join(extras)

    def assert_family_update_rejected(self, missing):
        result = self.assemble()

        self.assertNotEqual(
            result.returncode, 0,
            "Incomplete family update was accepted: "
            + missing,
        )
        self.assertIn(missing, result.stderr)

        staged = self.root / "repo-output"

        expected = {
            asset.name: asset.read_bytes()
            for asset in self.fixture.glob("*.pkg.tar.zst*")
        }
        actual = {
            asset.name: asset.read_bytes()
            for asset in staged.glob("*.pkg.tar.zst*")
        }

        self.assertEqual(actual, expected)

        self.assertFalse(
            (staged / "test-repo.db").exists()
        )
        self.assertFalse(
            (self.root / "archive-output").exists()
        )
        self.assertFalse(
            (self.root / "archive-state.txt").exists()
        )
        self.assertFalse(
            (self.root / "gh-mutation").exists()
        )

    def test_missing_existing_debug_companion_ghostty(self):
        self.prepare_family_update(
            "ghostty",
            required=(
                "ghostty-shell-integration",
                "ghostty-terminfo",
                "ghostty-nautilus",
            ),
            existing_optional=("ghostty-debug",),
            omitted=("ghostty-debug",),
        )
        self.assert_family_update_rejected("ghostty-debug")

    def test_missing_existing_debug_companion_keepassxc(self):
        self.prepare_family_update(
            "keepassxc",
            existing_optional=("keepassxc-debug",),
            omitted=("keepassxc-debug",),
        )
        self.assert_family_update_rejected("keepassxc-debug")

    def test_missing_existing_debug_companion_moonlight(self):
        self.prepare_family_update(
            "moonlight-qt",
            existing_optional=("moonlight-qt-debug",),
            omitted=("moonlight-qt-debug",),
        )
        self.assert_family_update_rejected("moonlight-qt-debug")

    def test_missing_existing_debug_companion_syncthing(self):
        self.prepare_family_update(
            "syncthing",
            required=(
                "syncthing-discosrv",
                "syncthing-relaysrv",
            ),
            existing_optional=("syncthing-debug",),
            omitted=("syncthing-debug",),
        )
        self.assert_family_update_rejected("syncthing-debug")

    def test_missing_existing_debug_companion_discosrv(self):
        self.prepare_family_update(
            "syncthing",
            required=(
                "syncthing-discosrv",
                "syncthing-relaysrv",
            ),
            existing_optional=("syncthing-discosrv-debug",),
            omitted=("syncthing-discosrv-debug",),
        )
        self.assert_family_update_rejected(
            "syncthing-discosrv-debug"
        )

    def test_missing_existing_debug_companion_relaysrv(self):
        self.prepare_family_update(
            "syncthing",
            required=(
                "syncthing-discosrv",
                "syncthing-relaysrv",
            ),
            existing_optional=("syncthing-relaysrv-debug",),
            omitted=("syncthing-relaysrv-debug",),
        )
        self.assert_family_update_rejected(
            "syncthing-relaysrv-debug"
        )

    def test_missing_required_ghostty_companion(self):
        self.prepare_family_update(
            "ghostty",
            required=(
                "ghostty-shell-integration",
                "ghostty-terminfo",
                "ghostty-nautilus",
            ),
            omitted=("ghostty-terminfo",),
        )
        self.assert_family_update_rejected(
            "ghostty-terminfo"
        )

    def test_missing_required_syncthing_companion(self):
        self.prepare_family_update(
            "syncthing",
            required=(
                "syncthing-discosrv",
                "syncthing-relaysrv",
            ),
            omitted=("syncthing-relaysrv",),
        )
        self.assert_family_update_rejected(
            "syncthing-relaysrv"
        )

    def test_missing_required_wezterm_companion(self):
        self.prepare_family_update(
            "wezterm",
            required=("wezterm-debug",),
            omitted=("wezterm-debug",),
        )
        self.assert_family_update_rejected("wezterm-debug")

    def test_optional_debug_absent_from_both_states(self):
        self.prepare_family_update(
            "keepassxc",
        )

        result = self.assemble()
        self.assertEqual(
            result.returncode, 0,
            result.stdout + result.stderr,
        )
        self.assertFalse(
            (self.root / "gh-mutation").exists()
        )

    def test_complete_family_update(self):
        self.prepare_family_update(
            "keepassxc",
            existing_optional=("keepassxc-debug",),
        )

        result = self.assemble()
        self.assertEqual(
            result.returncode, 0,
            result.stdout + result.stderr,
        )

        staged = self.root / "repo-output"
        for name in ("keepassxc", "keepassxc-debug"):
            new = f"{name}-2.0-1-any.pkg.tar.zst"
            old = f"{name}-1.0-1-any.pkg.tar.zst"

            self.assertTrue((staged / new).is_file())
            self.assertFalse((staged / old).exists())
            self.assertTrue(
                (self.root / "archive-output" / old).is_file()
            )

        self.assertFalse(
            (self.root / "gh-mutation").exists()
        )

    def test_unrelated_family_preserved(self):
        package = self.make_package(
            "keepassxc-debug", "1.0", self.fixture
        )

        result = self.assemble()
        self.assertEqual(
            result.returncode, 0,
            result.stdout + result.stderr,
        )

        staged = self.root / "repo-output" / package.name

        self.assertEqual(
            staged.read_bytes(), package.read_bytes()
        )
        self.assertEqual(
            Path(str(staged) + ".sig").read_bytes(),
            Path(str(package) + ".sig").read_bytes(),
        )

        self.assertFalse(
            (self.root / "gh-mutation").exists()
        )

    def test_batch_replaces_two_packages(self):
        extra = "yazi-extra-2.0-1-any.pkg.tar.zst"
        self.make_package(
            "yazi-extra", "2.0", self.root / "package-output"
        )
        self.env["ADDITIONAL_PACKAGE_FILES"] = extra

        result = self.assemble()
        self.assertEqual(
            result.returncode, 0, result.stderr + result.stdout
        )

        output = self.root / "repo-output"
        self.assertEqual(
            {p.name for p in output.glob("*.pkg.tar.zst")},
            {
                "yazi-2.0-1-any.pkg.tar.zst",
                extra,
                "broot-1.0-1-any.pkg.tar.zst",
            },
        )

        state = (
            self.root / "archive-state.txt"
        ).read_text().splitlines()

        self.assertEqual(state, [
            "batch-v2",
            "yazi",
            "yazi-2.0-1-any.pkg.tar.zst",
            "yazi-1.0-1-any.pkg.tar.zst",
            "yazi-extra",
            extra,
            "yazi-extra-1.0-1-any.pkg.tar.zst",
        ])

        archive = self.root / "archive-output"

        for name in ("yazi", "yazi-extra"):
            old = f"{name}-1.0-1-any.pkg.tar.zst"

            self.assertEqual(
                (archive / old).read_bytes(),
                (self.fixture / old).read_bytes(),
            )

            self.run_command([
                "gpg", "--verify",
                str(archive / (old + ".sig")),
                str(archive / old),
            ], check=True)

        self.assertEqual(
            {p.name for p in archive.iterdir()},
            {
                "yazi-1.0-1-any.pkg.tar.zst",
                "yazi-1.0-1-any.pkg.tar.zst.sig",
                "yazi-extra-1.0-1-any.pkg.tar.zst",
                "yazi-extra-1.0-1-any.pkg.tar.zst.sig",
            },
        )

        db = self.run_command([
            "bsdtar", "-tf", str(output / "test-repo.db")
        ], check=True).stdout

        for name in (
            "yazi-2.0-1",
            "yazi-extra-2.0-1",
            "broot-1.0-1",
        ):
            self.assertIn(name + "/desc", db)

        for name in ("yazi-1.0-1", "yazi-extra-1.0-1"):
            self.assertNotIn(name + "/desc", db)

        self.assertFalse((self.root / "gh-mutation").exists())

    def test_batch_adds_package_without_old_version(self):
        extra = "wezterm-debug-2.0-1-any.pkg.tar.zst"
        self.make_package(
            "wezterm-debug", "2.0", self.root / "package-output"
        )
        self.env["ADDITIONAL_PACKAGE_FILES"] = extra

        result = self.assemble()
        self.assertEqual(
            result.returncode, 0, result.stderr + result.stdout
        )

        state = (
            self.root / "archive-state.txt"
        ).read_text().splitlines()

        self.assertEqual(state, [
            "batch-v2",
            "yazi",
            "yazi-2.0-1-any.pkg.tar.zst",
            "yazi-1.0-1-any.pkg.tar.zst",
            "wezterm-debug",
            extra,
            "",
        ])

        self.assertTrue(
            (self.root / "repo-output" / extra).is_file()
        )
        self.assertFalse((self.root / "gh-mutation").exists())

    def test_batch_missing_extra_signature(self):
        extra = "yazi-extra-2.0-1-any.pkg.tar.zst"
        self.make_package(
            "yazi-extra", "2.0", self.root / "package-output"
        )
        self.env["ADDITIONAL_PACKAGE_FILES"] = extra
        (self.root / "package-output" / (extra + ".sig")).unlink()

        result = self.assemble()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "gh-mutation").exists())
        self.assertFalse(
            (self.root / "repo-output/test-repo.db").exists()
        )

    def test_batch_duplicate_candidate_identity(self):
        self.env["ADDITIONAL_PACKAGE_FILES"] = (
            self.env["PACKAGE_FILE"]
        )

        result = self.assemble()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "duplicate candidate identity", result.stderr.lower()
        )
        self.assertFalse((self.root / "gh-mutation").exists())

    def test_batch_unauthorized_extra_signature(self):
        extra = self.make_package(
            "yazi-extra", "2.0", self.root / "package-output"
        )
        self.env["ADDITIONAL_PACKAGE_FILES"] = extra.name
        self.make_unauthorized_signature(extra)

        result = self.assemble()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Unauthorized signing fingerprint", result.stderr
        )
        self.assertFalse((self.root / "gh-mutation").exists())
        self.assertFalse(
            (self.root / "repo-output/test-repo.db").exists()
        )


    def test_existing_candidate_version_blocks_assembly(self):
        old = self.fixture / "yazi-1.0-1-any.pkg.tar.zst"
        old.unlink()
        Path(str(old) + ".sig").unlink()

        candidate = self.root / "package-output" / self.env["PACKAGE_FILE"]
        for asset in (candidate, Path(str(candidate) + ".sig")):
            (self.fixture / asset.name).write_bytes(asset.read_bytes())

        result = self.assemble()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Candidate package version already present",
            result.stderr,
        )
        self.assertFalse(
            (self.root / "archive-state.txt").exists()
        )
        self.assertFalse(
            (self.root / "gh-mutation").exists()
        )

    def test_existing_split_package_version_blocks_assembly(self):
        old = self.fixture / "yazi-extra-1.0-1-any.pkg.tar.zst"
        old.unlink()
        Path(str(old) + ".sig").unlink()

        extra = self.make_package(
            "yazi-extra", "2.0",
            self.root / "package-output",
        )
        for asset in (extra, Path(str(extra) + ".sig")):
            (self.fixture / asset.name).write_bytes(asset.read_bytes())
        self.env["ADDITIONAL_PACKAGE_FILES"] = extra.name

        result = self.assemble()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Candidate package version already present",
            result.stderr,
        )
        self.assertFalse(
            (self.root / "archive-state.txt").exists()
        )
        self.assertFalse(
            (self.root / "gh-mutation").exists()
        )

    def test_orphaned_existing_candidate_signature_blocks(self):
        old = self.fixture / "yazi-1.0-1-any.pkg.tar.zst"
        old.unlink()
        Path(str(old) + ".sig").unlink()

        candidate = self.root / "package-output" / self.env["PACKAGE_FILE"]
        signature = Path(str(candidate) + ".sig")
        (self.fixture / signature.name).write_bytes(signature.read_bytes())

        result = self.assemble()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Candidate package version already present",
            result.stderr,
        )
        self.assertFalse(
            (self.root / "gh-mutation").exists()
        )

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

        state = (
            self.root / "archive-state.txt"
        ).read_text().splitlines()

        self.assertEqual(state, [
            "yazi",
            "yazi-2.0-1-any.pkg.tar.zst",
            "yazi-1.0-1-any.pkg.tar.zst",
        ])

        archive = self.root / "archive-output"
        old_name = "yazi-1.0-1-any.pkg.tar.zst"
        old_package = archive / old_name
        old_signature = archive / (old_name + ".sig")

        self.assertTrue(old_package.is_file())
        self.assertTrue(old_signature.is_file())

        self.assertEqual(
            old_package.read_bytes(),
            (self.fixture / old_name).read_bytes(),
        )
        self.assertEqual(
            old_signature.read_bytes(),
            (self.fixture / (old_name + ".sig")).read_bytes(),
        )

        self.run_command([
            "gpg", "--verify", str(old_signature), str(old_package)
        ], check=True)

        self.assertFalse((output / old_name).exists())
        self.assertFalse((output / (old_name + ".sig")).exists())

        self.assertEqual(
            {file.name for file in archive.iterdir()},
            {old_name, old_name + ".sig"},
        )

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

    def test_duplicate_existing_identity(self):
        self.make_package("broot", "2.0", self.fixture)

        result = self.assemble()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Duplicate package identity", result.stderr)

        output = self.root / "repo-output"
        self.assertFalse((output / "test-repo.db").exists())
        self.assertFalse((self.root / "gh-mutation").exists())

        self.assertTrue(
            (output / "broot-1.0-1-any.pkg.tar.zst").exists()
        )
        self.assertTrue(
            (output / "broot-2.0-1-any.pkg.tar.zst").exists()
        )

    def test_failed_assembly_never_publishes(self):
        signature = self.fixture / "broot-1.0-1-any.pkg.tar.zst.sig"
        signature.write_bytes(b"invalid signature")

        result = self.assemble()

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "gh-mutation").exists())
        self.assertFalse(
            (self.root / "repo-output/test-repo.db").exists()
        )

    def test_signing_fingerprint_not_in_public_key(self):
        self.env["SIGNING_SUBKEY"] = "A" * 40

        result = self.assemble()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match repository public key", result.stderr)
        self.assertFalse((self.root / "gh-mutation").exists())

    def test_missing_repository_public_key(self):
        keyfile = (
            self.root / "arch/keys/t4t3z0r-package-signing.asc"
        )
        keyfile.unlink()

        result = self.assemble()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public key is missing", result.stderr)
        self.assertFalse((self.root / "gh-mutation").exists())

    def run_archive_preflight(self, package="yazi"):
        return self.run_command([
            "python3", str(ARCHIVER),
            "--package", package,
            "--fingerprint", self.key,
            "--staging", str(self.root / "archive-output"),
        ])

    def test_archive_preflight_valid_signed_package(self):
        result = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)

        result = self.run_archive_preflight()
        self.assertEqual(result.returncode, 0, result.stderr)

        plan = __import__("json").loads(result.stdout)
        self.assertTrue(plan["verified"])
        self.assertTrue(plan["dry_run"])
        self.assertEqual(
            plan["file"], "yazi-1.0-1-any.pkg.tar.zst"
        )
        self.assertEqual(plan["previous_versions_to_keep"], 0)
        self.assertFalse(plan["archive_required"])

    def test_archive_preflight_rejects_wrong_signer(self):
        result = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)

        package = (
            self.root / "archive-output/yazi-1.0-1-any.pkg.tar.zst"
        )
        self.make_unauthorized_signature(package)

        result = self.run_archive_preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Unauthorized or ambiguous package signature",
            result.stderr,
        )

    def test_archive_preflight_rejects_missing_signature(self):
        result = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)

        signature = (
            self.root / "archive-output/yazi-1.0-1-any.pkg.tar.zst.sig"
        )
        signature.unlink()

        result = self.run_archive_preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Expected exactly one staged package/signature pair",
            result.stderr,
        )

    def test_archive_preflight_rejects_identity_mismatch(self):
        result = self.assemble()
        self.assertEqual(result.returncode, 0, result.stderr)

        result = self.run_archive_preflight("gameshell")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Staged package identity mismatch", result.stderr)

    def test_unauthorized_candidate_signer(self):
        package = self.root / "package-output" / self.env["PACKAGE_FILE"]
        self.make_unauthorized_signature(package)

        result = self.assemble()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unauthorized signing fingerprint", result.stderr)
        self.assertFalse((self.root / "gh-mutation").exists())
        self.assertFalse((self.root / "repo-output/test-repo.db").exists())

    def test_unauthorized_existing_signer(self):
        package = self.fixture / "broot-1.0-1-any.pkg.tar.zst"
        self.make_unauthorized_signature(package)

        result = self.assemble()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unauthorized signing fingerprint", result.stderr)
        self.assertFalse((self.root / "gh-mutation").exists())
        self.assertFalse((self.root / "repo-output/test-repo.db").exists())

    def test_corrupted_existing_signature(self):
        signature = self.fixture / "broot-1.0-1-any.pkg.tar.zst.sig"
        signature.write_bytes(b"invalid signature")

        result = self.assemble()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            (self.root / "repo-output/test-repo.db").exists()
        )

    def test_failed_assembly_clears_stale_archive_state(self):
        state = self.root / "archive-state.txt"
        state.write_text("stale-success" + chr(10))

        archive = self.root / "archive-output"
        archive.mkdir()
        (archive / "stale-package").write_bytes(b"stale")

        signature = self.root / (
            "package-output/yazi-2.0-1-any.pkg.tar.zst.sig"
        )
        signature.write_bytes(b"invalid signature")

        result = self.assemble()

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(state.exists())
        self.assertFalse(archive.exists())
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
