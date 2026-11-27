"""Native Arch tests for publisher recipe evaluation boundaries.

Run explicitly in the disposable privileged Arch CI container.
Do not execute this suite on a workstation or persistent host.
"""

import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest

from pathlib import Path

from test_generated_recipe_workflows import workflow_step


ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0, str(ROOT / "scripts/package-pipeline")
)

from generated_recipe_metadata import render_recipe

from native_dependency_metadata import (
    extract_dependencies,
    check_dependencies,
    MissingDependencies,
    DependencyCheckError,
)


NATIVE = os.environ.get("PACKAGE_PIPELINE_NATIVE_TESTS") == "1"

SENTINEL = "PRIVILEGED_TEST_SENTINEL"

NOCTALIA_DEPS = """
bash cairo curl fontconfig freetype2 git glib2 glibc
harfbuzz hicolor-icon-theme jemalloc libgcc libglvnd
libical libjxl libpipewire libqalculate librsvg
libsecret libsndfile libsodium libstdc++ libwebp
libwireplumber libxkbcommon libxml2 md4c pam pango
polkit sdbus-cpp tomlplusplus wayland
meson ninja nlohmann-json pkgconf stb wayland-protocols
""".split()


@unittest.skipUnless(
    NATIVE,
    "Explicit disposable native Arch CI execution required",
)
class NativePublisherTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("Native suite requires container root")

        if not Path("/etc/arch-release").exists():
            raise RuntimeError("Native suite requires Arch Linux")

        for tool in (
            "makepkg", "pacman", "runuser", "git",
            "useradd", "userdel",
        ):
            if shutil.which(tool) is None:
                raise RuntimeError(f"Required tool missing: {tool}")

        for user in ("builduser", "builder"):
            try:
                pwd.getpwnam(user)
            except KeyError:
                continue

            raise RuntimeError(
                f"Refusing to reuse existing account: {user}"
            )

        subprocess.run(
            ["useradd", "--create-home", "builduser"],
            check=True,
        )

        cls.addClassCleanup(
            subprocess.run,
            ["userdel", "-r", "builduser"],
            check=True,
        )

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.root = Path(temporary.name)
        self.root.chmod(0o755)

        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.root),
            "LANG": "C.UTF-8",
            "GITHUB_WORKSPACE": str(self.root),
            SENTINEL: "must-not-reach-builder",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(self.root / "gitconfig"),
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_TERMINAL_PROMPT": "0",
        }

        self.evidence = self.root / "evidence"
        self.evidence.mkdir(mode=0o755)

        self.recipe = self.root / "build/noctalia-custom"
        self.recipe.mkdir(parents=True)

        account = pwd.getpwnam("builduser")

        os.chown(
            self.recipe,
            account.pw_uid,
            account.pw_gid,
        )

        scripts = self.root / "scripts/package-pipeline"
        scripts.mkdir(parents=True)

        shutil.copy2(
            ROOT / "scripts/package-pipeline"
            / "native_dependency_metadata.py",
            scripts,
        )

    def execute(self, script, **variables):
        return subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", script],
            cwd=self.root,
            env={**self.env, **variables},
            capture_output=True,
            text=True,
            timeout=90,
        )

    def command(self, *args):
        result = subprocess.run(
            args,
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )

        return result.stdout.strip()

    def assert_success(self, result):
        self.assertEqual(
            result.returncode,
            0,
            result.stdout + result.stderr,
        )

    def assert_failure(self, result):
        self.assertNotEqual(
            result.returncode,
            0,
            result.stdout + result.stderr,
        )

    def write_recipe(self, source):
        path = self.recipe / "PKGBUILD"
        path.write_text(source)
        path.chmod(0o644)

    def fixture_recipe(self, extra=""):
        return (
            "pkgname=fixture\n"
            "pkgver=1.0\n"
            "pkgrel=1\n"
            "pkgdesc='Native metadata fixture'\n"
            "arch=('x86_64')\n"
            "license=('MIT')\n"
            "depends=('bash')\n"
            + extra
            + "\npackage() { :; }\n"
        )

    def preflight(self):
        return self.execute(
            workflow_step(
                "publish-noctalia-custom.yml",
                "Preflight package metadata",
            )
        )

    def native_metadata(self):
        return self.execute(
            '''
            runuser -u builduser -- \
              env -i \
              HOME=/home/builduser \
              USER=builduser \
              LOGNAME=builduser \
              PATH=/usr/bin:/bin \
              LANG=C.UTF-8 \
              bash -e -o pipefail -c '
                cd "$1"
                makepkg --printsrcinfo
              ' _ "$GITHUB_WORKSPACE/build/noctalia-custom"
            '''
        )

    def test_production_noctalia_dependency_parity(self):
        template = (
            ROOT / "arch/noctalia-custom/PKGBUILD.in"
        ).read_text()

        self.write_recipe(
            render_recipe(
                "noctalia-custom",
                template,
                {
                    "PKGVER": "5.6.0.custom.23080f65",
                    "SOURCE_SHA256": "a" * 64,
                },
            )
        )

        result = self.native_metadata()
        self.assert_success(result)

        dependencies = extract_dependencies(
            result.stdout,
            "x86_64",
        )

        self.assertEqual(len(NOCTALIA_DEPS), 39)
        self.assertEqual(
            sorted(dependencies),
            sorted(NOCTALIA_DEPS),
        )

    def test_native_architecture_and_array_append(self):
        self.write_recipe(
            self.fixture_recipe(
                "  depends+=('glibc>=1')\n"
                "depends_x86_64=('git')\n"
                "makedepends_x86_64=('python')\n"
            )
        )

        result = self.native_metadata()
        self.assert_success(result)

        self.assertEqual(
            set(extract_dependencies(
                result.stdout, "x86_64"
            )),
            {"bash", "glibc>=1", "git", "python"},
        )

    def test_native_split_package_declarations(self):
        self.write_recipe(
            "pkgbase=fixture\n"
            "pkgname=('fixture-main' 'fixture-tools')\n"
            "pkgver=1.0\n"
            "pkgrel=1\n"
            "pkgdesc='Split metadata fixture'\n"
            "arch=('x86_64')\n"
            "license=('MIT')\n"
            "depends=('bash')\n"
            "makedepends=('git')\n"
            "package_fixture-main() {\n"
            "  depends=('glibc')\n"
            "}\n"
            "package_fixture-tools() {\n"
            "  depends=('python')\n"
            "}\n"
        )

        result = self.native_metadata()
        self.assert_success(result)

        self.assertEqual(
            set(extract_dependencies(
                result.stdout, "x86_64"
            )),
            {"bash", "git", "glibc", "python"},
        )

    def test_actual_pacman_satisfied_dependency(self):
        self.assertIsNone(check_dependencies(["bash"]))

    def test_actual_pacman_missing_dependency(self):
        dependency = "package-pipeline-native-missing-fixture"

        with self.assertRaises(MissingDependencies) as caught:
            check_dependencies(["bash", dependency])

        self.assertEqual(
            caught.exception.dependencies,
            (dependency,),
        )

    def test_actual_pacman_version_constraint(self):
        with self.assertRaises(MissingDependencies):
            check_dependencies(["bash>999999999"])

    def test_pacman_execution_failure(self):
        original_path = os.environ.get("PATH")

        try:
            # No real executable is available through this PATH.
            os.environ["PATH"] = str(self.root / "absent")

            with self.assertRaises(DependencyCheckError):
                check_dependencies(["bash"])
        finally:
            if original_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = original_path

    def test_noctalia_preflight_unprivileged_and_sanitized(self):
        self.write_recipe(
            self.fixture_recipe(
                'test "$(id -u)" -ne 0 || exit 91\n'
                f'test -z "${{{SENTINEL}+set}}" || exit 92\n'
                'id -u > evaluation-uid\n'
            )
        )

        result = self.preflight()
        self.assert_success(result)

        uid = int(
            (self.recipe / "evaluation-uid").read_text()
        )

        self.assertEqual(
            uid, pwd.getpwnam("builduser").pw_uid
        )

        evidence = self.evidence / "rendered-SRCINFO"

        self.assertTrue(evidence.is_file())
        self.assertEqual(evidence.stat().st_uid, 0)

        self.assertEqual(
            extract_dependencies(
                evidence.read_text(), "x86_64"
            ),
            ["bash"],
        )

    def test_noctalia_metadata_failure_stops_preflight(self):
        self.write_recipe(
            self.fixture_recipe("exit 93\n")
        )

        result = self.preflight()
        self.assert_failure(result)

        self.assertFalse(
            (self.evidence / "rendered-SRCINFO").exists()
        )

        self.assertEqual(
            list(self.evidence.glob(".rendered-SRCINFO.*")),
            [],
        )

    def test_noctalia_missing_dependency_stops_preflight(self):
        self.write_recipe(
            self.fixture_recipe(
                "depends+=("
                "'package-pipeline-native-missing-fixture'"
                ")\n"
            )
        )

        result = self.preflight()
        self.assertEqual(
            result.returncode,
            2,
            result.stdout + result.stderr,
        )

        self.assertIn(
            "Missing dependencies:",
            result.stderr,
        )

        self.assertFalse(
            (self.evidence / "rendered-SRCINFO").exists()
        )

    def test_noctalia_malformed_dependency_stops_preflight(self):
        self.write_recipe(
            self.fixture_recipe(
                "depends+=('--root')\n"
            )
        )

        result = self.preflight()
        self.assert_failure(result)

        self.assertFalse(
            (self.evidence / "rendered-SRCINFO").exists()
        )

    def wezterm_fixture(self):
        upstream = self.root / "upstream"
        upstream.mkdir()

        self.command(
            "git", "-C", str(upstream),
            "init", "-q", "-b", "fixture",
        )

        for key, value in (
            ("user.name", "Fixture"),
            ("user.email", "fixture@example.invalid"),
            ("commit.gpgsign", "false"),
            ("tag.gpgSign", "false"),
        ):
            self.command(
                "git", "-C", str(upstream),
                "config", key, value,
            )

        self.command(
            "git", "-C", str(upstream),
            "commit", "--allow-empty", "-qm", "Release",
        )

        self.command(
            "git", "-C", str(upstream),
            "tag", "20240203-110809-5046fc22",
        )

        self.command(
            "git", "-C", str(upstream),
            "commit", "--allow-empty", "-qm", "Development",
        )

        sha = self.command(
            "git", "-C", str(upstream),
            "rev-parse", "HEAD",
        )

        self.command(
            "git", "config", "--global",
            f"url.{upstream}.insteadOf",
            "https://github.com/wezterm/wezterm.git",
        )

        # Replace only the source-selection service boundary.
        # The actual workflow Git and recipe evaluation remain intact.
        contract = (
            self.root / "scripts/package-pipeline"
            / "verify_source_contract.py"
        )

        contract.write_text(
            "import json\n"
            "print(json.dumps("
            + repr({
                "source_field": "_commit",
                "source_value": sha,
            })
            + "))\n"
        )

        recipe = self.root / "arch/wezterm"
        recipe.mkdir(parents=True)

        original = (
            ROOT / "arch/wezterm/PKGBUILD"
        ).read_text()

        # Instrument the actual production recipe without changing
        # its Git-derived pkgver() transformation.
        (recipe / "PKGBUILD").write_text(
            'test "$(id -u)" -ne 0 || exit 91\n'
            f'test -z "${{{SENTINEL}+set}}" || exit 92\n'
            + original
        )

        return (
            "20240203.110809.5046fc22.r1.g"
            + sha[:9]
        )

    def wezterm_verify(self, expected):
        try:
            pwd.getpwnam("builder")
        except KeyError:
            pass
        else:
            self.fail("Unexpected existing builder account")

        try:
            return self.execute(
                workflow_step(
                    "publish-wezterm.yml",
                    "Verify upstream Git-derived package version",
                ),
                PKGVER=expected,
            )
        finally:
            try:
                pwd.getpwnam("builder")
            except KeyError:
                pass
            else:
                subprocess.run(
                    ["userdel", "-r", "builder"],
                    check=True,
                )

    def test_wezterm_actual_recipe_version_unprivileged(self):
        expected = self.wezterm_fixture()

        result = self.wezterm_verify(expected)
        self.assert_success(result)

        self.assertIn(
            "PASS: WezTerm upstream Git-derived version verified",
            result.stdout,
        )

    def test_wezterm_version_mismatch_is_rejected(self):
        self.wezterm_fixture()

        result = self.wezterm_verify("1.0.0")
        self.assert_failure(result)

        self.assertIn(
            "Upstream Git history does not match",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
