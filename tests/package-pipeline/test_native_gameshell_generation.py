"""Exercise GameShell generation and packaging in disposable Arch CI."""

import hashlib
import os
import pwd
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from pathlib import Path

from test_generated_recipe_workflows import workflow_step


ROOT = Path(__file__).resolve().parents[2]

NATIVE = os.environ.get("PACKAGE_PIPELINE_NATIVE_TESTS") == "1"


@unittest.skipUnless(
    NATIVE,
    "Explicit disposable native Arch CI execution required",
)
class NativeGameShellGenerationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("Native suite requires container root")

        if not Path("/etc/arch-release").is_file():
            raise RuntimeError("Native suite requires Arch Linux")

        for tool in (
            "git", "python3", "bash", "tar", "gzip",
            "makepkg", "pacman", "bsdtar",
            "runuser", "useradd", "userdel",
        ):
            if shutil.which(tool) is None:
                raise RuntimeError(f"Required tool missing: {tool}")

        for user in ("builder", "builduser"):
            try:
                pwd.getpwnam(user)
            except KeyError:
                continue

            raise RuntimeError(
                f"Refusing to reuse existing account: {user}"
            )

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o755)

        self.addCleanup(self.remove_builduser)

        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.root),
            "LANG": "C.UTF-8",
            "GITHUB_WORKSPACE": str(self.root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }

        for directory in (
            ".github/workflows",
            "scripts/package-pipeline",
            "arch",
            "source/GameShell",
        ):
            (self.root / directory).mkdir(
                parents=True, mode=0o755
            )

        for helper in (
            "build_workspace_boundary.py",
            "gameshell_archive_intake.py",
            "generated_recipe_metadata.py",
        ):
            shutil.copy2(
                ROOT / "scripts/package-pipeline" / helper,
                self.root / "scripts/package-pipeline",
            )

        shutil.copytree(
            ROOT / "arch/gameshell",
            self.root / "arch/gameshell",
        )

        self.upstream = self.root / "source/GameShell"

        self.command(
            "git", "init", "-q",
            "-b", "fixture", str(self.root),
        )

        self.command(
            "git", "init", "-q",
            "-b", "fixture", str(self.upstream),
        )

    def remove_builduser(self):
        try:
            pwd.getpwnam("builduser")
        except KeyError:
            return

        subprocess.run(
            ["userdel", "-r", "builduser"],
            check=True,
        )

    def execute(self, args, **variables):
        return subprocess.run(
            args,
            cwd=self.root,
            env={**self.env, **variables},
            capture_output=True,
            text=True,
            timeout=180,
        )

    def success(self, result):
        self.assertEqual(
            result.returncode, 0,
            result.stdout + result.stderr,
        )

    def command(self, *args):
        result = self.execute(list(args))
        self.success(result)
        return result.stdout.strip()

    def source_file(self, name, content, mode=0o644):
        path = self.upstream / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)

    def fixture(self, invalid=False):
        for name, content in (
            ("LICENSE", "GameShell license fixture\n"),
            ("start.sh", "#!/bin/sh\nexit 0\n"),
            ("lib/profile.sh", "# fixture\n"),
            ("lib/header.sh", "#!/bin/sh\nexit 0\n"),
            ("scripts/example", "#!/bin/sh\nexit 0\n"),
            ("missions/default.idx", "group/01_mission\n"),
            (
                "missions/group/00_shared/init.sh",
                "# shared mission fixture\n",
            ),
        ):
            self.source_file(name, content)

        mission = (
            self.upstream / "missions/group/01_mission"
        )

        mission.mkdir()

        (mission / "init.sh").symlink_to(
            "../00_shared/init.sh"
        )

        generator = r'''#!/usr/bin/env bash
set -euo pipefail

test "$(id -u)" -ne 0
test -z "${GITHUB_WORKSPACE+set}"

test "$#" -eq 3
test "$1" = -z
test "$2" = -N

output="$3"

id -u > "$(dirname "$output")/generation-uid"

# Verify the actual generator cannot change trusted inputs.
workspace="$(cd "$(dirname "$output")/../.." && pwd)"

for protected in \
    "$workspace/arch/gameshell/PKGBUILD.in" \
    "$workspace/scripts/package-pipeline/gameshell_archive_intake.py" \
    "$workspace/source/GameShell/LICENSE" \
    "$workspace/evidence" \
    "$workspace/build/gameshell"
do
    test ! -w "$protected"
done

stage="$(mktemp -d "$(dirname "$output")/fixture.XXXXXXXX")"

trap 'rm -rf -- "$stage"' EXIT

mkdir "$stage/gameshell"

cp -RPp start.sh lib scripts missions "$stage/gameshell"

tar -zcf "$output.tgz" -C "$stage" gameshell

cat "$stage/gameshell/lib/header.sh" "$output.tgz" \
    > "$output.sh"

chmod 755 "$output.sh"
'''

        if invalid:
            generator += (
                '\nprintf "invalid suffix" >> "$output.sh"\n'
            )

        self.source_file(
            "utils/gameshell_archive.sh",
            generator,
            0o755,
        )

        self.command(
            "git", "-C", str(self.upstream),
            "add", ".",
        )

        self.command(
            "git", "-C", str(self.upstream),
            "-c", "commit.gpgsign=false",
            "commit", "-qm", "Controlled GameShell fixture",
        )

        return self.command(
            "git", "-C", str(self.upstream),
            "rev-parse", "HEAD",
        )

    def generation_step(self):
        # Identify the exact production step by its unique helper.
        # The normal workflow extractor then supplies its shell body.
        workflow = (
            ROOT / ".github/workflows/publish-gameshell.yml"
        ).read_text()

        lines = workflow.splitlines()

        matches = [
            index
            for index, line in enumerate(lines)
            if line.strip().startswith(
                "python3 scripts/package-pipeline/"
                "gameshell_archive_intake.py "
            )
        ]

        self.assertEqual(len(matches), 1)

        for line in reversed(lines[:matches[0]]):
            if line.startswith("      - name: "):
                return workflow_step(
                    "publish-gameshell.yml",
                    line.removeprefix("      - name: "),
                )

        self.fail("GameShell generation step not found")

    def generate(self, revision):
        return self.execute(
            [
                "bash", "-e", "-o", "pipefail",
                "-c", self.generation_step(),
            ],
            SOURCE_SHA=revision,
            PKGVER="0.6.0",
        )

    def test_actual_generation_and_native_package_build(self):
        revision = self.fixture()

        original_license = (
            self.upstream / "LICENSE"
        ).read_bytes()

        result = self.generate(revision)
        self.success(result)

        account = pwd.getpwnam("builduser")

        generation = (
            self.root / "build/gameshell-generation"
        )

        self.assertEqual(
            int(
                (generation / "generation-uid").read_text()
            ),
            account.pw_uid,
        )

        self.assertNotEqual(account.pw_uid, 0)

        package_dir = self.root / "build/gameshell"
        evidence = self.root / "evidence"

        self.assertEqual(package_dir.stat().st_uid, 0)
        self.assertEqual(evidence.stat().st_uid, 0)

        standalone = (
            package_dir / "gameshell.sh"
        ).read_bytes()

        self.assertEqual(
            standalone,
            (generation / "gameshell.sh").read_bytes(),
        )

        self.assertEqual(
            (evidence / "gameshell.tgz").read_bytes(),
            (generation / "gameshell.tgz").read_bytes(),
        )

        with tarfile.open(
            evidence / "gameshell.tgz", "r:gz"
        ) as archive:
            link = archive.getmember(
                "gameshell/missions/group/01_mission/init.sh"
            )

            self.assertTrue(link.issym())

            self.assertEqual(
                link.linkname,
                "../00_shared/init.sh",
            )

        for record, filename in (
            ("game-archive-SHA256SUMS", "gameshell.sh"),
            ("source-SHA256SUMS", "GameShell-source.tar.gz"),
        ):
            digest = hashlib.sha256(
                (package_dir / filename).read_bytes()
            ).hexdigest()

            self.assertEqual(
                (evidence / record).read_text(),
                f"{digest}  {filename}\n",
            )

            self.assertEqual(
                (evidence / record).stat().st_uid,
                0,
            )

        self.assertEqual(
            (self.upstream / "LICENSE").read_bytes(),
            original_license,
        )

        self.assertEqual(
            self.command(
                "git", "-C", str(self.upstream),
                "status", "--porcelain",
            ),
            "",
        )

        # Exercise the actual rendered production recipe and
        # actual unsigned package build step.
        result = self.execute([
            "bash", "-e", "-o", "pipefail", "-c",
            workflow_step(
                "publish-gameshell.yml",
                "Build unsigned package",
            ),
        ])

        self.success(result)

        self.assertEqual(
            package_dir.stat().st_uid,
            account.pw_uid,
        )

        packages = list(
            package_dir.glob("gameshell-*.pkg.tar.*")
        )

        self.assertEqual(len(packages), 1)

        package = packages[0]

        self.assertEqual(
            package.stat().st_uid,
            account.pw_uid,
        )

        for member, expected in (
            (
                "usr/share/gameshell/gameshell.sh",
                standalone,
            ),
            (
                "usr/share/gameshell/source/"
                f"GameShell-{revision}.tar.gz",
                (
                    package_dir / "GameShell-source.tar.gz"
                ).read_bytes(),
            ),
        ):
            result = subprocess.run(
                ["bsdtar", "-xOf", str(package), member],
                capture_output=True,
                timeout=30,
                check=True,
            )

            self.assertEqual(result.stdout, expected)

    def test_invalid_generated_archive_stops_before_render(self):
        revision = self.fixture(invalid=True)

        result = self.generate(revision)

        self.assertNotEqual(
            result.returncode, 0,
            result.stdout + result.stderr,
        )

        self.assertIn(
            "Standalone archive payload mismatch",
            result.stderr,
        )

        self.assertFalse(
            (
                self.root / "build/gameshell/gameshell.sh"
            ).exists()
        )

        self.assertFalse(
            (
                self.root / "build/gameshell/PKGBUILD"
            ).exists()
        )


if __name__ == "__main__":
    unittest.main()
