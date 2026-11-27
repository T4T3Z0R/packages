"""Native build boundary tests for disposable Arch CI only."""

import hashlib
import io
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

HELPER = ROOT / "scripts/package-pipeline/build_workspace_boundary.py"

NATIVE = os.environ.get("PACKAGE_PIPELINE_NATIVE_TESTS") == "1"


@unittest.skipUnless(
    NATIVE,
    "Explicit disposable native Arch CI execution required",
)
class NativeBuildBoundaryTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("Native suite requires container root")

        if not Path("/etc/arch-release").is_file():
            raise RuntimeError("Native suite requires Arch Linux")

        for tool in (
            "python3", "bash", "runuser", "useradd",
            "userdel", "makepkg", "bsdtar", "sha256sum",
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

        subprocess.run(
            ["useradd", "--create-home", "builduser"],
            check=True,
        )

        cls.addClassCleanup(
            subprocess.run,
            ["userdel", "-r", "builduser"],
            check=True,
        )

        cls.account = pwd.getpwnam("builduser")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.parent = Path(temporary.name).resolve()
        self.parent.chmod(0o755)

        self.root = self.parent / "workspace"
        self.root.mkdir(mode=0o755)

        for directory in (
            ".git",
            ".github/workflows",
            "arch/broot",
            "scripts/package-pipeline",
            "build/fixture",
            "candidate",
            "evidence",
        ):
            (self.root / directory).mkdir(
                parents=True, mode=0o755
            )

        self.writable = self.root / "build/fixture"

        os.chown(
            self.writable,
            self.account.pw_uid,
            self.account.pw_gid,
        )

        self.trusted = (
            self.root / "scripts/package-pipeline/trusted.py"
        )

        self.trusted.write_text("# protected fixture\n")
        self.trusted.chmod(0o644)

        self.evidence = self.root / "evidence/checksum"
        self.evidence.write_text("protected evidence\n")
        self.evidence.chmod(0o644)

        self.recipe = self.root / "arch/broot/PKGBUILD"

        self.recipe.write_text(
            "pkgname=boundary-fixture\n"
            "pkgver=1.0\n"
            "pkgrel=1\n"
            "pkgdesc='Native boundary fixture'\n"
            "arch=('any')\n"
            "license=('MIT')\n"
            "options=('!strip' '!debug')\n"
            "build() {\n"
            '  test "$(id -u)" -ne 0 || exit 91\n'
            '  id -u > "$srcdir/build-uid"\n'
            "}\n"
            "package() {\n"
            '  install -d "$pkgdir/usr/share/boundary-fixture"\n'
            '  install -m 644 "$srcdir/build-uid" "$pkgdir/usr/share/boundary-fixture/uid"\n'
            "}\n"
        )

        shutil.copy2(
            HELPER,
            self.root / "scripts/package-pipeline",
        )

        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.parent),
            "LANG": "C.UTF-8",
            "GITHUB_WORKSPACE": str(self.root),
        }

    def execute(self, args, **variables):
        return subprocess.run(
            args,
            cwd=self.root,
            env={**self.env, **variables},
            capture_output=True,
            text=True,
            timeout=120,
        )

    def success(self, result):
        self.assertEqual(
            result.returncode, 0,
            result.stdout + result.stderr,
        )

    def failure(self, result, message):
        self.assertNotEqual(
            result.returncode, 0,
            result.stdout + result.stderr,
        )

        self.assertIn(
            message,
            result.stdout + result.stderr,
        )

    def verify(self):
        return self.execute([
            "python3", "-I",
            str(
                self.root / "scripts/package-pipeline"
                / "build_workspace_boundary.py"
            ),
            "--user", "builduser",
            "--workspace", str(self.root),
            "--writable", "build/fixture",
        ])

    def as_builder(self, script, *args):
        return self.execute([
            "runuser", "-u", "builduser", "--",
            "env", "-i",
            "HOME=/home/builduser",
            "PATH=/usr/bin:/bin",
            "LANG=C.UTF-8",
            "python3", "-I", "-c", script,
            *map(str, args),
        ])

    def test_real_filesystem_permissions(self):
        self.success(self.verify())

        result = self.as_builder(
            """
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
assert os.getuid() != 0

def denied(operation):
    try:
        operation()
    except PermissionError:
        return
    raise AssertionError("Protected mutation succeeded")

trusted = root / "scripts/package-pipeline/trusted.py"

denied(lambda: trusted.write_text("modified"))
denied(lambda: trusted.chmod(0o666))
denied(lambda: trusted.unlink())
denied(lambda: (root / "evidence/checksum").write_text("modified"))
denied(lambda: (root / "arch/broot/PKGBUILD").write_text("modified"))
denied(lambda: (root / ".git/config").touch())
denied(lambda: (root / ".github/workflows/new.yml").touch())
denied(lambda: (root / "build/sibling").mkdir())
denied(lambda: (root / "candidate/new.pkg").touch())
denied(lambda: (root / "evidence").rename(root / "evidence-old"))
denied(lambda: root.rename(root.parent / "replacement"))

owned = root / "build/fixture"
probe = owned / "probe"
probe.write_text("allowed")
assert probe.read_text() == "allowed"
probe.rename(owned / "renamed")
(owned / "renamed").unlink()
""",
            self.root,
        )

        self.success(result)

        self.assertEqual(
            self.trusted.read_text(),
            "# protected fixture\n",
        )

        self.assertEqual(
            self.evidence.read_text(),
            "protected evidence\n",
        )

    def test_writable_protected_file_rejected(self):
        self.trusted.chmod(0o666)

        self.failure(
            self.verify(),
            "Builder can write protected path",
        )

    def test_builder_owned_readonly_file_rejected(self):
        os.chown(
            self.trusted,
            self.account.pw_uid,
            self.account.pw_gid,
        )

        self.trusted.chmod(0o444)

        self.failure(
            self.verify(),
            "Protected path is owned by builder",
        )

    def test_primary_group_write_rejected(self):
        os.chown(
            self.trusted,
            0,
            self.account.pw_gid,
        )

        self.trusted.chmod(0o664)

        self.failure(
            self.verify(),
            "Builder can write protected path",
        )

    def test_writable_ancestor_rejected(self):
        self.parent.chmod(0o777)

        self.failure(
            self.verify(),
            "replace protected path through ancestor",
        )

    def test_inaccessible_ancestor_rejected(self):
        self.parent.chmod(0o700)

        self.failure(
            self.verify(),
            "cannot traverse workspace ancestor",
        )

    def test_writable_build_parent_rejected(self):
        self.writable.parent.chmod(0o777)

        self.failure(
            self.verify(),
            "Builder can write protected path",
        )

    def test_protected_symlink_rejected(self):
        link = self.root / "scripts/alias"
        link.symlink_to(self.writable)

        self.failure(
            self.verify(),
            "Unexpected protected filesystem entry",
        )

    def test_protected_mission_link_permissions(self):
        missions = self.root / "source/GameShell/missions/group"

        shared = missions / "00_shared"
        mission = missions / "01_mission"

        shared.mkdir(parents=True)
        mission.mkdir()

        target = shared / "init.sh"
        target.write_text("protected target\n")
        target.chmod(0o644)

        link = mission / "init.sh"
        link.symlink_to("../00_shared/init.sh")

        self.success(self.verify())

        result = self.as_builder(
            """
import sys
from pathlib import Path

link = Path(sys.argv[1])

assert link.read_text() == "protected target\\n"

for operation in (
    lambda: link.write_text("modified"),
    lambda: link.unlink(),
):
    try:
        operation()
    except PermissionError:
        continue

    raise AssertionError("Protected link mutation succeeded")
""",
            link,
        )

        self.success(result)

        self.assertEqual(
            target.read_text(),
            "protected target\n",
        )

        self.assertTrue(link.is_symlink())

        target.chmod(0o666)

        self.failure(
            self.verify(),
            "Builder can write protected path",
        )

    def test_actual_fixed_recipe_build_step(self):
        # Remove the unrelated writable fixture before testing
        # the actual fixed-recipe publisher setup.
        self.writable.rmdir()
        self.writable.parent.rmdir()

        original_recipe = self.recipe.read_bytes()

        script = workflow_step(
            "publish-broot.yml",
            "Build and test as unprivileged user",
        )

        self.assertIn(
            "build_workspace_boundary.py",
            script,
        )

        try:
            result = self.execute([
                "bash", "-e", "-o", "pipefail",
                "-c", script,
            ])

            self.success(result)

            account = pwd.getpwnam("builder")

            packages = list(
                (self.root / "build/broot").glob(
                    "boundary-fixture-*.pkg.tar.*"
                )
            )

            self.assertEqual(len(packages), 1)

            package = packages[0]

            self.assertEqual(
                package.stat().st_uid,
                account.pw_uid,
            )

            result = self.execute([
                "bsdtar", "-xOf", str(package),
                "usr/share/boundary-fixture/uid",
            ])

            self.success(result)

            self.assertEqual(
                int(result.stdout.strip()),
                account.pw_uid,
            )

            self.assertEqual(
                self.recipe.read_bytes(),
                original_recipe,
            )

            self.assertEqual(
                self.trusted.read_text(),
                "# protected fixture\n",
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

    def packaged_fixture(
        self,
        *,
        game=b"standalone fixture\n",
        source=b"corresponding source fixture\n",
        duplicate=False,
        missing=False,
        corrupt_evidence=False,
    ):
        revision = "a" * 40

        game_member = "usr/share/gameshell/gameshell.sh"

        source_member = (
            "usr/share/gameshell/source/"
            f"GameShell-{revision}.tar.gz"
        )

        package_name = "gameshell-fixture.pkg.tar"

        package = self.root / "candidate" / package_name

        entries = [(game_member, game)]

        if not missing:
            entries.append((source_member, source))

        if duplicate:
            entries.append((game_member, game))

        with tarfile.open(package, "w") as archive:
            for name, content in entries:
                member = tarfile.TarInfo(name)
                member.size = len(content)
                member.mode = 0o644

                archive.addfile(
                    member,
                    io.BytesIO(content),
                )

        package.chmod(0o644)

        for name, filename, content in (
            (
                "game-archive-SHA256SUMS",
                "gameshell.sh",
                b"standalone fixture\n",
            ),
            (
                "source-SHA256SUMS",
                "GameShell-source.tar.gz",
                b"corresponding source fixture\n",
            ),
        ):
            digest = hashlib.sha256(content).hexdigest()

            record = f"{digest}  {filename}\n"

            if corrupt_evidence:
                record += record

            path = self.root / "evidence" / name

            path.write_text(record)
            path.chmod(0o644)

        script = workflow_step(
            "publish-gameshell.yml",
            "Inspect and smoke-test candidate",
        )

        start_marker = "# Verify packaged source bytes"
        end_marker = (
            'test "$(wc -l < '
            'evidence/packaged-source-SHA256SUMS)" -eq 2'
        )

        self.assertEqual(script.count(start_marker), 1)
        self.assertEqual(script.count(end_marker), 1)

        start = script.index(start_marker)

        end = (
            script.index(end_marker, start)
            + len(end_marker)
        )

        # Execute the actual verification block, without the
        # adjacent privileged inspection or installation steps.
        return self.execute(
            [
                "bash", "-e", "-o", "pipefail",
                "-c", script[start:end],
            ],
            SOURCE_SHA=revision,
            EXPECTED_PACKAGE=package_name,
        )

    def test_packaged_source_bytes_verified(self):
        result = self.packaged_fixture()

        self.success(result)

        records = (
            self.root / "evidence/packaged-source-SHA256SUMS"
        )

        self.assertEqual(
            len(records.read_text().splitlines()),
            2,
        )

        self.assertEqual(records.stat().st_uid, 0)

        self.assertEqual(
            result.stdout.count(
                "PASS: Packaged source checksum verified:"
            ),
            2,
        )

    def test_modified_packaged_game_rejected(self):
        self.failure(
            self.packaged_fixture(game=b"modified"),
            "Packaged source checksum mismatch",
        )

    def test_modified_packaged_source_rejected(self):
        self.failure(
            self.packaged_fixture(source=b"modified"),
            "Packaged source checksum mismatch",
        )

    def test_duplicate_packaged_member_rejected(self):
        result = self.packaged_fixture(duplicate=True)

        self.assertNotEqual(result.returncode, 0)

        records = (
            self.root / "evidence/packaged-source-SHA256SUMS"
        )

        self.assertEqual(records.read_text(), "")

    def test_missing_packaged_member_rejected(self):
        result = self.packaged_fixture(missing=True)

        self.assertNotEqual(result.returncode, 0)

        records = (
            self.root / "evidence/packaged-source-SHA256SUMS"
        )

        self.assertEqual(
            len(records.read_text().splitlines()),
            1,
        )

    def test_duplicate_checksum_evidence_rejected(self):
        result = self.packaged_fixture(
            corrupt_evidence=True
        )

        self.assertNotEqual(result.returncode, 0)

        records = (
            self.root / "evidence/packaged-source-SHA256SUMS"
        )

        self.assertEqual(records.read_text(), "")


if __name__ == "__main__":
    unittest.main()
