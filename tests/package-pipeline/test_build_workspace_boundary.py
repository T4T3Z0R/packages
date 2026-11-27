"""Portable tests for the build workspace filesystem policy."""

import os
import sys
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0, str(ROOT / "scripts/package-pipeline")
)

import build_workspace_boundary as boundary


class BoundaryPolicyTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.root = Path(temporary.name).resolve()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()

        self.build = self.workspace / "build"
        self.build.mkdir()

        self.writable = self.build / "fixture"
        self.writable.mkdir()

        self.trusted = self.workspace / "scripts"
        self.trusted.mkdir()

        self.script = self.trusted / "trusted.py"
        self.script.write_text("# protected fixture\n")

        self.uid = self.workspace.stat().st_uid
        self.other_uid = self.uid + 1

    def test_valid_workspace(self):
        self.assertEqual(
            boundary.validate_workspace(self.workspace),
            self.workspace,
        )

    def test_relative_workspace_rejected(self):
        with self.assertRaises(boundary.BoundaryError):
            boundary.validate_workspace(Path("workspace"))

    def test_filesystem_root_rejected(self):
        with self.assertRaises(boundary.BoundaryError):
            boundary.validate_workspace(Path("/"))

    def test_workspace_file_rejected(self):
        with self.assertRaises(boundary.BoundaryError):
            boundary.validate_workspace(self.script)

    def test_workspace_symlink_rejected(self):
        link = self.root / "alias"
        link.symlink_to(self.workspace)

        with self.assertRaises(boundary.BoundaryError):
            boundary.validate_workspace(link)

    def test_valid_writable_root(self):
        self.assertEqual(
            boundary.writable_roots(
                self.workspace,
                ["build/fixture"],
            ),
            {self.writable},
        )

    def test_empty_writable_roots(self):
        self.assertEqual(
            boundary.writable_roots(self.workspace, []),
            set(),
        )

    def test_invalid_exclusions_rejected(self):
        for value in (
            "build",
            "scripts",
            "scripts/trusted.py",
            "build/../scripts",
            "build/fixture/nested",
            str(self.writable),
            "../workspace",
        ):
            with self.subTest(value=value):
                with self.assertRaises(boundary.BoundaryError):
                    boundary.writable_roots(
                        self.workspace,
                        [value],
                    )

    def test_duplicate_exclusion_rejected(self):
        with self.assertRaises(boundary.BoundaryError):
            boundary.writable_roots(
                self.workspace,
                ["build/fixture", "build/fixture"],
            )

    def test_missing_exclusion_rejected(self):
        with self.assertRaises(FileNotFoundError):
            boundary.writable_roots(
                self.workspace,
                ["build/missing"],
            )

    def test_file_exclusion_rejected(self):
        target = self.build / "file"
        target.touch()

        with self.assertRaises(boundary.BoundaryError):
            boundary.writable_roots(
                self.workspace,
                ["build/file"],
            )

    def test_symlink_exclusion_rejected(self):
        link = self.build / "link"
        link.symlink_to(self.trusted)

        with self.assertRaises(boundary.BoundaryError):
            boundary.writable_roots(
                self.workspace,
                ["build/link"],
            )

    def test_protected_inventory_excludes_only_allowed_tree(self):
        ignored = self.writable / "generated"
        ignored.touch()

        entries = boundary.collect_protected(
            self.workspace,
            {self.writable},
            self.other_uid,
        )

        self.assertEqual(
            set(entries),
            {
                self.workspace,
                self.build,
                self.trusted,
                self.script,
            },
        )

    def test_builder_owned_readonly_file_rejected(self):
        self.script.chmod(0o444)

        with self.assertRaisesRegex(
            boundary.BoundaryError,
            "owned by builder",
        ):
            boundary.protected_entry(
                self.script,
                self.script.lstat(),
                self.uid,
            )

    def test_builder_owned_directory_rejected(self):
        self.trusted.chmod(0o555)

        with self.assertRaisesRegex(
            boundary.BoundaryError,
            "owned by builder",
        ):
            boundary.protected_entry(
                self.trusted,
                self.trusted.lstat(),
                self.uid,
            )

    def test_protected_symlink_rejected(self):
        link = self.trusted / "link"
        link.symlink_to(self.writable)

        with self.assertRaisesRegex(
            boundary.BoundaryError,
            "Unexpected protected filesystem entry",
        ):
            boundary.collect_protected(
                self.workspace,
                {self.writable},
                self.other_uid,
            )

    def test_protected_fifo_rejected(self):
        os.mkfifo(self.trusted / "fifo")

        with self.assertRaisesRegex(
            boundary.BoundaryError,
            "Unexpected protected filesystem entry",
        ):
            boundary.collect_protected(
                self.workspace,
                {self.writable},
                self.other_uid,
            )

    def test_builder_owned_ancestor_rejected(self):
        with self.assertRaisesRegex(
            boundary.BoundaryError,
            "ancestor is owned by builder",
        ):
            boundary.collect_ancestors(
                self.workspace,
                self.uid,
            )


class ProtectedMissionLinkTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.workspace = Path(temporary.name).resolve()
        self.missions = (
            self.workspace / "source/GameShell/missions"
        )

        self.shared = self.missions / "group/00_shared"
        self.mission = self.missions / "group/01_mission"

        self.shared.mkdir(parents=True)
        self.mission.mkdir(parents=True)

        self.target = self.shared / "init.sh"
        self.target.write_text("# mission fixture\\n")

        self.link = self.mission / "init.sh"
        self.uid = self.workspace.stat().st_uid + 1

    def collect(self):
        return boundary.collect_protected(
            self.workspace, set(), self.uid
        )

    def test_relative_regular_file_link_allowed(self):
        self.link.symlink_to("../00_shared/init.sh")

        entries = self.collect()

        self.assertIn(self.link, entries)
        self.assertIn(self.target, entries)

    def test_relative_directory_link_allowed(self):
        directory = self.shared / "ascii-art"
        directory.mkdir()

        asset = directory / "example.txt"
        asset.write_text("fixture")

        link = self.mission / "ascii-art"
        link.symlink_to("../00_shared/ascii-art")

        entries = self.collect()

        self.assertIn(link, entries)
        self.assertIn(asset, entries)
        self.assertNotIn(link / "example.txt", entries)

    def test_absolute_mission_link_rejected(self):
        self.link.symlink_to(self.target)

        with self.assertRaisesRegex(
            boundary.BoundaryError, "Invalid GameShell"
        ):
            self.collect()

    def test_escaping_mission_link_rejected(self):
        self.link.symlink_to("../../../../outside")

        with self.assertRaisesRegex(
            boundary.BoundaryError, "Invalid GameShell"
        ):
            self.collect()

    def test_dangling_mission_link_rejected(self):
        self.link.symlink_to("../00_shared/missing")

        with self.assertRaisesRegex(
            boundary.BoundaryError, "Missing or invalid"
        ):
            self.collect()

    def test_chained_mission_link_rejected(self):
        indirect = self.shared / "indirect.sh"
        indirect.symlink_to("../00_shared/init.sh")

        self.link.symlink_to("../00_shared/indirect.sh")

        with self.assertRaises(boundary.BoundaryError):
            self.collect()

    def test_link_through_symlink_directory_rejected(self):
        alias = self.shared.parent / "alias"
        alias.symlink_to("00_shared")

        self.link.symlink_to("../alias/init.sh")

        with self.assertRaises(boundary.BoundaryError):
            boundary.verify_protected_mission_link(
                self.link,
                self.link.lstat(),
                self.workspace,
                set(),
                self.uid,
            )

    def test_builder_owned_mission_link_rejected(self):
        self.link.symlink_to("../00_shared/init.sh")

        with self.assertRaisesRegex(
            boundary.BoundaryError, "owned by builder"
        ):
            boundary.verify_protected_mission_link(
                self.link,
                self.link.lstat(),
                self.workspace,
                set(),
                self.link.lstat().st_uid,
            )

    def test_link_outside_mission_scope_rejected(self):
        link = self.workspace / "unapproved"
        link.symlink_to(self.target)

        with self.assertRaisesRegex(
            boundary.BoundaryError,
            "Unexpected protected filesystem entry",
        ):
            self.collect()


class EffectiveAccessTests(BoundaryPolicyTests):

    def check(self, access):
        with patch.object(
            boundary.os,
            "access",
            side_effect=access,
        ):
            boundary.check_effective_access(
                [
                    self.workspace,
                    self.build,
                    self.trusted,
                    self.script,
                ],
                [(self.root, self.workspace)],
                {self.writable},
                self.other_uid,
            )

    def normal_access(self, path, mode):
        return (
            path == self.writable
            or (
                path == self.root
                and mode == os.X_OK
            )
        )

    def test_valid_effective_access(self):
        self.check(self.normal_access)

    def test_writable_protected_file_rejected(self):
        def access(path, mode):
            return (
                path == self.script
                or self.normal_access(path, mode)
            )

        with self.assertRaisesRegex(
            boundary.BoundaryError,
            "Builder can write protected path",
        ):
            self.check(access)

    def test_writable_build_parent_rejected(self):
        def access(path, mode):
            return (
                path == self.build
                or self.normal_access(path, mode)
            )

        with self.assertRaisesRegex(
            boundary.BoundaryError,
            "Builder can write protected path",
        ):
            self.check(access)

    def test_writable_ancestor_rejected(self):
        def access(path, mode):
            return (
                path == self.root
                or self.normal_access(path, mode)
            )

        with self.assertRaisesRegex(
            boundary.BoundaryError,
            "replace protected path through ancestor",
        ):
            self.check(access)

    def test_inaccessible_ancestor_rejected(self):
        with self.assertRaisesRegex(
            boundary.BoundaryError,
            "cannot traverse workspace ancestor",
        ):
            self.check(
                lambda path, mode: path == self.writable
            )

    def test_sticky_ancestor_allowed(self):
        self.root.chmod(0o1777)

        def access(path, mode):
            return (
                path == self.root
                or self.normal_access(path, mode)
            )

        self.check(access)

    def test_unusable_writable_directory_rejected(self):
        def access(path, mode):
            return (
                path == self.root
                and mode == os.X_OK
            )

        with self.assertRaisesRegex(
            boundary.BoundaryError,
            "cannot use authorized workspace",
        ):
            self.check(access)

    def test_inaccessible_docker_endpoints_allowed(self):
        with patch.object(
            boundary.os,
            "access",
            return_value=False,
        ):
            boundary.check_docker_socket_access()

    def test_writable_docker_endpoint_rejected(self):
        for endpoint in (
            Path("/var/run/docker.sock"),
            Path("/run/docker.sock"),
        ):
            with self.subTest(endpoint=endpoint):
                with patch.object(
                    boundary.os,
                    "access",
                    side_effect=lambda path, mode: (
                        path == endpoint
                        and mode == os.W_OK
                    ),
                ):
                    with self.assertRaisesRegex(
                        boundary.BoundaryError,
                        "Docker control endpoint",
                    ):
                        boundary.check_docker_socket_access()


# Keep the effective-access fixtures without inheriting and
# repeating all the filesystem-policy test methods.
for name in tuple(BoundaryPolicyTests.__dict__):
    if name.startswith("test_"):
        setattr(EffectiveAccessTests, name, None)


if __name__ == "__main__":
    unittest.main()
