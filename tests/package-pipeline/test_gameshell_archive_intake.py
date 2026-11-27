"""Portable regression tests for GameShell archive intake."""

import gzip
import hashlib
import io
import os
import sys
import tarfile
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(
    0, str(ROOT / "scripts/package-pipeline")
)

import gameshell_archive_intake as intake


HEADER = b"#!/bin/sh\n# Fixture only; never execute.\n"

REQUIRED = (
    "gameshell/start.sh",
    "gameshell/lib/profile.sh",
    "gameshell/lib/header.sh",
    "gameshell/missions/default.idx",
    "gameshell/scripts/example",
    "gameshell/missions/example/goal.txt",
)


def payload_for(
    names=REQUIRED,
    extra=(),
):
    buffer = io.BytesIO()

    with tarfile.open(
        fileobj=buffer,
        mode="w",
    ) as archive:
        for name in names:
            content = (
                HEADER
                if name == "gameshell/lib/header.sh"
                else b"fixture\n"
            )
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o644

            archive.addfile(
                member,
                io.BytesIO(content),
            )

        for member, content in extra:
            archive.addfile(
                member,
                io.BytesIO(content)
                if content is not None
                else None,
            )

    return gzip.compress(
        buffer.getvalue(),
        mtime=0,
    )


class ArchiveValidationTests(unittest.TestCase):

    def validate(self, payload):
        return intake.validate_archive(
            HEADER + payload,
            payload,
        )

    def test_valid_archive(self):
        payload = payload_for()

        self.assertEqual(
            self.validate(payload),
            sorted(REQUIRED),
        )

    def test_payload_mismatch(self):
        payload = payload_for()

        with self.assertRaises(ValueError):
            intake.validate_archive(
                HEADER + payload + b"extra",
                payload,
            )

    def test_missing_shell_header(self):
        payload = payload_for()

        with self.assertRaises(ValueError):
            intake.validate_archive(
                b"not a shell header\n" + payload,
                payload,
            )

    def test_invalid_compressed_payload(self):
        for payload in (
            b"not gzip",
            b"\x1f\x8b",
            gzip.compress(b"not a tar archive"),
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(
                    (OSError, ValueError, EOFError,
                     tarfile.TarError)
                ):
                    self.validate(payload)

    def test_missing_required_files(self):
        for missing in REQUIRED:
            with self.subTest(missing=missing):
                names = tuple(
                    name for name in REQUIRED
                    if name != missing
                )

                with self.assertRaises(ValueError):
                    self.validate(payload_for(names))

    def test_mission_index_is_not_mission_content(self):
        names = (
            "gameshell/start.sh",
            "gameshell/lib/profile.sh",
            "gameshell/lib/header.sh",
            "gameshell/scripts/example",
            "gameshell/missions/default.idx",
            "gameshell/missions/alternate.idx",
        )

        with self.assertRaisesRegex(
            ValueError,
            "Required GameShell mission content missing",
        ):
            self.validate(payload_for(names))

    def test_unsafe_member_paths(self):
        for name in (
            "/gameshell/absolute",
            "gameshell/../outside",
            "other-root/file",
            "gameshell/sub/../../outside",
            "gameshell/bad\\name",
            "gameshell/bad\nname",
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.validate(
                        payload_for(REQUIRED + (name,))
                    )

    def test_duplicate_member(self):
        with self.assertRaises(ValueError):
            self.validate(
                payload_for(
                    REQUIRED + (REQUIRED[0],)
                )
            )

    def test_normalized_duplicate_member(self):
        with self.assertRaises(ValueError):
            self.validate(
                payload_for(
                    REQUIRED + ("gameshell/./start.sh",)
                )
            )

    def test_symbolic_link(self):
        member = tarfile.TarInfo("gameshell/link")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"

        with self.assertRaises(ValueError):
            self.validate(
                payload_for(extra=((member, None),))
            )

    def test_hard_link(self):
        member = tarfile.TarInfo("gameshell/link")
        member.type = tarfile.LNKTYPE
        member.linkname = REQUIRED[0]

        with self.assertRaises(ValueError):
            self.validate(
                payload_for(extra=((member, None),))
            )

    def test_special_member_types(self):
        for member_type in (
            tarfile.FIFOTYPE,
            tarfile.CHRTYPE,
            tarfile.BLKTYPE,
        ):
            with self.subTest(member_type=member_type):
                member = tarfile.TarInfo(
                    "gameshell/special"
                )

                member.type = member_type

                with self.assertRaises(ValueError):
                    self.validate(
                        payload_for(
                            extra=((member, None),)
                        )
                    )

    def test_special_permission_bits(self):
        for mode in (0o4755, 0o2755, 0o1755):
            with self.subTest(mode=mode):
                member = tarfile.TarInfo(
                    "gameshell/special-mode"
                )

                member.mode = mode
                member.size = 1

                with self.assertRaises(ValueError):
                    self.validate(
                        payload_for(
                            extra=((member, b"x"),)
                        )
                    )

    def test_member_count_limit(self):
        with patch.object(intake, "MAX_MEMBERS", 5):
            with self.assertRaises(ValueError):
                self.validate(payload_for())

    def test_compressed_size_limit(self):
        payload = payload_for()

        with patch.object(
            intake,
            "MAX_ARCHIVE_BYTES",
            len(payload) - 1,
        ):
            with self.assertRaises(ValueError):
                intake.inspect_payload(payload)

    def test_expanded_stream_limit(self):
        payload = payload_for()

        with patch.object(
            intake,
            "MAX_EXPANDED_BYTES",
            1024,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "Expanded archive exceeds size limit",
            ):
                self.validate(payload)

    def test_header_size_limit(self):
        payload = payload_for()

        with patch.object(
            intake,
            "MAX_HEADER_BYTES",
            len(HEADER) - 1,
        ):
            with self.assertRaises(ValueError):
                self.validate(payload)


class ArchiveRelationshipTests(unittest.TestCase):

    GROUP = "gameshell/missions/group"
    SHARED = GROUP + "/00_shared"
    MISSION = GROUP + "/01_mission"

    def regular(self, name, content=b"fixture\n"):
        member = tarfile.TarInfo(name)
        member.mode = 0o644
        member.size = len(content)

        return member, content

    def directory(self, name):
        member = tarfile.TarInfo(name)
        member.type = tarfile.DIRTYPE
        member.mode = 0o755

        return member, None

    def link(self, name, target):
        member = tarfile.TarInfo(name)
        member.type = tarfile.SYMTYPE
        member.linkname = target
        member.mode = 0o777

        return member, None

    def validate(self, extra):
        payload = payload_for(extra=extra)

        return intake.validate_archive(
            HEADER + payload,
            payload,
        )

    def test_relative_mission_file_link_allowed(self):
        target = self.SHARED + "/init.sh"
        link = self.MISSION + "/init.sh"

        # Forward references must work.
        entries = self.validate((
            self.link(link, "../00_shared/init.sh"),
            self.regular(target),
        ))

        self.assertIn(link, entries)
        self.assertIn(target, entries)

    def test_relative_mission_directory_link_allowed(self):
        target = self.SHARED + "/ascii-art"
        link = self.MISSION + "/ascii-art"

        entries = self.validate((
            self.directory(target),
            self.regular(target + "/example.txt"),
            self.link(link, "../00_shared/ascii-art"),
        ))

        self.assertIn(link, entries)
        self.assertIn(target, entries)
        self.assertIn(target + "/example.txt", entries)

    def test_unsafe_mission_link_targets_rejected(self):
        for target in (
            "/etc/passwd",
            "../../other-group/init.sh",
            "../../../outside",
            "../00_shared/../init.sh",
            "../00_shared//init.sh",
            "../00_shared/./init.sh",
            "../00_shared/bad\\name",
            "../00_shared/bad\nname",
        ):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    self.validate((
                        self.link(
                            self.MISSION + "/init.sh",
                            target,
                        ),
                        self.regular(
                            self.SHARED + "/init.sh"
                        ),
                    ))

    def test_missing_mission_link_target_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "Missing archive mission link target"
        ):
            self.validate((
                self.link(
                    self.MISSION + "/init.sh",
                    "../00_shared/init.sh",
                ),
            ))

    def test_chained_mission_link_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "target is not direct"
        ):
            self.validate((
                self.link(
                    self.MISSION + "/init.sh",
                    "../00_shared/indirect.sh",
                ),
                self.link(
                    self.SHARED + "/indirect.sh",
                    "../02_shared/init.sh",
                ),
                self.regular(
                    self.GROUP + "/02_shared/init.sh"
                ),
            ))

    def test_cyclic_mission_links_rejected(self):
        with self.assertRaises(ValueError):
            self.validate((
                self.link(
                    self.MISSION + "/init.sh",
                    "../00_shared/init.sh",
                ),
                self.link(
                    self.SHARED + "/init.sh",
                    "../01_mission/init.sh",
                ),
            ))

    def test_members_below_symbolic_link_rejected(self):
        target = self.SHARED + "/ascii-art"
        link = self.MISSION + "/ascii-art"

        entries = (
            self.directory(target),
            self.link(link, "../00_shared/ascii-art"),
            self.regular(link + "/unexpected.txt"),
        )

        for order in (entries, tuple(reversed(entries))):
            with self.subTest(order=order):
                with self.assertRaisesRegex(
                    ValueError, "non-directory ancestor"
                ):
                    self.validate(order)

    def test_members_below_regular_file_rejected(self):
        entries = (
            self.regular("gameshell/parent"),
            self.regular("gameshell/parent/child"),
        )

        for order in (entries, tuple(reversed(entries))):
            with self.subTest(order=order):
                with self.assertRaisesRegex(
                    ValueError, "non-directory ancestor"
                ):
                    self.validate(order)

    def test_link_outside_missions_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "symbolic link location"
        ):
            self.validate((
                self.link(
                    "gameshell/lib/link",
                    "../scripts/example",
                ),
            ))

    def test_duplicate_symbolic_link_name_rejected(self):
        name = self.MISSION + "/init.sh"

        with self.assertRaisesRegex(
            ValueError, "Duplicate archive member"
        ):
            self.validate((
                self.regular(self.SHARED + "/init.sh"),
                self.link(name, "../00_shared/init.sh"),
                self.link(name, "../00_shared/init.sh"),
            ))

    def test_standalone_header_mismatch_rejected(self):
        payload = payload_for()

        with self.assertRaisesRegex(
            ValueError, "Standalone and embedded headers differ"
        ):
            intake.validate_archive(
                HEADER + b"# Different header\n" + payload,
                payload,
            )

    def test_missing_embedded_header_rejected(self):
        names = tuple(
            name for name in REQUIRED
            if name != "gameshell/lib/header.sh"
        )

        payload = payload_for(names)

        with self.assertRaisesRegex(
            ValueError, "Required embedded header missing"
        ):
            intake.validate_archive(
                HEADER + payload,
                payload,
            )


class ProtectedIntakeTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.root = Path(temporary.name)

        self.generated = self.root / "generated"
        self.destination = self.root / "destination"
        self.evidence = self.root / "evidence"

        for directory in (
            self.generated,
            self.destination,
            self.evidence,
        ):
            directory.mkdir(mode=0o755)

        self.payload = payload_for()
        self.standalone = HEADER + self.payload

        self.script = self.generated / "gameshell.sh"

        self.script.write_bytes(self.standalone)

        (self.generated / "gameshell.tgz").write_bytes(
            self.payload
        )

    def run_intake(self):
        intake.intake(
            self.generated,
            self.destination,
            self.evidence,
        )

    def assert_no_staged_archive(self):
        self.assertFalse(
            (self.destination / "gameshell.sh").exists()
        )

    def test_valid_intake_preserves_exact_bytes(self):
        self.run_intake()

        self.assertEqual(
            (self.destination / "gameshell.sh").read_bytes(),
            self.standalone,
        )

        self.assertEqual(
            (
                self.evidence / "game-archive-files.txt"
            ).read_text().splitlines(),
            sorted(REQUIRED),
        )

        self.assertEqual(
            (self.evidence / "gameshell.tgz").read_bytes(),
            self.payload,
        )

        self.assertEqual(
            (
                self.evidence / "game-payload-SHA256SUMS"
            ).read_text(),
            hashlib.sha256(self.payload).hexdigest()
            + "  gameshell.tgz\n",
        )

    def test_generated_symlink_rejected(self):
        target = self.root / "outside"
        target.write_bytes(self.standalone)

        self.script.unlink()
        self.script.symlink_to(target)

        with self.assertRaises(OSError):
            self.run_intake()

        self.assert_no_staged_archive()

    def test_generated_hard_link_rejected(self):
        os.link(
            self.script,
            self.root / "second-link",
        )

        with self.assertRaises(ValueError):
            self.run_intake()

        self.assert_no_staged_archive()

    def test_generated_fifo_rejected(self):
        self.script.unlink()
        os.mkfifo(self.script)

        with self.assertRaises(ValueError):
            self.run_intake()

        self.assert_no_staged_archive()

    def test_generated_directory_symlink_rejected(self):
        original = self.root / "real-generated"
        self.generated.rename(original)
        self.generated.symlink_to(
            original,
            target_is_directory=True,
        )

        with self.assertRaises(OSError):
            self.run_intake()

        self.assert_no_staged_archive()

    def test_existing_destination_not_overwritten(self):
        target = self.destination / "gameshell.sh"
        target.write_bytes(b"preserve this")

        with self.assertRaises(FileExistsError):
            self.run_intake()

        self.assertEqual(
            target.read_bytes(),
            b"preserve this",
        )

    def test_destination_symlink_rejected(self):
        target = self.root / "outside"
        target.write_bytes(b"preserve this")

        (self.destination / "gameshell.sh").symlink_to(
            target
        )

        with self.assertRaises(FileExistsError):
            self.run_intake()

        self.assertEqual(
            target.read_bytes(),
            b"preserve this",
        )

    def test_writable_evidence_directory_rejected(self):
        self.evidence.chmod(0o777)

        with self.assertRaises(ValueError):
            self.run_intake()

        self.assert_no_staged_archive()

    def test_writable_destination_directory_rejected(self):
        self.destination.chmod(0o777)

        with self.assertRaises(ValueError):
            self.run_intake()

        self.assert_no_staged_archive()

    def test_invalid_payload_leaves_no_staged_archive(self):
        self.script.write_bytes(
            HEADER + b"invalid archive"
        )

        with self.assertRaises(ValueError):
            self.run_intake()

        self.assert_no_staged_archive()

        self.assertEqual(
            list(self.evidence.iterdir()),
            [],
        )


if __name__ == "__main__":
    unittest.main()
