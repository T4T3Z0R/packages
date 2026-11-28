"""Portable regression tests for protected candidate intake."""

import hashlib
import importlib.util
import io
import os
import stat
import tempfile
import types
import unittest

from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]

HELPER = (
    ROOT
    / "scripts"
    / "package-pipeline"
    / "candidate_intake.py"
)

SPEC = importlib.util.spec_from_file_location(
    "candidate_intake",
    HELPER,
)

intake = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(intake)


class CandidateNameTests(unittest.TestCase):
    def test_valid_package_names(self):
        names = (
            "broot-1.62.0-1-x86_64.pkg.tar.zst",
            "noctalia-custom-5.6.0.custom.23080f65-2-x86_64.pkg.tar.zst",
            "gameshell-0.6.0.r40.g63ae30982cf2-1-any.pkg.tar.zst",
            "ghostty-shell-integration-1.4.0-1-x86_64.pkg.tar.zst",
            "example-1.0+git-1-x86_64.pkg.tar.zst",
        )

        for name in names:
            with self.subTest(name=name):
                self.assertEqual(
                    intake.validate_package_name(name),
                    name,
                )

    def test_invalid_package_names(self):
        names = (
            "",
            ".pkg.tar.zst",
            "-example.pkg.tar.zst",
            ".hidden.pkg.tar.zst",
            "../example.pkg.tar.zst",
            "/example.pkg.tar.zst",
            "directory/example.pkg.tar.zst",
            "example\\file.pkg.tar.zst",
            "example file.pkg.tar.zst",
            "example\nfile.pkg.tar.zst",
            "example\tfile.pkg.tar.zst",
            "example\x00file.pkg.tar.zst",
            "éxample.pkg.tar.zst",
            "example.pkg.tar.gz",
            "example.pkg.tar.zst.sig",
            "a" * 256 + ".pkg.tar.zst",
        )

        for name in names:
            with self.subTest(name=repr(name)):
                with self.assertRaises(intake.IntakeError):
                    intake.validate_package_name(name)


class PathTests(unittest.TestCase):
    def test_valid_absolute_path(self):
        self.assertEqual(
            intake.absolute_parts(
                "/workspace/build/example"
            ),
            ["workspace", "build", "example"],
        )

    def test_reject_unsafe_paths(self):
        paths = (
            "",
            "/",
            "relative/path",
            "//workspace/example",
            "/workspace//example",
            "/workspace/./example",
            "/workspace/../example",
            "/workspace/example/",
        )

        for path in paths:
            with self.subTest(path=path):
                with self.assertRaises(intake.IntakeError):
                    intake.absolute_parts(path)

    def test_open_real_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "real"
            path.mkdir()

            descriptor = intake.open_directory(str(path))

            try:
                self.assertEqual(
                    os.fstat(descriptor).st_ino,
                    path.stat().st_ino,
                )
            finally:
                os.close(descriptor)

    def test_reject_directory_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            real = root / "real"
            real.mkdir()

            link = root / "link"
            link.symlink_to(real, target_is_directory=True)

            with self.assertRaises(OSError):
                intake.open_directory(str(link))

    def test_reject_intermediate_directory_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            real = root / "real"
            real.mkdir()
            (real / "child").mkdir()

            link = root / "link"
            link.symlink_to(real, target_is_directory=True)

            with self.assertRaises(OSError):
                intake.open_directory(
                    str(link / "child")
                )


class SourceMetadataTests(unittest.TestCase):
    def metadata(self, **changes):
        values = {
            "st_mode": stat.S_IFREG | 0o644,
            "st_uid": 12345,
            "st_gid": 12345,
            "st_nlink": 1,
            "st_size": 4096,
        }

        values.update(changes)

        return types.SimpleNamespace(**values)

    def test_accept_regular_owned_source(self):
        intake.validate_source(
            self.metadata(),
            12345,
        )

    def test_reject_wrong_owner(self):
        with self.assertRaisesRegex(
            intake.IntakeError,
            "owner mismatch",
        ):
            intake.validate_source(
                self.metadata(st_uid=0),
                12345,
            )

    def test_reject_multiple_hardlinks(self):
        with self.assertRaisesRegex(
            intake.IntakeError,
            "multiple links",
        ):
            intake.validate_source(
                self.metadata(st_nlink=2),
                12345,
            )

    def test_reject_nonregular_types(self):
        for kind in (
            stat.S_IFDIR,
            stat.S_IFLNK,
            stat.S_IFIFO,
            stat.S_IFSOCK,
            stat.S_IFCHR,
            stat.S_IFBLK,
        ):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(
                    intake.IntakeError,
                    "not regular",
                ):
                    intake.validate_source(
                        self.metadata(
                            st_mode=kind | 0o644
                        ),
                        12345,
                    )

    def test_reject_empty_source(self):
        with self.assertRaisesRegex(
            intake.IntakeError,
            "size outside policy",
        ):
            intake.validate_source(
                self.metadata(st_size=0),
                12345,
            )

    def test_reject_oversized_source(self):
        with self.assertRaisesRegex(
            intake.IntakeError,
            "size outside policy",
        ):
            intake.validate_source(
                self.metadata(
                    st_size=intake.MAX_PACKAGE_BYTES + 1
                ),
                12345,
            )

    def test_accept_exact_size_limit(self):
        intake.validate_source(
            self.metadata(
                st_size=intake.MAX_PACKAGE_BYTES
            ),
            12345,
        )


class IdentityTests(unittest.TestCase):
    def test_reject_root_source_reader(self):
        with mock.patch.object(
            intake.os, "getuid", return_value=0
        ):
            with self.assertRaisesRegex(
                intake.IntakeError,
                "must be unprivileged",
            ):
                intake.stream_source("/unused.pkg.tar.zst")

    def test_reject_mismatched_effective_uid(self):
        with (
            mock.patch.object(
                intake.os, "getuid", return_value=12345
            ),
            mock.patch.object(
                intake.os, "geteuid", return_value=0
            ),
        ):
            with self.assertRaisesRegex(
                intake.IntakeError,
                "must be unprivileged",
            ):
                intake.stream_source("/unused.pkg.tar.zst")

    def test_reject_privileged_supplementary_group(self):
        with (
            mock.patch.object(
                intake.os, "getuid", return_value=12345
            ),
            mock.patch.object(
                intake.os, "geteuid", return_value=12345
            ),
            mock.patch.object(
                intake.os, "getgid", return_value=12345
            ),
            mock.patch.object(
                intake.os, "getegid", return_value=12345
            ),
            mock.patch.object(
                intake.os, "getgroups", return_value=[0]
            ),
        ):
            with self.assertRaisesRegex(
                intake.IntakeError,
                "privileged group",
            ):
                intake.stream_source("/unused.pkg.tar.zst")

    def test_reject_unprivileged_stage(self):
        with mock.patch.object(
            intake.os, "getuid", return_value=12345
        ):
            with self.assertRaisesRegex(
                intake.IntakeError,
                "requires root",
            ):
                intake.stage_candidate(
                    "builder",
                    "/unused.pkg.tar.zst",
                    "/unused",
                )


class DigestTests(unittest.TestCase):
    def test_exact_digest_and_size(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate"

            payload = bytes(range(256)) * 8193
            path.write_bytes(payload)

            digest, size = intake.hash_file(path)

            self.assertEqual(
                digest,
                hashlib.sha256(payload).hexdigest(),
            )
            self.assertEqual(size, len(payload))

    def test_reject_empty_staged_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate"
            path.touch()

            with self.assertRaisesRegex(
                intake.IntakeError,
                "empty",
            ):
                intake.hash_file(path)

    def test_reject_oversized_staged_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate"
            path.write_bytes(b"12345")

            with mock.patch.object(
                intake,
                "MAX_PACKAGE_BYTES",
                4,
            ):
                with self.assertRaisesRegex(
                    intake.IntakeError,
                    "exceeds limit",
                ):
                    intake.hash_file(path)


class TransferMutationTests(unittest.TestCase):
    """Exercise actual file reads with controlled mutations.

    Identity and ownership policy are mocked here so these tests
    run as either root or an ordinary user. Native tests exercise
    the real privilege transition separately.
    """

    def exercise_transfer(self, mutation=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.pkg.tar.zst"

            payload = b"candidate-data-" * 1024
            path.write_bytes(payload)

            output = io.BytesIO()

            class MutatingOutput:
                def __init__(self):
                    self.changed = False

                def write(self, data):
                    result = output.write(data)

                    if mutation and not self.changed:
                        self.changed = True
                        mutation(path)

                    return result

                def flush(self):
                    output.flush()

            with (
                mock.patch.object(
                    intake.os, "getuid", return_value=12345
                ),
                mock.patch.object(
                    intake.os, "geteuid", return_value=12345
                ),
                mock.patch.object(
                    intake.os, "getgid", return_value=12345
                ),
                mock.patch.object(
                    intake.os, "getegid", return_value=12345
                ),
                mock.patch.object(
                    intake.os, "getgroups", return_value=[]
                ),
                mock.patch.object(
                    intake, "validate_source"
                ),
                mock.patch.object(
                    intake,
                    "CHUNK_BYTES",
                    1024,
                ),
                mock.patch.object(
                    intake.sys,
                    "stdout",
                    types.SimpleNamespace(
                        buffer=MutatingOutput()
                    ),
                ),
            ):
                intake.stream_source(str(path))

            return output.getvalue(), payload

    def test_stream_preserves_exact_bytes(self):
        actual, expected = self.exercise_transfer()
        self.assertEqual(actual, expected)

    def test_reject_growth_during_transfer(self):
        def grow(path):
            with path.open("ab") as stream:
                stream.write(b"unexpected")

        with self.assertRaisesRegex(
            intake.IntakeError,
            "grew during transfer",
        ):
            self.exercise_transfer(grow)

    def test_reject_truncation_during_transfer(self):
        def truncate(path):
            path.write_bytes(b"short")

        with self.assertRaisesRegex(
            intake.IntakeError,
            "truncated during transfer",
        ):
            self.exercise_transfer(truncate)

    def test_reject_inplace_mutation(self):
        def modify(path):
            with path.open("r+b") as stream:
                stream.seek(2048)
                stream.write(b"modified")

            previous = path.stat()

            os.utime(
                path,
                ns=(
                    previous.st_atime_ns,
                    previous.st_mtime_ns + 1_000_000_000,
                ),
            )

        with self.assertRaisesRegex(
            intake.IntakeError,
            "changed during transfer",
        ):
            self.exercise_transfer(modify)

    def test_reject_source_replacement(self):
        def replace(path):
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(path.read_bytes())
            os.replace(replacement, path)

        with self.assertRaisesRegex(
            intake.IntakeError,
            "changed during transfer",
        ):
            self.exercise_transfer(replace)


if __name__ == "__main__":
    unittest.main()
