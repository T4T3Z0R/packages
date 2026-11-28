"""Portable candidate privilege and static linkage policy tests."""

import hashlib
import importlib.util
import io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest

from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPTS = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "package-pipeline"
)


def load_module(name):
    spec = importlib.util.spec_from_file_location(
        name,
        SCRIPTS / f"{name}.py",
    )

    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)

    return module


privileges = load_module("candidate_privileges")
linkage = load_module("candidate_linkage")


def process_status(**overrides):
    fields = {
        "Uid": "65534 65534 65534 65534",
        "Gid": "65534 65534 65534 65534",
        "Groups": "",
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
    }

    fields.update(overrides)

    return "".join(
        f"{name}:\t{value}\n"
        for name, value in fields.items()
    )


def validate_status(status):
    return privileges.validate_process_status(
        status,
        uid=65534,
        gid=65534,
    )


def dynamic_tags(*additional):
    return [
        ("DT_NEEDED", "libc.so.6"),
        *additional,
        ("DT_NULL", None),
    ]


EXECUTABLE = "/protected/candidate/fixture"

HEADER = (
    f"{EXECUTABLE} "
    f"(interpreter => {linkage.INTERPRETER})\n"
)


def runtime_path(path):
    linkage.validate_absolute_path(path)

    if path == linkage.INTERPRETER:
        return "/usr/lib/ld-linux-x86-64.so.2"

    if not path.startswith("/usr/lib/"):
        raise linkage.LinkageError(
            "Untrusted runtime library"
        )

    return path


def parse_tree(records, *, needed=("libc.so.6",)):
    return linkage.parse_dependency_tree(
        HEADER + records,
        executable=EXECUTABLE,
        needed=needed,
        runtime_path_validator=runtime_path,
    )


class PrivilegeStatusTests(unittest.TestCase):

    def test_valid_process_status(self):
        result = validate_status(process_status())

        self.assertEqual(result["uid"], 65534)
        self.assertEqual(result["gid"], 65534)
        self.assertEqual(
            result["supplementary_groups"], []
        )
        self.assertTrue(result["capabilities_cleared"])
        self.assertTrue(result["bounding_set_cleared"])
        self.assertTrue(result["no_new_privs"])

    def test_reject_invalid_expected_identity(self):
        for uid, gid in (
            (0, 65534),
            (65534, 0),
            (-1, 65534),
            (True, 65534),
            (65534, "65534"),
        ):
            with self.subTest(uid=uid, gid=gid):
                with self.assertRaises(
                    privileges.PrivilegeError
                ):
                    privileges.validate_process_status(
                        process_status(),
                        uid=uid,
                        gid=gid,
                    )

    def test_missing_required_fields(self):
        for field in privileges.REQUIRED_FIELDS:
            with self.subTest(field=field):
                status = "".join(
                    line + "\n"
                    for line in process_status().splitlines()
                    if not line.startswith(field + ":")
                )

                with self.assertRaisesRegex(
                    privileges.PrivilegeError,
                    "fields missing",
                ):
                    validate_status(status)

    def test_duplicate_required_fields(self):
        for line in process_status().splitlines():
            with self.subTest(line=line):
                with self.assertRaisesRegex(
                    privileges.PrivilegeError,
                    "Duplicate process status field",
                ):
                    validate_status(
                        process_status() + line + "\n"
                    )

    def test_all_identity_positions(self):
        for field in ("Uid", "Gid"):
            for index in range(4):
                values = ["65534"] * 4
                values[index] = "0"

                with self.subTest(
                    field=field,
                    position=index,
                ):
                    with self.assertRaisesRegex(
                        privileges.PrivilegeError,
                        "Unexpected process identity",
                    ):
                        validate_status(
                            process_status(
                                **{
                                    field: " ".join(values)
                                }
                            )
                        )

    def test_malformed_identity_fields(self):
        for value in (
            "",
            "65534",
            "65534 65534 65534",
            "65534 65534 65534 65534 65534",
            "+65534 65534 65534 65534",
            "abc 65534 65534 65534",
        ):
            with self.subTest(value=value):
                with self.assertRaises(
                    privileges.PrivilegeError
                ):
                    validate_status(
                        process_status(Uid=value)
                    )

    def test_supplementary_groups_rejected(self):
        for value in ("0", "65534", "1000 998"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    privileges.PrivilegeError,
                    "Supplementary groups",
                ):
                    validate_status(
                        process_status(Groups=value)
                    )

    def test_every_capability_set_rejected(self):
        for field in privileges.CAPABILITY_FIELDS:
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    privileges.PrivilegeError,
                    field,
                ):
                    validate_status(
                        process_status(
                            **{
                                field: "0000000000000001"
                            }
                        )
                    )

    def test_malformed_capabilities_rejected(self):
        for value in (
            "",
            "0",
            "00000000000000000",
            "000000000000000g",
        ):
            with self.subTest(value=value):
                with self.assertRaises(
                    privileges.PrivilegeError
                ):
                    validate_status(
                        process_status(CapEff=value)
                    )

    def test_no_new_privs_required(self):
        for value in ("", "0", "2", "01", "true"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    privileges.PrivilegeError,
                    "NoNewPrivs",
                ):
                    validate_status(
                        process_status(NoNewPrivs=value)
                    )

    def test_identity_guard_rejects_saved_root(self):
        with (
            patch.object(
                privileges.os,
                "getresuid",
                return_value=(65534, 65534, 0),
            ),
            patch.object(
                privileges.os,
                "getresgid",
                return_value=(65534,) * 3,
            ),
            patch.object(
                privileges.os,
                "getgroups",
                return_value=[],
            ),
        ):
            with self.assertRaises(
                privileges.PrivilegeError
            ):
                privileges.require_inspection_identity()


class PathPolicyTests(unittest.TestCase):

    def test_valid_absolute_paths(self):
        for value in (
            EXECUTABLE,
            linkage.INTERPRETER,
            "/usr/lib/libstdc++.so.6",
            "/usr/lib/libical.so.4.0",
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    linkage.validate_absolute_path(value),
                    value,
                )

    def test_invalid_absolute_paths(self):
        for value in (
            "",
            "/",
            "relative/path",
            "/usr//lib/libc.so.6",
            "/usr/./lib/libc.so.6",
            "/usr/lib/../bin/bash",
            "/usr/lib/",
            "/tmp/with space",
            "/tmp/line\nbreak",
            "/tmp/glob*",
            "/tmp/glob?",
            "/tmp/[glob]",
            "/tmp/back\\slash",
            "/" + "a" * 4096,
            None,
        ):
            with self.subTest(value=value):
                with self.assertRaises(
                    linkage.LinkageError
                ):
                    linkage.validate_absolute_path(value)

    def test_valid_library_names(self):
        for value in (
            "libc.so.6",
            "libsdbus-c++.so.2",
            "libical.so.4.0",
            "libwlroots-0.20.so",
            "libjxl_threads.so.0.13",
            "ld-linux-x86-64.so.2",
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    linkage.validate_library_name(value),
                    value,
                )

    def test_invalid_library_names(self):
        for value in (
            "",
            ".",
            "..",
            "/usr/lib/libc.so.6",
            "../libc.so.6",
            "subdir/libc.so.6",
            "$ORIGIN/libc.so.6",
            "libc.so.6\n",
            "lib c.so.6",
            "-option",
            "lib*.so",
            "lib[abc].so",
            "lib\\name.so",
            "a" * 256,
            None,
        ):
            with self.subTest(value=value):
                with self.assertRaises(
                    linkage.LinkageError
                ):
                    linkage.validate_library_name(value)

    def test_library_name_size_boundary(self):
        value = "a" * 255

        self.assertEqual(
            linkage.validate_library_name(value),
            value,
        )


class DynamicPolicyTests(unittest.TestCase):

    def test_standard_dynamic_metadata(self):
        result = linkage.validate_dynamic_tags(
            dynamic_tags(
                ("DT_NEEDED", "libstdc++.so.6"),
                ("DT_FLAGS", 0x8),
                ("DT_FLAGS_1", 0x08000001),
            )
        )

        self.assertEqual(
            result,
            ("libc.so.6", "libstdc++.so.6"),
        )

    def test_every_forbidden_dynamic_tag(self):
        for tag in linkage.FORBIDDEN_DYNAMIC_TAGS:
            with self.subTest(tag=tag):
                with self.assertRaisesRegex(
                    linkage.LinkageError,
                    "Unsupported candidate dynamic tag",
                ):
                    linkage.validate_dynamic_tags(
                        dynamic_tags((tag, None))
                    )

    def test_forbidden_dynamic_flags(self):
        for flag in (
            linkage.DF_TEXTREL,
            linkage.DF_ORIGIN,
            linkage.DF_TEXTREL | linkage.DF_ORIGIN,
        ):
            with self.subTest(flag=flag):
                with self.assertRaisesRegex(
                    linkage.LinkageError,
                    "Unsupported candidate dynamic flags",
                ):
                    linkage.validate_dynamic_tags(
                        dynamic_tags(("DT_FLAGS", flag))
                    )

    def test_forbidden_search_flags(self):
        for flag in (
            linkage.DF_1_NODEFLIB,
            linkage.DF_1_ORIGIN,
        ):
            with self.subTest(flag=flag):
                with self.assertRaisesRegex(
                    linkage.LinkageError,
                    "Unsupported candidate search flags",
                ):
                    linkage.validate_dynamic_tags(
                        dynamic_tags(
                            ("DT_FLAGS_1", flag)
                        )
                    )

    def test_path_bearing_dependency_rejected(self):
        with self.assertRaises(
            linkage.LinkageError
        ):
            linkage.validate_dynamic_tags(
                dynamic_tags(
                    ("DT_NEEDED", "../libunsafe.so")
                )
            )

    def test_duplicate_direct_dependency(self):
        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Duplicate direct dependency",
        ):
            linkage.validate_dynamic_tags(
                dynamic_tags(
                    ("DT_NEEDED", "libc.so.6")
                )
            )

    def test_missing_termination(self):
        with self.assertRaisesRegex(
            linkage.LinkageError,
            "lacks termination",
        ):
            linkage.validate_dynamic_tags([
                ("DT_NEEDED", "libc.so.6"),
            ])

    def test_no_direct_dependencies(self):
        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Expected dynamically linked executable",
        ):
            linkage.validate_dynamic_tags([
                ("DT_NULL", None),
            ])

    def test_dependency_count_boundary(self):
        with patch.object(
            linkage,
            "MAX_DIRECT_DEPENDENCIES",
            2,
        ):
            self.assertEqual(
                len(
                    linkage.validate_dynamic_tags(
                        dynamic_tags(
                            ("DT_NEEDED", "libm.so.6")
                        )
                    )
                ),
                2,
            )

            with self.assertRaisesRegex(
                linkage.LinkageError,
                "Direct dependency count",
            ):
                linkage.validate_dynamic_tags(
                    dynamic_tags(
                        ("DT_NEEDED", "libm.so.6"),
                        ("DT_NEEDED", "libgcc_s.so.1"),
                    )
                )

    def test_dynamic_tag_count_boundary(self):
        with patch.object(
            linkage,
            "MAX_DYNAMIC_TAGS",
            2,
        ):
            self.assertEqual(
                linkage.validate_dynamic_tags(
                    dynamic_tags()
                ),
                ("libc.so.6",),
            )

            with self.assertRaisesRegex(
                linkage.LinkageError,
                "Dynamic tag count",
            ):
                linkage.validate_dynamic_tags(
                    dynamic_tags(("DT_FLAGS", 8))
                )


class DependencyTreeTests(unittest.TestCase):

    def test_complete_tree(self):
        result = parse_tree(
            "    libmiddle.so => /usr/lib/libmiddle.so\n"
            "        libleaf.so => /usr/lib/libleaf.so\n"
            "    libc.so.6 => /usr/lib/libc.so.6\n",
            needed=("libmiddle.so", "libc.so.6"),
        )

        self.assertEqual(
            result["interpreter_path"],
            "/usr/lib/ld-linux-x86-64.so.2",
        )

        self.assertEqual(
            set(result["libraries"]),
            {
                "libmiddle.so",
                "libleaf.so",
                "libc.so.6",
            },
        )

    def test_deduplicated_direct_dependency(self):
        result = parse_tree(
            "    libmiddle.so => /usr/lib/libmiddle.so\n"
            "        libc.so.6 => /usr/lib/libc.so.6\n",
            needed=("libmiddle.so", "libc.so.6"),
        )

        self.assertIn(
            "libc.so.6",
            result["libraries"],
        )

    def test_missing_direct_dependency(self):
        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Unresolved runtime dependency",
        ):
            parse_tree(
                "    libc.so.6 => None\n"
            )

    def test_missing_transitive_dependency(self):
        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Unresolved runtime dependency",
        ):
            parse_tree(
                "    libc.so.6 => /usr/lib/libc.so.6\n"
                "        libleaf.so => None\n"
            )

    def test_missing_direct_record(self):
        with self.assertRaisesRegex(
            linkage.LinkageError,
            "omitted required direct dependencies",
        ):
            parse_tree(
                "    libm.so.6 => /usr/lib/libm.so.6\n"
            )

    def test_wrong_header(self):
        for header in (
            "",
            "/wrong/path",
            f"{EXECUTABLE} (interpreter => None)",
            f"{EXECUTABLE} (interpreter => /tmp/loader)",
        ):
            with self.subTest(header=header):
                with self.assertRaisesRegex(
                    linkage.LinkageError,
                    "Unexpected dependency tree header",
                ):
                    linkage.parse_dependency_tree(
                        header + "\n",
                        executable=EXECUTABLE,
                        needed=("libc.so.6",),
                        runtime_path_validator=runtime_path,
                    )

    def test_unexpected_record(self):
        for record in (
            "unexpected diagnostic\n",
            "\n",
            "    libc.so.6 -> /usr/lib/libc.so.6\n",
            "    libc.so.6 => relative/path\n",
            "    libc.so.6 => /usr/lib/libc.so.6 extra\n",
        ):
            with self.subTest(record=record):
                with self.assertRaises(
                    linkage.LinkageError
                ):
                    parse_tree(record)

    def test_invalid_indentation(self):
        for indent in (" ", "  ", "     ", "\t"):
            with self.subTest(indent=indent):
                with self.assertRaises(
                    linkage.LinkageError
                ):
                    parse_tree(
                        indent
                        + "libc.so.6 => /usr/lib/libc.so.6\n"
                    )

    def test_invalid_initial_depth(self):
        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Invalid dependency tree depth",
        ):
            parse_tree(
                "        libc.so.6 => /usr/lib/libc.so.6\n"
            )

    def test_duplicate_tree_record(self):
        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Duplicate dependency tree record",
        ):
            parse_tree(
                "    libc.so.6 => /usr/lib/libc.so.6\n"
                "    libc.so.6 => /usr/lib/libc.so.6\n"
            )

    def test_untrusted_runtime_path(self):
        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Untrusted runtime library",
        ):
            parse_tree(
                "    libc.so.6 => /tmp/libc.so.6\n"
            )

    def test_runtime_path_traversal(self):
        with self.assertRaises(
            linkage.LinkageError
        ):
            parse_tree(
                "    libc.so.6 => /usr/lib/../bin/bash\n"
            )

    def test_resolved_library_count_boundary(self):
        with patch.object(
            linkage,
            "MAX_RESOLVED_LIBRARIES",
            1,
        ):
            result = parse_tree(
                "    libc.so.6 => /usr/lib/libc.so.6\n"
            )

            self.assertEqual(
                len(result["libraries"]), 1
            )

            with self.assertRaisesRegex(
                linkage.LinkageError,
                "Resolved dependency count",
            ):
                parse_tree(
                    "    libc.so.6 => /usr/lib/libc.so.6\n"
                    "    libm.so.6 => /usr/lib/libm.so.6\n"
                )

    def test_tree_depth_boundary(self):
        with patch.object(
            linkage,
            "MAX_TREE_DEPTH",
            1,
        ):
            parse_tree(
                "    libc.so.6 => /usr/lib/libc.so.6\n"
            )

            with self.assertRaisesRegex(
                linkage.LinkageError,
                "Invalid dependency tree depth",
            ):
                parse_tree(
                    "    libc.so.6 => /usr/lib/libc.so.6\n"
                    "        libm.so.6 => /usr/lib/libm.so.6\n"
                )


class ResolverBoundaryTests(unittest.TestCase):

    def fake_resolver(
        self,
        *,
        output=b"",
        diagnostics=b"",
        returncode=0,
    ):
        def invoke(arguments, **kwargs):
            self.assertEqual(
                arguments,
                [
                    linkage.PYTHON,
                    "-I",
                    "-B",
                    linkage.RESOLVER,
                    "--",
                    EXECUTABLE,
                ],
            )

            self.assertEqual(kwargs["cwd"], "/")

            self.assertEqual(
                kwargs["env"],
                linkage.ENVIRONMENT,
            )

            self.assertEqual(
                kwargs["timeout"],
                linkage.RESOLVER_TIMEOUT,
            )

            self.assertIs(
                kwargs["preexec_fn"],
                linkage.resolver_limits,
            )

            kwargs["stdout"].write(output)
            kwargs["stderr"].write(diagnostics)

            return subprocess.CompletedProcess(
                arguments,
                returncode,
            )

        return invoke

    def test_successful_resolver_invocation(self):
        output = (
            HEADER
            + "    libc.so.6 => /usr/lib/libc.so.6\n"
        ).encode("ascii")

        expected = {
            "interpreter_path": linkage.INTERPRETER,
            "libraries": {
                "libc.so.6": "/usr/lib/libc.so.6"
            },
        }

        with (
            patch.object(
                linkage.subprocess,
                "run",
                side_effect=self.fake_resolver(
                    output=output
                ),
            ),
            patch.object(
                linkage,
                "parse_dependency_tree",
                return_value=expected,
            ) as parser,
        ):
            result = linkage.resolve_dependencies(
                EXECUTABLE,
                ("libc.so.6",),
            )

        self.assertEqual(result, expected)

        parser.assert_called_once_with(
            output.decode("ascii"),
            executable=EXECUTABLE,
            needed=("libc.so.6",),
        )

    def test_nonzero_exit_rejected(self):
        with patch.object(
            linkage.subprocess,
            "run",
            side_effect=self.fake_resolver(
                returncode=1
            ),
        ):
            with self.assertRaisesRegex(
                linkage.LinkageError,
                "Static resolver failed",
            ):
                linkage.resolve_dependencies(
                    EXECUTABLE, ("libc.so.6",)
                )

    def test_stderr_rejected_despite_zero_exit(self):
        with patch.object(
            linkage.subprocess,
            "run",
            side_effect=self.fake_resolver(
                diagnostics=b"unexpected warning\n"
            ),
        ):
            with self.assertRaisesRegex(
                linkage.LinkageError,
                "Unexpected static resolver diagnostics",
            ):
                linkage.resolve_dependencies(
                    EXECUTABLE, ("libc.so.6",)
                )

    def test_timeout_rejected(self):
        with patch.object(
            linkage.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(
                cmd=linkage.RESOLVER,
                timeout=linkage.RESOLVER_TIMEOUT,
            ),
        ):
            with self.assertRaisesRegex(
                linkage.LinkageError,
                "Static dependency resolver timed out",
            ):
                linkage.resolve_dependencies(
                    EXECUTABLE, ("libc.so.6",)
                )

    def test_output_size_limit(self):
        with (
            patch.object(
                linkage,
                "MAX_RESOLVER_OUTPUT",
                32,
            ),
            patch.object(
                linkage.subprocess,
                "run",
                side_effect=self.fake_resolver(
                    output=b"a" * 32
                ),
            ),
        ):
            with self.assertRaisesRegex(
                linkage.LinkageError,
                "output exceeds policy",
            ):
                linkage.resolve_dependencies(
                    EXECUTABLE, ("libc.so.6",)
                )

    def test_hashing_size_limit(self):
        with patch.object(
            linkage,
            "MAX_ELF_BYTES",
            4,
        ):
            self.assertEqual(
                len(linkage.file_digest(io.BytesIO(b"abcd"))),
                64,
            )

            with self.assertRaisesRegex(
                linkage.LinkageError,
                "ELF size exceeds hashing limit",
            ):
                linkage.file_digest(
                    io.BytesIO(b"abcde")
                )

    def test_privilege_guard_precedes_file_open(self):
        def reject():
            raise privileges.PrivilegeError(
                "Rejected process"
            )

        with patch.object(
            linkage.os,
            "open",
        ) as opener:
            with self.assertRaises(
                privileges.PrivilegeError
            ):
                linkage.inspect_executable(
                    EXECUTABLE,
                    privilege_guard=reject,
                )

            opener.assert_not_called()


class ELFStructureTests(unittest.TestCase):

    def fixture(self):
        data = bytearray(4096)

        ident = (
            b"\x7fELF\x02\x01\x01"
            + b"\0" * 9
        )

        linkage.ELF64_HEADER.pack_into(
            data, 0,
            ident, 3, 62, 1,
            0, 64, 2048, 0,
            64, 56, 3, 64, 4, 3,
        )

        interpreter = (
            linkage.INTERPRETER.encode("ascii")
            + b"\0"
        )

        # One file-backed load segment.
        linkage.ELF64_PROGRAM.pack_into(
            data, 64,
            1, 5, 0, 0, 0,
            len(data), len(data), 4096,
        )

        linkage.ELF64_PROGRAM.pack_into(
            data, 120,
            3, 4, 256, 256, 256,
            len(interpreter), len(interpreter), 1,
        )

        linkage.ELF64_PROGRAM.pack_into(
            data, 176,
            2, 6, 512, 512, 512,
            80, 80, 8,
        )

        data[256:256 + len(interpreter)] = interpreter

        strings = b"\0libc.so.6\0"

        data[1024:1024 + len(strings)] = strings

        for index, record in enumerate((
            (1, 1),
            (5, 1024),
            (10, len(strings)),
            (0, 0),
            (0, 0),
        )):
            linkage.ELF64_DYNAMIC.pack_into(
                data, 512 + index * 16,
                *record,
            )

        # Section zero remains all zero.
        linkage.ELF64_SECTION.pack_into(
            data, 2048 + 64,
            0, 6, 3, 512, 512, 80,
            2, 0, 8, 16,
        )

        linkage.ELF64_SECTION.pack_into(
            data, 2048 + 128,
            0, 3, 2, 1024, 1024,
            len(strings), 0, 0, 1, 0,
        )

        linkage.ELF64_SECTION.pack_into(
            data, 2048 + 192,
            0, 3, 0, 0, 1536,
            1, 0, 0, 1, 0,
        )

        return data

    def inspect(self, data):
        return linkage.inspect_elf_structure(
            io.BytesIO(data),
            len(data),
        )

    def test_valid_structure(self):
        result = self.inspect(self.fixture())

        self.assertEqual(
            result["needed"],
            ("libc.so.6",),
        )
        self.assertEqual(result["program_headers"], 3)
        self.assertEqual(result["section_headers"], 4)
        self.assertEqual(result["dynamic_bytes"], 80)

    def test_truncated_header(self):
        with self.assertRaises(linkage.LinkageError):
            self.inspect(self.fixture()[:32])

    def test_wrong_architecture(self):
        data = self.fixture()
        struct.pack_into("<H", data, 18, 183)

        with self.assertRaises(linkage.LinkageError):
            self.inspect(data)

    def test_program_header_count_limit(self):
        data = self.fixture()
        struct.pack_into("<H", data, 56, 129)

        with self.assertRaises(linkage.LinkageError):
            self.inspect(data)

    def test_section_header_count_limit(self):
        data = self.fixture()
        struct.pack_into("<H", data, 60, 257)

        with self.assertRaises(linkage.LinkageError):
            self.inspect(data)

    def test_program_header_table_extent(self):
        data = self.fixture()
        struct.pack_into("<Q", data, 32, 4090)

        with self.assertRaises(linkage.LinkageError):
            self.inspect(data)

    def test_section_header_table_extent(self):
        data = self.fixture()
        struct.pack_into("<Q", data, 40, 4090)

        with self.assertRaises(linkage.LinkageError):
            self.inspect(data)

    def test_wrong_interpreter(self):
        data = self.fixture()
        data[257] = ord("X")

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Unexpected physical ELF interpreter",
        ):
            self.inspect(data)

    def test_missing_dynamic_termination(self):
        data = self.fixture()

        for offset in (560, 576):
            linkage.ELF64_DYNAMIC.pack_into(
                data, offset, 21, 0
            )

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Dynamic termination outside segment",
        ):
            self.inspect(data)

    def test_nonzero_dynamic_padding(self):
        data = self.fixture()

        linkage.ELF64_DYNAMIC.pack_into(
            data, 576, 0, 1
        )

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Nonzero data after dynamic termination",
        ):
            self.inspect(data)

    def test_duplicate_singleton_tag(self):
        data = self.fixture()

        linkage.ELF64_DYNAMIC.pack_into(
            data, 560, 5, 1024
        )

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Duplicate singleton dynamic tag",
        ):
            self.inspect(data)

    def test_string_table_limit(self):
        data = self.fixture()

        linkage.ELF64_DYNAMIC.pack_into(
            data, 544,
            10, linkage.MAX_DYNAMIC_STRING_BYTES + 1,
        )

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Dynamic string table outside policy",
        ):
            self.inspect(data)

    def test_missing_string_mapping(self):
        data = self.fixture()

        linkage.ELF64_DYNAMIC.pack_into(
            data, 528, 5, 8192
        )

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Ambiguous or absent file-backed mapping",
        ):
            self.inspect(data)

    def test_dynamic_section_disagreement(self):
        data = self.fixture()

        struct.pack_into(
            "<Q", data,
            2048 + 64 + 24,
            513,
        )

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Dynamic section and segment disagree",
        ):
            self.inspect(data)

    def test_string_section_disagreement(self):
        data = self.fixture()

        struct.pack_into(
            "<Q", data,
            2048 + 128 + 24,
            1025,
        )

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Dynamic string table section mismatch",
        ):
            self.inspect(data)

    def test_dependency_offset_outside_table(self):
        data = self.fixture()

        linkage.ELF64_DYNAMIC.pack_into(
            data, 512, 1, 999
        )

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Dependency string offset outside table",
        ):
            self.inspect(data)

    def test_non_ascii_dependency(self):
        data = self.fixture()
        data[1025] = 255

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Non-ASCII dependency string",
        ):
            self.inspect(data)

    def test_forbidden_numeric_dynamic_tags(self):
        for tag in (
            14, 15, 22, 29,
            0x6ffffefb,
            0x6ffffefc,
            0x7ffffffd,
            0x7fffffff,
        ):
            with self.subTest(tag=tag):
                data = self.fixture()

                linkage.ELF64_DYNAMIC.pack_into(
                    data, 560, tag, 1
                )

                with self.assertRaisesRegex(
                    linkage.LinkageError,
                    "Unsupported candidate dynamic tag",
                ):
                    self.inspect(data)


class ExpectedExecutableIdentityTests(unittest.TestCase):

    def test_valid_expected_identity_boundaries(self):
        for size in (1, linkage.MAX_ELF_BYTES):
            linkage.validate_expected_executable(
                size,
                "a" * 64,
            )

    def test_invalid_expected_sizes(self):
        for size in (
            None, True, False, 0, -1, "1", 1.5,
            linkage.MAX_ELF_BYTES + 1,
        ):
            with self.subTest(size=size):
                with self.assertRaisesRegex(
                    linkage.LinkageError,
                    "size outside policy",
                ):
                    linkage.validate_expected_executable(
                        size, "a" * 64
                    )

    def test_invalid_expected_digests(self):
        for digest in (
            None, 1, "", "A" * 64, "g" * 64,
            "a" * 63, "a" * 65,
        ):
            with self.subTest(digest=digest):
                with self.assertRaisesRegex(
                    linkage.LinkageError,
                    "Invalid expected executable digest",
                ):
                    linkage.validate_expected_executable(
                        1, digest
                    )


class BoundExecutableInspectionTests(unittest.TestCase):

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(
            prefix="bound-linkage-"
        )

        self.addCleanup(scratch.cleanup)

        self.path = Path(scratch.name) / "analysis-input"

        self.payload = b"synthetic executable bytes"

        self.path.write_bytes(self.payload)
        self.path.chmod(0o644)

        self.digest = hashlib.sha256(
            self.payload
        ).hexdigest()

        self.real_fstat = os.fstat
        self.real_lstat = Path.lstat

        self.metadata = {
            "needed": ("libc.so.6",),
        }

        self.resolved = {
            "interpreter_path":
                "/usr/lib/ld-linux-x86-64.so.2",
            "libraries": {
                "libc.so.6": "/usr/lib/libc.so.6",
            },
        }

        self.guard_calls = 0

        self.enterContext(
            patch.object(
                linkage.os,
                "fstat",
                side_effect=self.fixture_fstat,
            )
        )

        fixture_lstat = self.fixture_lstat

        self.enterContext(
            patch.object(
                Path,
                "lstat",
                new=lambda path: fixture_lstat(path),
            )
        )

        self.parser = self.enterContext(
            patch.object(
                linkage,
                "inspect_elf_metadata",
                side_effect=self.parse_fixture,
            )
        )

        self.resolver = self.enterContext(
            patch.object(
                linkage,
                "resolve_dependencies",
                return_value=self.resolved,
            )
        )

    def fixture_metadata(self, info):
        # Normalize ownership only. File size, mode, inode,
        # link count and timestamps remain genuine.
        return SimpleNamespace(
            st_uid=0,
            **{
                field: getattr(info, field)
                for field in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_gid",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            },
        )

    def fixture_fstat(self, descriptor):
        return self.fixture_metadata(
            self.real_fstat(descriptor)
        )

    def fixture_lstat(self, path):
        return self.fixture_metadata(
            self.real_lstat(path)
        )

    def guard(self):
        self.guard_calls += 1

    def parse_fixture(self, stream):
        self.assertEqual(
            stream.read(), self.payload
        )

        return self.metadata

    def inspect(self, **overrides):
        arguments = {
            "privilege_guard": self.guard,
            "expected_size": len(self.payload),
            "expected_sha256": self.digest,
        }

        arguments.update(overrides)

        return linkage.inspect_executable(
            self.path,
            **arguments,
        )

    def assert_rejected_before_parsing(
        self,
        message,
        **overrides,
    ):
        with self.assertRaisesRegex(
            linkage.LinkageError,
            message,
        ):
            self.inspect(**overrides)

        self.parser.assert_not_called()
        self.resolver.assert_not_called()

    def test_exact_expected_bytes_accepted(self):
        result = self.inspect()

        self.assertEqual(
            result,
            {
                "schema": 1,
                "static_linkage_validation": True,
                "sha256": self.digest,
                **self.metadata,
                **self.resolved,
            },
        )

        self.assertEqual(self.guard_calls, 1)

        self.parser.assert_called_once()

        self.resolver.assert_called_once_with(
            self.path,
            self.metadata["needed"],
        )

    def test_wrong_size_rejected_before_parsing(self):
        self.assert_rejected_before_parsing(
            "Materialized executable size or mode mismatch",
            expected_size=len(self.payload) + 1,
        )

    def test_wrong_digest_rejected_before_parsing(self):
        self.assert_rejected_before_parsing(
            "Materialized executable digest mismatch",
            expected_sha256="0" * 64,
        )

    def test_executable_mode_rejected_before_parsing(self):
        self.path.chmod(0o755)

        self.assert_rejected_before_parsing(
            "Materialized executable size or mode mismatch",
        )

    def test_incomplete_expected_identity_rejected(self):
        for overrides, message in (
            (
                {"expected_size": None},
                "size outside policy",
            ),
            (
                {"expected_sha256": None},
                "Invalid expected executable digest",
            ),
        ):
            with self.subTest(overrides=overrides):
                self.assert_rejected_before_parsing(
                    message,
                    **overrides,
                )

    def test_invalid_identity_rejected_before_open(self):
        with patch.object(
            linkage.os, "open"
        ) as opener:
            self.assert_rejected_before_parsing(
                "size outside policy",
                expected_size=0,
            )

        opener.assert_not_called()

    def test_guard_rejected_before_open(self):
        def reject():
            raise privileges.PrivilegeError(
                "Synthetic privilege rejection"
            )

        with patch.object(
            linkage.os, "open"
        ) as opener:
            with self.assertRaisesRegex(
                privileges.PrivilegeError,
                "Synthetic privilege rejection",
            ):
                self.inspect(
                    privilege_guard=reject,
                )

        opener.assert_not_called()
        self.parser.assert_not_called()
        self.resolver.assert_not_called()

    def test_mutation_during_hashing_prevents_parsing(self):
        original_hash = linkage.file_digest

        def hash_then_mutate(stream):
            result = original_hash(stream)

            self.path.write_bytes(
                b"x" * len(self.payload)
            )

            return result

        with patch.object(
            linkage,
            "file_digest",
            side_effect=hash_then_mutate,
        ):
            self.assert_rejected_before_parsing(
                "Candidate changed before ELF inspection"
            )

    def test_mutation_during_parsing_prevents_resolution(self):
        def parse_then_mutate(stream):
            result = self.parse_fixture(stream)

            self.path.write_bytes(
                b"x" * len(self.payload)
            )

            return result

        self.parser.side_effect = parse_then_mutate

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Candidate changed during ELF inspection",
        ):
            self.inspect()

        self.parser.assert_called_once()
        self.resolver.assert_not_called()

    def test_mutation_during_resolution_rejected(self):
        def resolve_then_mutate(*args, **kwargs):
            self.path.write_bytes(
                b"x" * len(self.payload)
            )

            return self.resolved

        self.resolver.side_effect = resolve_then_mutate

        with self.assertRaisesRegex(
            linkage.LinkageError,
            "Candidate changed during linkage inspection",
        ):
            self.inspect()

    def test_hardlinked_input_rejected_before_parsing(self):
        os.link(
            self.path,
            self.path.with_name("additional-link"),
        )

        self.assert_rejected_before_parsing(
            "Candidate ELF file outside storage policy"
        )

    def test_unbound_interface_remains_compatible(self):
        self.path.chmod(0o755)

        result = self.inspect(
            expected_size=None,
            expected_sha256=None,
        )

        self.assertEqual(
            result["sha256"], self.digest
        )

        self.parser.assert_called_once()
        self.resolver.assert_called_once()


class RestrictedLinkageEntryPointTests(unittest.TestCase):

    def setUp(self):
        self.path = "/protected/analysis-input"
        self.size = 4096
        self.digest = "a" * 64

        self.expected = {
            "schema": 1,
            "static_linkage_validation": True,
            "sha256": self.digest,
        }

    def inspect(self, **overrides):
        arguments = {
            "expected_size": self.size,
            "expected_sha256": self.digest,
        }

        arguments.update(overrides)

        return linkage.inspect_verified_executable(
            self.path, **arguments
        )

    def test_root_identity_rejected_before_guard_load(self):
        for uids, gids in (
            ((0, 0, 0), (65534,) * 3),
            ((65534,) * 3, (0, 0, 0)),
            ((65534, 65534, 0), (65534,) * 3),
        ):
            with self.subTest(uids=uids, gids=gids):
                with (
                    patch.object(
                        linkage.os,
                        "getresuid",
                        return_value=uids,
                    ),
                    patch.object(
                        linkage.os,
                        "getresgid",
                        return_value=gids,
                    ),
                    patch.object(
                        linkage,
                        "load_linkage_privilege_guard",
                    ) as loader,
                ):
                    with self.assertRaisesRegex(
                        linkage.LinkageError,
                        "refuses root identity",
                    ):
                        self.inspect()

                    loader.assert_not_called()

    def test_exact_identity_forwarded_to_inspector(self):
        def guard():
            pass

        with (
            patch.object(
                linkage.os,
                "getresuid",
                return_value=(65534,) * 3,
            ),
            patch.object(
                linkage.os,
                "getresgid",
                return_value=(65534,) * 3,
            ),
            patch.object(
                linkage,
                "load_linkage_privilege_guard",
                return_value={
                    "require_inspection_identity": guard,
                    "PrivilegeError":
                        privileges.PrivilegeError,
                },
            ),
            patch.object(
                linkage,
                "inspect_executable",
                return_value=self.expected,
            ) as inspector,
        ):
            self.assertEqual(
                self.inspect(), self.expected
            )

        inspector.assert_called_once_with(
            self.path,
            privilege_guard=guard,
            expected_size=self.size,
            expected_sha256=self.digest,
        )

    def test_privilege_error_translated(self):
        with (
            patch.object(
                linkage.os,
                "getresuid",
                return_value=(65534,) * 3,
            ),
            patch.object(
                linkage.os,
                "getresgid",
                return_value=(65534,) * 3,
            ),
            patch.object(
                linkage,
                "load_linkage_privilege_guard",
                return_value={
                    "require_inspection_identity":
                        lambda: None,
                    "PrivilegeError":
                        privileges.PrivilegeError,
                },
            ),
            patch.object(
                linkage,
                "inspect_executable",
                side_effect=privileges.PrivilegeError(
                    "Synthetic privilege failure"
                ),
            ),
        ):
            with self.assertRaisesRegex(
                linkage.LinkageError,
                "Synthetic privilege failure",
            ):
                self.inspect()

    def arguments(self):
        return [
            "--path=" + self.path,
            "--expected-size=" + str(self.size),
            "--expected-sha256=" + self.digest,
        ]

    def test_cli_emits_exact_json_receipt(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch.object(
                linkage,
                "inspect_verified_executable",
                return_value=self.expected,
            ) as inspector,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = linkage.main(self.arguments())

        self.assertEqual(status, 0)
        self.assertEqual(stderr.getvalue(), "")

        self.assertEqual(
            json.loads(stdout.getvalue()),
            self.expected,
        )

        self.assertEqual(
            stdout.getvalue().count("\n"), 1
        )

        inspector.assert_called_once_with(
            self.path,
            expected_size=self.size,
            expected_sha256=self.digest,
        )

    def test_cli_failure_emits_no_receipt(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch.object(
                linkage,
                "inspect_verified_executable",
                side_effect=linkage.LinkageError(
                    "Synthetic inspection failure"
                ),
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = linkage.main(self.arguments())

        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")

        self.assertIn(
            "Synthetic inspection failure",
            stderr.getvalue(),
        )

    def test_cli_requires_all_identity_arguments(self):
        arguments = self.arguments()

        for omitted in range(len(arguments)):
            partial = [
                value
                for index, value in enumerate(arguments)
                if index != omitted
            ]

            with self.subTest(omitted=omitted):
                with (
                    patch.object(
                        linkage,
                        "inspect_verified_executable",
                    ) as inspector,
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(
                        SystemExit
                    ) as error:
                        linkage.main(partial)

                    self.assertEqual(
                        error.exception.code, 2
                    )

                    inspector.assert_not_called()


class LinkageReceiptSchemaTests(unittest.TestCase):

    SIZE = 4096
    DIGEST = "a" * 64

    def fixture(self):
        return {
            "schema": 1,
            "static_linkage_validation": True,
            "sha256": self.DIGEST,
            "architecture": "x86_64",
            "interpreter": linkage.INTERPRETER,
            "needed": ["libc.so.6"],
            "program_headers": 3,
            "section_headers": 4,
            "dynamic_bytes": 80,
            "dynamic_string_bytes": 11,
            "interpreter_path":
                "/usr/lib/ld-linux-x86-64.so.2",
            "libraries": {
                "libc.so.6": "/usr/lib/libc.so.6",
            },
        }

    def validate(self, receipt, **overrides):
        arguments = {
            "expected_size": self.SIZE,
            "expected_sha256": self.DIGEST,
        }

        arguments.update(overrides)

        return linkage.validate_linkage_receipt(
            receipt,
            **arguments,
        )

    def assert_rejected(self, receipt, **overrides):
        with self.assertRaises(
            linkage.LinkageError
        ):
            self.validate(
                receipt,
                **overrides,
            )

    def test_exact_receipt_accepted(self):
        receipt = self.fixture()

        result = self.validate(receipt)

        self.assertEqual(result, receipt)

        self.assertEqual(
            len(linkage.LINKAGE_RECEIPT_FIELDS),
            12,
        )

        self.assertIsNot(result, receipt)

        self.assertIsNot(
            result["needed"],
            receipt["needed"],
        )

        self.assertIsNot(
            result["libraries"],
            receipt["libraries"],
        )

    def test_every_missing_field_rejected(self):
        for name in self.fixture():
            with self.subTest(name=name):
                receipt = self.fixture()

                del receipt[name]

                self.assert_rejected(receipt)

    def test_unexpected_fields_rejected(self):
        receipt = self.fixture()

        receipt["unexpected"] = True

        self.assert_rejected(receipt)

    def test_nonobject_receipts_rejected(self):
        for value in (
            None, [], "receipt", True, 1,
        ):
            with self.subTest(value=value):
                self.assert_rejected(value)

    def test_invalid_schema_versions_rejected(self):
        for value in (
            True, False, None, 0, 2, "1", 1.0,
        ):
            with self.subTest(value=value):
                receipt = self.fixture()
                receipt["schema"] = value

                self.assert_rejected(receipt)

    def test_validation_marker_requires_true(self):
        for value in (
            False, None, 0, 1, "true", [],
        ):
            with self.subTest(value=value):
                receipt = self.fixture()

                receipt[
                    "static_linkage_validation"
                ] = value

                self.assert_rejected(receipt)

    def test_wrong_member_digest_rejected(self):
        for value in (
            "0" * 64,
            "A" * 64,
            None,
            1,
            "a" * 63,
        ):
            with self.subTest(value=value):
                receipt = self.fixture()
                receipt["sha256"] = value

                self.assert_rejected(receipt)

    def test_invalid_expected_identity_rejected(self):
        for overrides in (
            {"expected_size": 0},
            {"expected_size": True},
            {"expected_size": None},
            {"expected_sha256": "invalid"},
            {"expected_sha256": None},
        ):
            with self.subTest(overrides=overrides):
                self.assert_rejected(
                    self.fixture(),
                    **overrides,
                )

    def test_architecture_and_interpreter_rejected(self):
        for name, value in (
            ("architecture", "aarch64"),
            ("architecture", None),
            ("interpreter", "/usr/bin/ld"),
            ("interpreter", None),
        ):
            with self.subTest(name=name):
                receipt = self.fixture()
                receipt[name] = value

                self.assert_rejected(receipt)

    def test_numeric_metadata_types_rejected(self):
        for name in (
            "program_headers",
            "section_headers",
            "dynamic_bytes",
            "dynamic_string_bytes",
        ):
            for value in (
                True, False, None, 0, -1, "1", 1.0,
            ):
                with self.subTest(
                    name=name, value=value
                ):
                    receipt = self.fixture()
                    receipt[name] = value

                    self.assert_rejected(receipt)

    def test_numeric_metadata_limits_enforced(self):
        for name, value in (
            (
                "program_headers",
                linkage.MAX_PROGRAM_HEADERS + 1,
            ),
            (
                "section_headers",
                linkage.MAX_SECTION_HEADERS + 1,
            ),
            (
                "dynamic_bytes",
                linkage.MAX_DYNAMIC_BYTES + 16,
            ),
            (
                "dynamic_string_bytes",
                linkage.MAX_DYNAMIC_STRING_BYTES + 1,
            ),
        ):
            with self.subTest(name=name):
                receipt = self.fixture()
                receipt[name] = value

                self.assert_rejected(receipt)

    def test_unaligned_dynamic_segment_rejected(self):
        receipt = self.fixture()
        receipt["dynamic_bytes"] = 81

        self.assert_rejected(receipt)

    def test_metadata_extents_bound_to_member_size(self):
        for name, value in (
            ("program_headers", 128),
            ("section_headers", 256),
            ("dynamic_bytes", 4112),
            ("dynamic_string_bytes", 4097),
        ):
            with self.subTest(name=name):
                receipt = self.fixture()
                receipt[name] = value

                self.assert_rejected(receipt)

    def test_invalid_direct_dependency_collections(self):
        for value in (
            None,
            [],
            "libc.so.6",
            ("libc.so.6",),
            {},
            ["libc.so.6"] *
                (linkage.MAX_DIRECT_DEPENDENCIES + 1),
        ):
            with self.subTest(value=value):
                receipt = self.fixture()
                receipt["needed"] = value

                self.assert_rejected(receipt)

    def test_duplicate_direct_dependencies_rejected(self):
        receipt = self.fixture()

        receipt["needed"] = [
            "libc.so.6",
            "libc.so.6",
        ]

        self.assert_rejected(receipt)

    def test_invalid_dependency_names_rejected(self):
        for name in (
            "",
            ".",
            "..",
            "/usr/lib/libc.so.6",
            "../libc.so.6",
            "lib c.so",
            "x" * 256,
            None,
            True,
        ):
            with self.subTest(name=name):
                receipt = self.fixture()
                receipt["needed"] = [name]

                self.assert_rejected(receipt)

                receipt = self.fixture()
                receipt["libraries"][name] = (
                    "/usr/lib/libc.so.6"
                )

                self.assert_rejected(receipt)

    def test_invalid_runtime_paths_rejected(self):
        for value in (
            "/tmp/libc.so.6",
            "/usr/lib64/libc.so.6",
            "/usr/lib/../bin/fixture",
            "/usr/lib//libc.so.6",
            "/usr/lib/./libc.so.6",
            "/usr/lib",
            "libc.so.6",
            "/usr/lib/lib c.so",
            "/usr/lib/libc.so\n",
            None,
        ):
            with self.subTest(value=value):
                receipt = self.fixture()

                receipt["interpreter_path"] = value

                self.assert_rejected(receipt)

                receipt = self.fixture()

                receipt["libraries"]["libc.so.6"] = (
                    value
                )

                self.assert_rejected(receipt)

    def test_invalid_resolved_library_collections(self):
        for value in (
            None,
            {},
            [],
            ["/usr/lib/libc.so.6"],
            "libc.so.6",
        ):
            with self.subTest(value=value):
                receipt = self.fixture()
                receipt["libraries"] = value

                self.assert_rejected(receipt)

    def test_resolved_library_count_boundary(self):
        receipt = self.fixture()

        for index in range(
            linkage.MAX_RESOLVED_LIBRARIES - 1
        ):
            name = f"libfixture{index}.so"

            receipt["libraries"][name] = (
                "/usr/lib/" + name
            )

        result = self.validate(receipt)

        self.assertEqual(
            len(result["libraries"]),
            linkage.MAX_RESOLVED_LIBRARIES,
        )

        receipt["libraries"]["libextra.so"] = (
            "/usr/lib/libextra.so"
        )

        self.assert_rejected(receipt)

    def test_missing_direct_dependency_rejected(self):
        receipt = self.fixture()

        receipt["libraries"] = {
            "libother.so": "/usr/lib/libother.so"
        }

        self.assert_rejected(receipt)

    def test_transitive_dependencies_retained(self):
        receipt = self.fixture()

        receipt["libraries"]["libother.so"] = (
            "/usr/lib/libother.so"
        )

        result = self.validate(receipt)

        self.assertEqual(
            result["libraries"],
            receipt["libraries"],
        )

        self.assertEqual(
            result["needed"],
            ["libc.so.6"],
        )

    def test_receipt_validation_does_not_parse_elf(self):
        with (
            patch.object(
                linkage,
                "inspect_elf_metadata",
            ) as parser,
            patch.object(
                linkage,
                "resolve_dependencies",
            ) as resolver,
            patch.object(
                linkage.os,
                "open",
            ) as opener,
        ):
            self.validate(self.fixture())

        parser.assert_not_called()
        resolver.assert_not_called()
        opener.assert_not_called()


class FamilyLinkagePlanTests(unittest.TestCase):

    VERSION = "1.0-1"
    ARCHITECTURE = "x86_64"
    DIGEST = "a" * 64
    MEMBER_DIGEST = "b" * 64

    def fixture(self, *names):
        expected_names = {}
        checksums = {}
        packages = {}

        for name in names:
            filename = (
                f"{name}-{self.VERSION}-"
                f"{self.ARCHITECTURE}.pkg.tar.zst"
            )

            expected_names[filename] = name
            checksums[filename] = self.DIGEST

            package = {
                "identity": {
                    "pkgname": name,
                    "pkgver": self.VERSION,
                    "arch": self.ARCHITECTURE,
                    "filename": filename,
                    "sha256": self.DIGEST,
                },
                "entries": {},
            }

            members = linkage.REQUIRED_EXECUTABLES.get(
                name, ()
            )

            if members:
                package["selected_members"] = {}

                for member in members:
                    package["entries"][member] = {
                        "type": "file",
                        "size": 4096,
                    }

                    package["selected_members"][member] = {
                        "size": 4096,
                        "sha256": self.MEMBER_DIGEST,
                    }

            packages[name] = package

        receipt = {
            "schema": 1,
            "structural_and_identity_validation": True,
            "family": "fixture-family",
            "version": self.VERSION,
            "architecture": self.ARCHITECTURE,
            "packages": packages,
        }

        arguments = {
            "expected_names": expected_names,
            "expected_checksums": checksums,
            "family": "fixture-family",
            "version": self.VERSION,
            "architecture": self.ARCHITECTURE,
        }

        return receipt, arguments

    def bind(self, receipt, arguments):
        return linkage.bind_family_linkage_members(
            receipt,
            **arguments,
        )

    def reject(self, receipt, arguments):
        with self.assertRaises(
            linkage.LinkageError
        ):
            self.bind(receipt, arguments)

    def noctalia(self):
        return self.fixture(
            "noctalia-custom",
            "noctalia-custom-debug",
        )

    def test_exact_noctalia_member_requests(self):
        receipt, arguments = self.noctalia()

        result = linkage.build_family_linkage_requests(
            arguments["expected_names"]
        )

        filename = next(
            filename
            for filename, name
            in arguments["expected_names"].items()
            if name == "noctalia-custom"
        )

        self.assertEqual(
            result,
            {
                filename: (
                    "usr/bin/noctalia",
                    "usr/libexec/noctalia/noctalia-pam-helper",
                ),
            },
        )

    def test_exact_greeter_member_requests(self):
        receipt, arguments = self.fixture(
            "noctalia-greeter-t4t3z0r",
            "noctalia-greeter-t4t3z0r-debug",
        )

        result = linkage.build_family_linkage_requests(
            arguments["expected_names"]
        )

        self.assertEqual(len(result), 1)

        self.assertEqual(
            next(iter(result.values())),
            (
                "usr/bin/noctalia-greeter",
                "usr/bin/noctalia-greeter-apply-appearance",
                "usr/bin/noctalia-greeter-compositor",
            ),
        )

    def test_unrelated_packages_receive_no_requests(self):
        receipt, arguments = self.fixture(
            "broot", "broot-debug"
        )

        self.assertEqual(
            linkage.build_family_linkage_requests(
                arguments["expected_names"]
            ),
            {},
        )

        self.assertEqual(
            self.bind(receipt, arguments),
            [],
        )

    def test_invalid_expected_name_mappings(self):
        for value in (
            None,
            {},
            [],
            {"../archive.pkg.tar.zst": "broot"},
            {"archive.tar": "broot"},
            {"archive.pkg.tar.zst": None},
            {"archive.pkg.tar.zst": ""},
        ):
            with self.subTest(value=value):
                with self.assertRaises(
                    linkage.LinkageError
                ):
                    linkage.build_family_linkage_requests(
                        value
                    )

    def test_duplicate_package_identity_rejected(self):
        with self.assertRaises(
            linkage.LinkageError
        ):
            linkage.build_family_linkage_requests({
                "one.pkg.tar.zst": "broot",
                "two.pkg.tar.zst": "broot",
            })

    def test_exact_archive_member_evidence_binding(self):
        receipt, arguments = self.noctalia()

        result = self.bind(
            receipt, arguments
        )

        self.assertEqual(len(result), 2)

        for record in result:
            self.assertEqual(
                record,
                {
                    "name": "noctalia-custom",
                    "version": self.VERSION,
                    "architecture": self.ARCHITECTURE,
                    "filename":
                        "noctalia-custom-1.0-1-x86_64.pkg.tar.zst",
                    "archive_sha256": self.DIGEST,
                    "member": record["member"],
                    "size": 4096,
                    "sha256": self.MEMBER_DIGEST,
                },
            )

        self.assertEqual(
            [record["member"] for record in result],
            list(sorted(
                linkage.REQUIRED_EXECUTABLES[
                    "noctalia-custom"
                ]
            )),
        )

    def test_all_five_policy_members_bound(self):
        receipt, arguments = self.fixture(
            "noctalia-custom",
            "noctalia-greeter-t4t3z0r",
        )

        result = self.bind(
            receipt, arguments
        )

        self.assertEqual(len(result), 5)

    def test_incorrect_family_receipt_identity_rejected(self):
        for field, value in (
            ("schema", True),
            ("schema", 2),
            (
                "structural_and_identity_validation",
                False,
            ),
            ("family", "other-family"),
            ("version", "2.0-1"),
            ("architecture", "aarch64"),
        ):
            with self.subTest(field=field):
                receipt, arguments = self.noctalia()

                receipt[field] = value

                self.reject(receipt, arguments)

    def test_missing_or_extra_package_rejected(self):
        for extra in (False, True):
            with self.subTest(extra=extra):
                receipt, arguments = self.noctalia()

                if extra:
                    receipt["packages"]["extra"] = {}
                else:
                    del receipt["packages"][
                        "noctalia-custom-debug"
                    ]

                self.reject(receipt, arguments)

    def test_expected_checksum_inventory_mismatch(self):
        receipt, arguments = self.noctalia()

        arguments["expected_checksums"].pop(
            next(iter(
                arguments["expected_checksums"]
            ))
        )

        self.reject(receipt, arguments)

    def test_invalid_expected_archive_checksum(self):
        receipt, arguments = self.noctalia()

        filename = next(iter(
            arguments["expected_checksums"]
        ))

        arguments["expected_checksums"][filename] = (
            "invalid"
        )

        self.reject(receipt, arguments)

    def test_package_identity_mismatch_rejected(self):
        for field, value in (
            ("pkgname", "other"),
            ("pkgver", "2.0-1"),
            ("arch", "aarch64"),
            ("filename", "other.pkg.tar.zst"),
            ("sha256", "0" * 64),
        ):
            with self.subTest(field=field):
                receipt, arguments = self.noctalia()

                receipt["packages"][
                    "noctalia-custom"
                ]["identity"][field] = value

                self.reject(receipt, arguments)

    def test_missing_required_member_rejected(self):
        receipt, arguments = self.noctalia()

        del receipt["packages"][
            "noctalia-custom"
        ]["selected_members"]["usr/bin/noctalia"]

        self.reject(receipt, arguments)

    def test_extra_selected_member_rejected(self):
        receipt, arguments = self.noctalia()

        receipt["packages"][
            "noctalia-custom"
        ]["selected_members"]["usr/bin/extra"] = {
            "size": 4096,
            "sha256": self.MEMBER_DIGEST,
        }

        self.reject(receipt, arguments)

    def test_unrequested_debug_members_rejected(self):
        receipt, arguments = self.noctalia()

        receipt["packages"][
            "noctalia-custom-debug"
        ]["selected_members"] = {}

        self.reject(receipt, arguments)

    def test_unrequested_unrelated_members_rejected(self):
        receipt, arguments = self.fixture("broot")

        receipt["packages"][
            "broot"
        ]["selected_members"] = {}

        self.reject(receipt, arguments)

    def test_nonregular_required_member_rejected(self):
        for kind in (
            "symlink", "directory", "hardlink"
        ):
            with self.subTest(kind=kind):
                receipt, arguments = self.noctalia()

                receipt["packages"][
                    "noctalia-custom"
                ]["entries"]["usr/bin/noctalia"][
                    "type"
                ] = kind

                self.reject(receipt, arguments)

    def test_member_inventory_size_mismatch_rejected(self):
        receipt, arguments = self.noctalia()

        receipt["packages"][
            "noctalia-custom"
        ]["entries"]["usr/bin/noctalia"][
            "size"
        ] = 4097

        self.reject(receipt, arguments)

    def test_invalid_member_digest_rejected(self):
        receipt, arguments = self.noctalia()

        receipt["packages"][
            "noctalia-custom"
        ]["selected_members"]["usr/bin/noctalia"][
            "sha256"
        ] = "invalid"

        self.reject(receipt, arguments)

    def test_invalid_member_sizes_rejected(self):
        for size in (
            0,
            True,
            linkage.MAX_ELF_BYTES + 1,
        ):
            with self.subTest(size=size):
                receipt, arguments = self.noctalia()

                package = receipt["packages"][
                    "noctalia-custom"
                ]

                package["entries"][
                    "usr/bin/noctalia"
                ]["size"] = size

                package["selected_members"][
                    "usr/bin/noctalia"
                ]["size"] = size

                self.reject(receipt, arguments)

    def test_unsupported_linkage_architecture_rejected(self):
        receipt, arguments = self.noctalia()

        receipt["architecture"] = "aarch64"
        arguments["architecture"] = "aarch64"

        for package in receipt["packages"].values():
            package["identity"]["arch"] = "aarch64"

        self.reject(receipt, arguments)


if __name__ == "__main__":
    unittest.main()
