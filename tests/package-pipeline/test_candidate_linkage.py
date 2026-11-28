"""Portable candidate privilege and static linkage policy tests."""

import importlib.util
import io
import struct
import subprocess
import sys
import unittest

from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
