"""Static inspection of conventional x86-64 candidate executables."""

import hashlib
import os
import re
import resource
import stat
import struct
import subprocess
import tempfile

from pathlib import Path


INTERPRETER = "/lib64/ld-linux-x86-64.so.2"

MAX_ELF_BYTES = 128 * 1024**2
MAX_PROGRAM_HEADERS = 128
MAX_SECTION_HEADERS = 256
MAX_DYNAMIC_STRING_BYTES = 1024**2

ELF64_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_PROGRAM = struct.Struct("<IIQQQQQQ")
ELF64_SECTION = struct.Struct("<IIQQQQIIQQ")
ELF64_DYNAMIC = struct.Struct("<qQ")
MAX_DYNAMIC_BYTES = 64 * 1024
MAX_DYNAMIC_TAGS = 4096
MAX_DIRECT_DEPENDENCIES = 256
MAX_RESOLVER_OUTPUT = 1024**2
MAX_RESOLVED_LIBRARIES = 512
MAX_TREE_DEPTH = 32
RESOLVER_TIMEOUT = 30
RESOLVER_ADDRESS_SPACE = 512 * 1024**2

RESOLVER = "/usr/bin/lddtree"
PYTHON = "/usr/bin/python"

ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "HOME": "/tmp",
}

REQUIRED_EXECUTABLES = {
    "noctalia-custom": (
        "usr/bin/noctalia",
        "usr/libexec/noctalia/noctalia-pam-helper",
    ),
    "noctalia-greeter-t4t3z0r": (
        "usr/bin/noctalia-greeter",
        "usr/bin/noctalia-greeter-compositor",
        "usr/bin/noctalia-greeter-apply-appearance",
    ),
}

LIBRARY_NAME = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,254}",
    re.ASCII,
)

SAFE_ABSOLUTE_PATH = re.compile(
    r"/[A-Za-z0-9_.+/-]+",
    re.ASCII,
)

TREE_RECORD = re.compile(
    r"( +)([A-Za-z0-9_][A-Za-z0-9_.+-]{0,254})"
    r" => (None|/[A-Za-z0-9_.+/-]+)",
    re.ASCII,
)

FORBIDDEN_DYNAMIC_TAGS = frozenset({
    "DT_RPATH",
    "DT_RUNPATH",
    "DT_AUDIT",
    "DT_DEPAUDIT",
    "DT_FILTER",
    "DT_AUXILIARY",
    "DT_SONAME",
    "DT_TEXTREL",
})

DF_TEXTREL = 0x00000004
DF_ORIGIN = 0x00000001

DF_1_NODEFLIB = 0x00000800
DF_1_ORIGIN = 0x00000080


class LinkageError(RuntimeError):
    """Candidate static linkage validation failed."""


def validate_absolute_path(value):
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or SAFE_ABSOLUTE_PATH.fullmatch(value) is None
        or any(
            part in {"", ".", ".."}
            for part in value[1:].split("/")
        )
    ):
        raise LinkageError(
            f"Unexpected absolute path: {value!r}"
        )

    return value


def validate_library_name(value):
    if (
        not isinstance(value, str)
        or LIBRARY_NAME.fullmatch(value) is None
        or value in {".", ".."}
    ):
        raise LinkageError(
            f"Unexpected dependency name: {value!r}"
        )

    return value


def validate_runtime_path(value):
    """Restrict dependencies to the qualified Arch library tree."""

    validate_absolute_path(value)

    try:
        resolved = Path(value).resolve(strict=True)
        info = resolved.stat()
    except OSError as error:
        raise LinkageError(
            f"Runtime library unavailable: {value!r}"
        ) from error

    if (
        not resolved.is_relative_to("/usr/lib")
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
    ):
        raise LinkageError(
            f"Untrusted runtime library: {value!r}"
        )

    for parent in resolved.parents:
        info = parent.stat()

        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            raise LinkageError(
                f"Untrusted runtime ancestor: {parent}"
            )

    return str(resolved)


def validate_dynamic_tags(tags):
    """Apply the restricted candidate dynamic linkage policy."""

    needed = []
    terminated = False
    count = 0

    for name, value in tags:
        count += 1

        if count > MAX_DYNAMIC_TAGS:
            raise LinkageError(
                "Dynamic tag count exceeds policy"
            )

        if name == "DT_NULL":
            terminated = True
            break

        if name in FORBIDDEN_DYNAMIC_TAGS:
            raise LinkageError(
                f"Unsupported candidate dynamic tag: {name}"
            )

        if name == "DT_FLAGS":
            if value & (DF_TEXTREL | DF_ORIGIN):
                raise LinkageError(
                    "Unsupported candidate dynamic flags"
                )

        if name == "DT_FLAGS_1":
            if value & (DF_1_NODEFLIB | DF_1_ORIGIN):
                raise LinkageError(
                    "Unsupported candidate search flags"
                )

        if name == "DT_NEEDED":
            needed.append(validate_library_name(value))

            if len(needed) > MAX_DIRECT_DEPENDENCIES:
                raise LinkageError(
                    "Direct dependency count exceeds policy"
                )

    if not terminated:
        raise LinkageError(
            "Dynamic table lacks termination"
        )

    if not needed:
        raise LinkageError(
            "Expected dynamically linked executable"
        )

    if len(needed) != len(set(needed)):
        raise LinkageError(
            "Duplicate direct dependency"
        )

    return tuple(needed)


def read_elf_range(stream, offset, length, file_size):
    """Read an explicitly bounded physical ELF file range."""

    if (
        offset < 0
        or length < 0
        or offset > file_size
        or length > file_size - offset
    ):
        raise LinkageError(
            "ELF range outside file bounds"
        )

    stream.seek(offset)
    data = stream.read(length)

    if len(data) != length:
        raise LinkageError("Truncated ELF range")

    return data


def inspect_elf_structure(stream, file_size):
    """Validate the restricted physical ELF64 layout before parsing."""

    if not 0 < file_size <= MAX_ELF_BYTES:
        raise LinkageError("ELF size outside policy")

    def read(offset, length):
        return read_elf_range(
            stream, offset, length, file_size
        )

    (
        ident, elf_type, machine, version,
        entry, phoff, shoff, flags, ehsize,
        phentsize, phnum, shentsize, shnum,
        shstrndx,
    ) = ELF64_HEADER.unpack(
        read(0, ELF64_HEADER.size)
    )

    if (
        ident[:7] != b"\x7fELF\x02\x01\x01"
        or elf_type not in (2, 3)
        or machine != 62
        or version != 1
        or ehsize != ELF64_HEADER.size
    ):
        raise LinkageError(
            "Unsupported physical ELF header"
        )

    if (
        phentsize != ELF64_PROGRAM.size
        or not 0 < phnum <= MAX_PROGRAM_HEADERS
        or phoff < ELF64_HEADER.size
    ):
        raise LinkageError(
            "Program header table outside policy"
        )

    if (
        shentsize != ELF64_SECTION.size
        or not 0 < shnum <= MAX_SECTION_HEADERS
        or shoff < ELF64_HEADER.size
        or not 0 < shstrndx < shnum
    ):
        raise LinkageError(
            "Section header table outside policy"
        )

    programs = list(
        ELF64_PROGRAM.iter_unpack(
            read(phoff, phnum * phentsize)
        )
    )

    sections = list(
        ELF64_SECTION.iter_unpack(
            read(shoff, shnum * shentsize)
        )
    )

    for program in programs:
        kind = program[0]
        offset = program[2]
        filesz = program[5]
        memsz = program[6]

        if (
            offset > file_size
            or filesz > file_size - offset
            or (kind == 1 and filesz > memsz)
        ):
            raise LinkageError(
                "Invalid program segment extent"
            )

    for section in sections:
        kind = section[1]
        offset = section[4]
        length = section[5]

        # SHT_NOBITS has no physical file payload.
        if kind not in (0, 8) and (
            offset > file_size
            or length > file_size - offset
        ):
            raise LinkageError(
                "Invalid section extent"
            )

    if sections[shstrndx][1] != 3:
        raise LinkageError(
            "Invalid section name string table"
        )

    interpreters = [
        record for record in programs
        if record[0] == 3
    ]

    if len(interpreters) != 1:
        raise LinkageError(
            "Expected exactly one interpreter segment"
        )

    interpreter = interpreters[0]
    expected = INTERPRETER.encode("ascii") + b"\0"

    if (
        interpreter[5] != len(expected)
        or read(
            interpreter[2], interpreter[5]
        ) != expected
    ):
        raise LinkageError(
            "Unexpected physical ELF interpreter"
        )

    dynamics = [
        record for record in programs
        if record[0] == 2
    ]

    if len(dynamics) != 1:
        raise LinkageError(
            "Expected exactly one dynamic segment"
        )

    dynamic = dynamics[0]
    dynamic_offset = dynamic[2]
    dynamic_address = dynamic[3]
    dynamic_size = dynamic[5]

    if (
        not 0 < dynamic_size <= MAX_DYNAMIC_BYTES
        or dynamic_size % ELF64_DYNAMIC.size
        or dynamic_size // ELF64_DYNAMIC.size
           > MAX_DYNAMIC_TAGS
    ):
        raise LinkageError(
            "Physical dynamic segment outside policy"
        )

    def mapped_offset(address, length):
        mappings = []

        for program in programs:
            if program[0] != 1:
                continue

            delta = address - program[3]
            filesz = program[5]

            if (
                0 <= delta <= filesz
                and length <= filesz - delta
            ):
                mappings.append(
                    program[2] + delta
                )

        if len(mappings) != 1:
            raise LinkageError(
                "Ambiguous or absent file-backed mapping"
            )

        return mappings[0]

    if mapped_offset(
        dynamic_address, dynamic_size
    ) != dynamic_offset:
        raise LinkageError(
            "Dynamic segment load mapping mismatch"
        )

    records = list(
        ELF64_DYNAMIC.iter_unpack(
            read(dynamic_offset, dynamic_size)
        )
    )

    first_null = next(
        (
            index
            for index, (tag, value) in enumerate(records)
            if tag == 0
        ),
        None,
    )

    if first_null is None:
        raise LinkageError(
            "Dynamic termination outside segment"
        )

    if any(
        record != (0, 0)
        for record in records[first_null:]
    ):
        raise LinkageError(
            "Nonzero data after dynamic termination"
        )

    active = records[:first_null]

    # Production repeats DT_NEEDED only.
    seen = set()

    for tag, value in active:
        if tag != 1 and tag in seen:
            raise LinkageError(
                "Duplicate singleton dynamic tag"
            )

        seen.add(tag)

    def single_tag(tag):
        values = [
            value
            for key, value in active
            if key == tag
        ]

        if len(values) != 1:
            raise LinkageError(
                "Missing or duplicate dynamic string metadata"
            )

        return values[0]

    string_address = single_tag(5)
    string_size = single_tag(10)

    if not 0 < string_size <= MAX_DYNAMIC_STRING_BYTES:
        raise LinkageError(
            "Dynamic string table outside policy"
        )

    string_offset = mapped_offset(
        string_address, string_size
    )

    strings = read(string_offset, string_size)

    if (
        strings[:1] != b"\0"
        or strings[-1:] != b"\0"
    ):
        raise LinkageError(
            "Invalid dynamic string table termination"
        )

    dynamic_sections = [
        section for section in sections
        if section[1] == 6
    ]

    if len(dynamic_sections) != 1:
        raise LinkageError(
            "Expected exactly one dynamic section"
        )

    section = dynamic_sections[0]

    if (
        section[3] != dynamic_address
        or section[4] != dynamic_offset
        or section[5] != dynamic_size
        or section[9] != ELF64_DYNAMIC.size
    ):
        raise LinkageError(
            "Dynamic section and segment disagree"
        )

    linked_index = section[6]

    if not 0 < linked_index < len(sections):
        raise LinkageError(
            "Invalid dynamic string table section index"
        )

    linked = sections[linked_index]

    if (
        linked[1] != 3
        or linked[3] != string_address
        or linked[4] != string_offset
        or linked[5] != string_size
    ):
        raise LinkageError(
            "Dynamic string table section mismatch"
        )

    # Apply the existing policy independently to numeric
    # dynamic tags relevant to dependency resolution.

    names = {
        1: "DT_NEEDED",
        14: "DT_SONAME",
        15: "DT_RPATH",
        22: "DT_TEXTREL",
        29: "DT_RUNPATH",
        30: "DT_FLAGS",
        0x6ffffefb: "DT_DEPAUDIT",
        0x6ffffefc: "DT_AUDIT",
        0x6ffffffb: "DT_FLAGS_1",
        0x7ffffffd: "DT_AUXILIARY",
        0x7fffffff: "DT_FILTER",
    }

    policy_tags = []

    for tag, value in active:
        if tag == 1:
            if not 0 < value < string_size:
                raise LinkageError(
                    "Dependency string offset outside table"
                )

            end = strings.find(
                b"\0",
                value,
                min(string_size, value + 256),
            )

            if end == -1:
                raise LinkageError(
                    "Dependency string outside length policy"
                )

            try:
                value = strings[value:end].decode("ascii")
            except UnicodeDecodeError as error:
                raise LinkageError(
                    "Non-ASCII dependency string"
                ) from error

        policy_tags.append(
            (names.get(tag, tag), value)
        )

    policy_tags.append(("DT_NULL", None))

    return {
        "needed": validate_dynamic_tags(policy_tags),
        "program_headers": phnum,
        "section_headers": shnum,
        "dynamic_bytes": dynamic_size,
        "dynamic_string_bytes": string_size,
    }


def inspect_elf_metadata(stream):
    """Read program headers and dynamic metadata without loading ELF."""

    # Imported only when ELF inspection is requested.
    # Portable policy tests do not require pyelftools.
    from elftools.elf.elffile import ELFFile

    size = os.fstat(stream.fileno()).st_size
    structure = inspect_elf_structure(stream, size)

    stream.seek(0)
    elf = ELFFile(stream)

    if (
        elf.elfclass != 64
        or not elf.little_endian
        or elf.header["e_machine"] != "EM_X86_64"
        or elf.header["e_type"] not in {
            "ET_EXEC",
            "ET_DYN",
        }
    ):
        raise LinkageError(
            "Unexpected candidate ELF architecture or type"
        )

    count = elf.num_segments()

    if not 0 < count <= MAX_PROGRAM_HEADERS:
        raise LinkageError(
            "Program header count outside policy"
        )

    interpreters = []
    dynamics = []

    for segment in elf.iter_segments():
        offset = segment["p_offset"]
        length = segment["p_filesz"]

        if (
            offset < 0
            or length < 0
            or offset + length > size
        ):
            raise LinkageError(
                "Program segment outside ELF file"
            )

        kind = segment["p_type"]

        if kind == "PT_INTERP":
            if not 0 < length <= 256:
                raise LinkageError(
                    "Interpreter segment outside policy"
                )

            stream.seek(offset)

            expected = INTERPRETER.encode("ascii") + b"\0"

            if stream.read(length) != expected:
                raise LinkageError(
                    "Unexpected candidate interpreter"
                )

            interpreters.append(INTERPRETER)

        elif kind == "PT_DYNAMIC":
            if not 0 < length <= MAX_DYNAMIC_BYTES:
                raise LinkageError(
                    "Dynamic segment outside policy"
                )

            if length % 16:
                raise LinkageError(
                    "Unaligned ELF64 dynamic segment"
                )

            dynamics.append(segment)

    if interpreters != [INTERPRETER]:
        raise LinkageError(
            "Expected exactly one approved interpreter"
        )

    if len(dynamics) != 1:
        raise LinkageError(
            "Expected exactly one dynamic segment"
        )

    def tags():
        for tag in dynamics[0].iter_tags():
            name = tag.entry.d_tag

            if name == "DT_NEEDED":
                value = tag.needed
            elif name in {"DT_FLAGS", "DT_FLAGS_1"}:
                value = tag.entry.d_val
            else:
                value = None

            yield name, value

    needed = validate_dynamic_tags(tags())

    if needed != structure["needed"]:
        raise LinkageError(
            "Independent ELF metadata interpretations disagree"
        )

    return {
        "architecture": "x86_64",
        "interpreter": INTERPRETER,
        **structure,
    }


def parse_dependency_tree(
    output,
    *,
    executable,
    needed,
    runtime_path_validator=validate_runtime_path,
):
    """Validate qualified lddtree output and resolved paths."""

    validate_absolute_path(executable)

    if not isinstance(output, str):
        raise LinkageError(
            "Invalid dependency resolver output"
        )

    lines = output.splitlines()

    expected_header = (
        f"{executable} "
        f"(interpreter => {INTERPRETER})"
    )

    if not lines or lines[0] != expected_header:
        raise LinkageError(
            "Unexpected dependency tree header"
        )

    interpreter = runtime_path_validator(INTERPRETER)

    records = {}
    direct = set()
    previous_depth = 0

    for line in lines[1:]:
        match = TREE_RECORD.fullmatch(line)

        if match is None:
            raise LinkageError(
                f"Unexpected dependency tree record: {line!r}"
            )

        indentation, library, location = match.groups()

        if (
            len(indentation) % 4
            or not indentation
        ):
            raise LinkageError(
                "Unexpected dependency tree indentation"
            )

        depth = len(indentation) // 4

        if (
            depth > MAX_TREE_DEPTH
            or depth > previous_depth + 1
        ):
            raise LinkageError(
                "Invalid dependency tree depth"
            )

        previous_depth = depth

        validate_library_name(library)

        if location == "None":
            raise LinkageError(
                f"Unresolved runtime dependency: {library}"
            )

        resolved = runtime_path_validator(location)

        if library in records:
            raise LinkageError(
                f"Duplicate dependency tree record: {library}"
            )

        records[library] = resolved

        if len(records) > MAX_RESOLVED_LIBRARIES:
            raise LinkageError(
                "Resolved dependency count exceeds policy"
            )

        if depth == 1:
            direct.add(library)

    if not set(needed) <= records.keys():
        raise LinkageError(
            "Resolver omitted required direct dependencies"
        )

    if not direct:
        raise LinkageError(
            "Empty resolved dependency tree"
        )

    return {
        "interpreter_path": interpreter,
        "libraries": dict(sorted(records.items())),
    }


def resolver_limits():
    """Resource limits applied before executing the static resolver."""

    resource.setrlimit(
        resource.RLIMIT_AS,
        (
            RESOLVER_ADDRESS_SPACE,
            RESOLVER_ADDRESS_SPACE,
        ),
    )

    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (
            MAX_RESOLVER_OUTPUT,
            MAX_RESOLVER_OUTPUT,
        ),
    )

    resource.setrlimit(
        resource.RLIMIT_CPU,
        (
            RESOLVER_TIMEOUT,
            RESOLVER_TIMEOUT,
        ),
    )

    resource.setrlimit(
        resource.RLIMIT_CORE,
        (0, 0),
    )


def resolve_dependencies(path, needed):
    """Execute only the trusted static parser, never the candidate."""

    executable = validate_absolute_path(str(path))

    with (
        tempfile.TemporaryFile() as stdout,
        tempfile.TemporaryFile() as stderr,
    ):
        try:
            result = subprocess.run(
                [
                    PYTHON,
                    "-I",
                    "-B",
                    RESOLVER,
                    "--",
                    executable,
                ],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                cwd="/",
                env=ENVIRONMENT,
                timeout=RESOLVER_TIMEOUT,
                preexec_fn=resolver_limits,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise LinkageError(
                "Static dependency resolver timed out"
            ) from error

        if result.returncode != 0:
            raise LinkageError(
                f"Static resolver failed: {result.returncode}"
            )

        stdout.seek(0)
        stderr.seek(0)

        output = stdout.read(MAX_RESOLVER_OUTPUT + 1)
        diagnostics = stderr.read(MAX_RESOLVER_OUTPUT + 1)

    if len(output) >= MAX_RESOLVER_OUTPUT:
        raise LinkageError(
            "Static resolver output exceeds policy"
        )

    if diagnostics:
        raise LinkageError(
            "Unexpected static resolver diagnostics"
        )

    return parse_dependency_tree(
        output.decode("ascii", errors="strict"),
        executable=executable,
        needed=needed,
    )


def file_identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def file_digest(stream):
    stream.seek(0)

    result = hashlib.sha256()
    total = 0

    while True:
        data = stream.read(1024**2)

        if not data:
            break

        total += len(data)

        if total > MAX_ELF_BYTES:
            raise LinkageError(
                "ELF size exceeds hashing limit"
            )

        result.update(data)

    stream.seek(0)

    return result.hexdigest()


def inspect_executable(path, *, privilege_guard):
    """Inspect a protected candidate executable without executing it.

    The caller must supply the trusted privilege guard and establish
    protected storage, exact archive-member provenance and an outer
    process deadline before invoking this function.

    Intended for a dedicated, single-threaded inspection process.
    """

    privilege_guard()

    path = Path(validate_absolute_path(str(path)))

    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
        | os.O_CLOEXEC,
    )

    try:
        before = os.fstat(descriptor)

        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= MAX_ELF_BYTES
            or before.st_uid != 0
            or before.st_mode & 0o7022
            or before.st_nlink != 1
        ):
            raise LinkageError(
                "Candidate ELF file outside storage policy"
            )
    except BaseException:
        os.close(descriptor)
        raise

    with os.fdopen(descriptor, "rb") as stream:
        original_digest = file_digest(stream)

        metadata = inspect_elf_metadata(stream)

        if file_identity(before) != file_identity(
            os.fstat(stream.fileno())
        ):
            raise LinkageError(
                "Candidate changed during ELF inspection"
            )

        resolved = resolve_dependencies(
            path,
            metadata["needed"],
        )

        if (
            file_digest(stream) != original_digest
            or file_identity(before) != file_identity(
                os.fstat(stream.fileno())
            )
            or file_identity(before) != file_identity(
                path.lstat()
            )
        ):
            raise LinkageError(
                "Candidate changed during linkage inspection"
            )

    return {
        "schema": 1,
        "static_linkage_validation": True,
        "sha256": original_digest,
        **metadata,
        **resolved,
    }
