"""Portable regression coverage for candidate archive inspection."""

import errno
import hashlib
import importlib.util
import io
import os
import sys
import tarfile
import tempfile
import time
import unittest

from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/package-pipeline/candidate_archive.py"

SPEC = importlib.util.spec_from_file_location(
    "candidate_archive",
    HELPER,
)

archive = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = archive
SPEC.loader.exec_module(archive)

registry = archive.load_release_registry()

BLOCK = 512
ZERO = bytes(BLOCK)
VERSION = "1.0-1"
DIGEST = "a" * 64


def header(
    name,
    *,
    size=0,
    kind=tarfile.REGTYPE,
    mode=None,
    target="",
    uid=0,
    gid=0,
    uname="root",
    gname="root",
    format=tarfile.USTAR_FORMAT,
):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = size
    info.linkname = target
    info.uid = uid
    info.gid = gid
    info.uname = uname
    info.gname = gname

    if mode is None:
        mode = {
            tarfile.DIRTYPE: 0o755,
            tarfile.SYMTYPE: 0o777,
        }.get(kind, 0o644)

    info.mode = mode

    return info.tobuf(
        format=format,
        encoding="utf-8",
        errors="strict",
    )


def member(name, payload=b"", **options):
    return (
        header(name, size=len(payload), **options)
        + payload
        + bytes((-len(payload)) % BLOCK)
    )


def pkginfo(
    name="broot",
    version=VERSION,
    architecture="x86_64",
):
    return (
        f"pkgname = {name}\n"
        f"pkgver = {version}\n"
        f"arch = {architecture}\n"
        "license = MIT\n"
        "depend = glibc\n"
        "depend = bash\n"
    )


def metadata(name="broot", **options):
    return (
        member(
            ".PKGINFO",
            pkginfo(name, **options).encode("utf-8"),
        )
        + member(".BUILDINFO", b"format = 2\n")
        + member(".MTREE", b"fixture")
    )


def body():
    return (
        metadata()
        + member("usr/", kind=tarfile.DIRTYPE)
        + member("usr/bin/", kind=tarfile.DIRTYPE)
        + member("usr/bin/broot", b"fixture", mode=0o755)
    )


def inspect(data):
    return archive.inspect_tar_stream(io.BytesIO(data))


def rechecksum(raw):
    raw = bytearray(raw)
    raw[148:156] = b" " * 8
    raw[148:156] = (
        f"{sum(raw):06o}".encode("ascii")
        + b"\x00 "
    )
    return bytes(raw)


def modify_header(raw, offset, replacement):
    raw = bytearray(raw)
    raw[offset:offset + len(replacement)] = replacement
    return rechecksum(raw)


def regular():
    return {
        "type": "file",
        "mode": 0o644,
        "size": 1,
    }


def directory():
    return {
        "type": "directory",
        "mode": 0o755,
        "size": 0,
    }


def symlink(target):
    return {
        "type": "symlink",
        "mode": 0o777,
        "size": 0,
        "target": target,
    }


def synthetic_inventory(
    name,
    *,
    version=VERSION,
    architecture="x86_64",
    extra=b"",
):
    result = inspect(
        metadata(
            name,
            version=version,
            architecture=architecture,
        )
        + extra
        + ZERO * 2
    )

    result.update({
        "package": (
            f"{name}-{version}-{architecture}.pkg.tar.zst"
        ),
        "compressed_bytes": 1024,
        "sha256": DIGEST,
    })

    return result


def batch(*inventories):
    selected = {
        item["package"]: item
        for item in inventories
    }

    checksums = {
        name: item["sha256"]
        for name, item in selected.items()
    }

    return selected, checksums


class PhysicalArchiveTests(unittest.TestCase):

    def test_valid_ustar(self):
        data = body() + ZERO * 2
        result = inspect(data)

        self.assertEqual(result["member_count"], 6)
        self.assertEqual(result["expanded_bytes"], len(data))
        self.assertTrue(result["structural_inventory_only"])
        self.assertEqual(
            result["metadata"][".PKGINFO"],
            pkginfo(),
        )

    def test_additional_zero_blocks(self):
        data = body() + ZERO * 21
        self.assertEqual(
            inspect(data)["expanded_bytes"],
            len(data),
        )

    def test_invalid_termination(self):
        cases = {
            "missing": body(),
            "single block": body() + ZERO,
            "partial block": body() + ZERO + ZERO[:100],
            "unaligned": body() + ZERO * 2 + b"\x00",
            "nonzero": body() + ZERO * 2 + b"x",
            "concatenated": (body() + ZERO * 2) * 2,
        }

        for label, data in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(archive.ArchiveError):
                    inspect(data)

    def test_truncated_payload(self):
        data = (
            body()
            + member("usr/share/truncated", b"abc")[:513]
        )

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Truncated",
        ):
            inspect(data)

    def test_nonzero_payload_padding(self):
        data = (
            body()
            + member("usr/share/padding", b"x")[:-1]
            + b"X"
            + ZERO * 2
        )

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Nonzero physical member padding",
        ):
            inspect(data)

    def test_unsupported_physical_member_types(self):
        types = (
            tarfile.AREGTYPE,
            tarfile.LNKTYPE,
            tarfile.FIFOTYPE,
            tarfile.CHRTYPE,
            tarfile.BLKTYPE,
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
            tarfile.GNUTYPE_SPARSE,
        )

        for kind in types:
            with self.subTest(kind=kind):
                data = (
                    body()
                    + member("unsupported", kind=kind)
                    + ZERO * 2
                )

                with self.assertRaises(archive.ArchiveError):
                    inspect(data)

    def test_unsupported_archive_format(self):
        data = (
            body()
            + member(
                "usr/share/example",
                format=tarfile.GNU_FORMAT,
            )
            + ZERO * 2
        )

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Unsupported physical tar format",
        ):
            inspect(data)

    def test_missing_required_metadata(self):
        for missing in archive.REQUIRED_METADATA:
            with self.subTest(missing=missing):
                data = b"".join(
                    member(name, b"fixture")
                    for name in archive.REQUIRED_METADATA
                    if name != missing
                )

                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "Missing required package metadata",
                ):
                    inspect(data + ZERO * 2)

    def test_duplicate_normalized_paths(self):
        for duplicate in (
            ".PKGINFO",
            "./.PKGINFO",
            "usr/bin/broot",
            "./usr/bin/broot",
        ):
            with self.subTest(duplicate=duplicate):
                data = (
                    body()
                    + member(duplicate, b"duplicate")
                    + ZERO * 2
                )

                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "Duplicate archive member",
                ):
                    inspect(data)

    def test_unsafe_member_paths(self):
        for name in (
            "/outside",
            "../outside",
            "usr/../outside",
            "usr//bin/example",
            "usr/./bin/example",
            "usr\\bin\\example",
            "usr/bin/\nexample",
        ):
            with self.subTest(name=name):
                data = body() + member(name) + ZERO * 2

                with self.assertRaises(archive.ArchiveError):
                    inspect(data)

    def test_non_directory_ancestor(self):
        data = (
            body()
            + member("usr/bin/broot/child", b"fixture")
            + ZERO * 2
        )

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "non-directory ancestor",
        ):
            inspect(data)

    def test_symlink_ancestor(self):
        data = (
            body()
            + member(
                "usr/bin/link",
                kind=tarfile.SYMTYPE,
                target="broot",
            )
            + member("usr/bin/link/child", b"fixture")
            + ZERO * 2
        )

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "non-directory ancestor",
        ):
            inspect(data)

    def test_nonregular_metadata(self):
        data = (
            member(
                ".PKGINFO",
                kind=tarfile.SYMTYPE,
                target="other",
            )
            + member(".BUILDINFO", b"fixture")
            + member(".MTREE", b"fixture")
            + ZERO * 2
        )

        with self.assertRaises(archive.ArchiveError):
            inspect(data)

    def test_nonregular_payload(self):
        for kind in (tarfile.DIRTYPE, tarfile.SYMTYPE):
            with self.subTest(kind=kind):
                data = (
                    body()
                    + member(
                        "unexpected",
                        b"payload",
                        kind=kind,
                    )
                    + ZERO * 2
                )

                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "Nonregular member has payload",
                ):
                    inspect(data)

    def test_regular_file_link_target(self):
        data = (
            body()
            + member("unexpected", target="broot")
            + ZERO * 2
        )

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Unexpected link target",
        ):
            inspect(data)


class HeaderEncodingTests(unittest.TestCase):

    def test_conventional_ustar(self):
        archive.decode_physical_header(
            header("usr/bin/example")
        )

    def test_production_libarchive_encoding(self):
        raw = bytearray(header("usr/bin/example"))

        for field, (start, end) in (
            archive.USTAR_NUMERIC_FIELDS.items()
        ):
            if field == "checksum":
                continue

            value = archive.decode_ustar_number(
                field,
                raw[start:end],
            )

            width = end - start

            if field in {"size", "mtime"}:
                encoded = (
                    f"{value:0{width - 1}o}".encode("ascii")
                    + b" "
                )
            else:
                encoded = (
                    f"{value:0{width - 2}o}".encode("ascii")
                    + b" \x00"
                )

            self.assertEqual(len(encoded), width)
            raw[start:end] = encoded

        archive.decode_physical_header(rechecksum(raw))

    def test_full_width_name_and_path_prefix(self):
        for name in (
            "a" * 100,
            "usr/share/" + "a" * 90 + "/example",
        ):
            with self.subTest(name=name):
                item, kind = archive.decode_physical_header(
                    header(name)
                )

                self.assertEqual(item.name, name)
                self.assertEqual(kind, "file")

    def test_ambiguous_numeric_encodings(self):
        raw = header("usr/bin/example")

        cases = (
            (124, b"\x80" + bytes(11)),
            (124, b"-0000000001\x00"),
            (100, b"0000899\x00"),
            (100, b"0755\x00BAD"),
        )

        for offset, replacement in cases:
            with self.subTest(offset=offset, raw=replacement):
                with self.assertRaises(archive.ArchiveError):
                    archive.decode_physical_header(
                        modify_header(raw, offset, replacement)
                    )

    def test_hidden_bytes_after_nul(self):
        raw = header("usr/bin/example")

        for offset in (90, 180, 280, 315, 490):
            with self.subTest(offset=offset):
                with self.assertRaises(archive.ArchiveError):
                    archive.decode_physical_header(
                        modify_header(raw, offset, b"hidden")
                    )

    def test_unauthorized_ownership(self):
        cases = (
            {"uid": 1000},
            {"gid": 1000},
            {"uname": "builder"},
            {"gname": "builder"},
        )

        for options in cases:
            with self.subTest(options=options):
                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "ownership",
                ):
                    archive.decode_physical_header(
                        header("example", **options)
                    )

    def test_device_and_reserved_fields(self):
        raw = header("example")

        for offset, value in (
            (329, b"0000001\x00"),
            (337, b"0000001\x00"),
            (500, b"X"),
        ):
            with self.subTest(offset=offset):
                with self.assertRaises(archive.ArchiveError):
                    archive.decode_physical_header(
                        modify_header(raw, offset, value)
                    )

    def test_restrictive_modes(self):
        for mode in (0o600, 0o640, 0o644, 0o700, 0o755):
            with self.subTest(mode=mode):
                archive.decode_physical_header(
                    header("example", mode=mode)
                )

    def test_unsafe_modes(self):
        for mode in (
            0o664,
            0o666,
            0o4755,
            0o2755,
            0o1755,
        ):
            with self.subTest(mode=mode):
                data = (
                    body()
                    + member("example", mode=mode)
                    + ZERO * 2
                )

                with self.assertRaises(archive.ArchiveError):
                    inspect(data)

    def test_invalid_symlink_mode(self):
        with self.assertRaises(archive.ArchiveError):
            archive.decode_physical_header(
                header(
                    "example",
                    kind=tarfile.SYMTYPE,
                    target="other",
                    mode=0o755,
                )
            )

    def test_invalid_checksum(self):
        raw = bytearray(header("example"))
        raw[0] ^= 1

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "checksum",
        ):
            archive.decode_physical_header(bytes(raw))

    def test_invalid_checksum_encoding(self):
        raw = bytearray(header("example"))
        raw[154:156] = b" \x00"

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "checksum encoding",
        ):
            archive.decode_physical_header(bytes(raw))


class SymbolicLinkTests(unittest.TestCase):

    def entries(self):
        return {
            "usr": directory(),
            "usr/bin": directory(),
            "usr/bin/terminal": regular(),
        }

    def test_relative_link(self):
        entries = self.entries()
        entries["usr/bin/alias"] = symlink("terminal")

        result = archive.validate_symbolic_links(
            "broot", entries
        )

        self.assertEqual(
            result["usr/bin/alias"]["resolved"],
            "usr/bin/terminal",
        )
        self.assertFalse(
            result["usr/bin/alias"]["cross_package"]
        )

    def test_invalid_relative_links(self):
        for target in (
            "../../../outside",
            "missing",
            "../bin",
            "/etc/passwd",
            "../../.PKGINFO",
            "alias",
        ):
            with self.subTest(target=target):
                entries = self.entries()
                entries[".PKGINFO"] = regular()
                entries["usr/bin/alias"] = symlink(target)

                with self.assertRaises(archive.ArchiveError):
                    archive.validate_symbolic_links(
                        "broot", entries
                    )

    def test_two_link_cycle(self):
        entries = self.entries()
        entries["usr/bin/one"] = symlink("two")
        entries["usr/bin/two"] = symlink("one")

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "cycle",
        ):
            archive.validate_symbolic_links(
                "broot", entries
            )

    def test_link_hop_boundary(self):
        for hops in (39, 40, 41):
            with self.subTest(hops=hops):
                entries = self.entries()

                for index in range(hops):
                    target = (
                        f"link{index + 1}"
                        if index + 1 < hops
                        else "terminal"
                    )

                    entries[
                        f"usr/bin/link{index}"
                    ] = symlink(target)

                if hops <= 40:
                    result = archive.validate_symbolic_links(
                        "broot", entries
                    )

                    self.assertEqual(
                        result["usr/bin/link0"]["hops"],
                        hops,
                    )
                else:
                    with self.assertRaisesRegex(
                        archive.ArchiveError,
                        "chain exceeds limit",
                    ):
                        archive.validate_symbolic_links(
                            "broot", entries
                        )

    def test_engrampa_documentation_exception(self):
        alias = "usr/share/help/fr/engrampa/figures/test.png"
        target = "usr/share/help/C/engrampa/figures/test.png"

        entries = {}

        for name in (alias, target):
            parts = name.split("/")

            for index in range(1, len(parts)):
                entries["/".join(parts[:index])] = directory()

        entries[alias] = symlink("/" + target)
        entries[target] = regular()

        result = archive.validate_symbolic_links(
            "engrampa", entries
        )

        self.assertEqual(result[alias]["resolved"], target)

        with self.assertRaises(archive.ArchiveError):
            archive.validate_symbolic_links("broot", entries)

        for replacement in (
            directory(),
            symlink("other.png"),
            None,
        ):
            with self.subTest(replacement=replacement):
                modified = dict(entries)

                if replacement is None:
                    del modified[target]
                else:
                    modified[target] = replacement

                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "directly to a regular file",
                ):
                    archive.validate_symbolic_links(
                        "engrampa", modified
                    )


class IdentityAndFamilyTests(unittest.TestCase):

    def test_literal_identity(self):
        result = archive.parse_package_identity(pkginfo())

        self.assertEqual(result, {
            "pkgname": "broot",
            "pkgver": VERSION,
            "arch": "x86_64",
        })

    def test_invalid_identity_metadata(self):
        value = pkginfo()

        cases = (
            value + "pkgname = broot\n",
            value + "pkgver = 1.0-1\n",
            value + "arch = x86_64\n",
            value.replace("arch = x86_64\n", ""),
            value.replace("pkgname = ", "pkgname="),
            value.replace("pkgname = broot", "pkgname = broot "),
            value.replace(VERSION, "1:1.0-1"),
            value.replace("x86_64", "aarch64"),
            value + "\x00",
        )

        for data in cases:
            with self.subTest(data=data):
                with self.assertRaises(archive.ArchiveError):
                    archive.parse_package_identity(data)

    def test_production_version_forms(self):
        for version in (
            "1.4.0-1",
            "2.8.0-4",
            "5.6.0.custom.23080f65-2",
            "0.6.0.r40.g63ae30982cf2-1",
            "20240203.110809.5046fc22.r985.g89e01990a-1",
        ):
            with self.subTest(version=version):
                archive.validate_identity_values(
                    "example", version, "x86_64"
                )

    def test_all_family_required_output_sets(self):
        self.assertEqual(len(registry.OUTPUT_CONTRACTS), 13)

        for family, contract in (
            registry.OUTPUT_CONTRACTS.items()
        ):
            with self.subTest(family=family):
                items = [
                    synthetic_inventory(
                        name,
                        architecture=contract.architecture,
                    )
                    for name in contract.required
                ]

                inventories, checksums = batch(*items)

                result = archive.validate_family_inventories(
                    family,
                    VERSION,
                    inventories,
                    checksums,
                    registry=registry,
                )

                self.assertEqual(
                    set(result["packages"]),
                    set(contract.required),
                )

    def test_identity_digest_and_filename_binding(self):
        inventory = synthetic_inventory("broot")

        expected = {
            "name": "broot",
            "version": VERSION,
            "architecture": "x86_64",
            "expected_sha256": DIGEST,
        }

        archive.validate_expected_identity(
            inventory, **expected
        )

        for field, value in (
            ("package", "broot-2.0-1-x86_64.pkg.tar.zst"),
            ("sha256", "b" * 64),
            ("metadata", {".PKGINFO": pkginfo("wezterm")}),
            ("metadata", {".PKGINFO": pkginfo(version="2.0-1")}),
            ("metadata", {".PKGINFO": pkginfo(architecture="any")}),
        ):
            with self.subTest(field=field, value=value):
                modified = dict(inventory)
                modified[field] = value

                with self.assertRaises(archive.ArchiveError):
                    archive.validate_expected_identity(
                        modified, **expected
                    )

    def syncthing_inventory(self, name, path=None):
        extra = (
            member("usr/", kind=tarfile.DIRTYPE)
            + member("usr/bin/", kind=tarfile.DIRTYPE)
        )

        if path:
            extra += member(path, b"fixture")

        return synthetic_inventory(name, extra=extra)

    def test_family_membership_and_collision_rejections(self):
        main = self.syncthing_inventory(
            "syncthing", "usr/bin/syncthing"
        )
        disco = self.syncthing_inventory(
            "syncthing-discosrv", "usr/bin/syncthing-discosrv"
        )
        relay = self.syncthing_inventory(
            "syncthing-relaysrv", "usr/bin/syncthing-relaysrv"
        )

        cases = (
            (main, disco),
            (main, disco, relay, synthetic_inventory("broot")),
            (
                main,
                disco,
                self.syncthing_inventory(
                    "syncthing-relaysrv",
                    "usr/bin/syncthing",
                ),
            ),
            (
                main,
                disco,
                self.syncthing_inventory(
                    "syncthing-relaysrv",
                    "usr/bin/syncthing/child",
                ),
            ),
        )

        for items in cases:
            with self.subTest(
                names=[item["package"] for item in items]
            ):
                inventories, checksums = batch(*items)

                with self.assertRaises(archive.ArchiveError):
                    archive.validate_family_inventories(
                        "syncthing",
                        VERSION,
                        inventories,
                        checksums,
                        registry=registry,
                    )

    def test_shared_debug_companion_ownership(self):
        names = (
            "syncthing",
            "syncthing-discosrv",
            "syncthing-relaysrv",
        )

        companions = [
            self.syncthing_inventory(
                name, f"usr/bin/{name}"
            )
            for name in names
        ]

        extra = b"".join(
            member(name, kind=tarfile.DIRTYPE)
            for name in (
                "usr/",
                "usr/lib/",
                "usr/lib/debug/",
                "usr/lib/debug/.build-id/",
                "usr/lib/debug/.build-id/ab/",
                "usr/lib/debug/usr/",
                "usr/lib/debug/usr/bin/",
            )
        )

        links = {}

        for index, name in enumerate(names, 1):
            link = (
                "usr/lib/debug/.build-id/ab/"
                + f"{index:038x}"
            )

            extra += member(
                link,
                kind=tarfile.SYMTYPE,
                target=f"../../../../bin/{name}",
            )

            extra += member(
                link + ".debug",
                kind=tarfile.SYMTYPE,
                target=f"../../usr/bin/{name}.debug",
            )

            extra += member(
                f"usr/lib/debug/usr/bin/{name}.debug",
                b"debug fixture",
            )

            links[link] = name

        debug = synthetic_inventory(
            "syncthing-debug", extra=extra
        )

        inventories, checksums = batch(
            *companions, debug
        )

        result = archive.validate_family_inventories(
            "syncthing",
            VERSION,
            inventories,
            checksums,
            registry=registry,
        )

        resolved = result["packages"][
            "syncthing-debug"
        ]["symbolic_links"]

        self.assertEqual(len(resolved), 6)

        for link, owner in links.items():
            self.assertEqual(
                resolved[link]["target_package"], owner
            )
            self.assertTrue(
                resolved[link]["cross_package"]
            )

        # A valid family member is not enough: the
        # actual approved companion target must exist.
        broken = list(companions)
        broken[2] = self.syncthing_inventory(
            "syncthing-relaysrv", "usr/bin/unrelated"
        )

        inventories, checksums = batch(*broken, debug)

        with self.assertRaises(archive.ArchiveError):
            archive.validate_family_inventories(
                "syncthing",
                VERSION,
                inventories,
                checksums,
                registry=registry,
            )


class ChecksumManifestTests(unittest.TestCase):

    filename = "broot-1.0-1-x86_64.pkg.tar.zst"

    def record(self):
        return (
            f"{DIGEST}  {self.filename}\n"
        ).encode("ascii")

    def test_exact_checksum_record(self):
        self.assertEqual(
            archive.parse_checksum_manifest(self.record()),
            {self.filename: DIGEST},
        )

    def test_invalid_manifest_records(self):
        record = self.record()

        cases = (
            b"",
            record + record,
            record[:-1],
            record.replace(b"\n", b"\r\n"),
            record.replace(b"a", b"A", 1),
            record.replace(b"  ", b" "),
            record.replace(b"  ", b"   "),
            record.replace(b"  ", b" *"),
            record.replace(b"  ", b"  /"),
            record.replace(b"  ", b"  ../"),
            record + b"\n",
            record + b"# comment\n",
            record + b"\xff\n",
            record.replace(b"broot", b"bro\x00ot"),
        )

        for data in cases:
            with self.subTest(data=data):
                with self.assertRaises(archive.ArchiveError):
                    archive.parse_checksum_manifest(data)

    def test_manifest_size_boundary(self):
        record = self.record()

        with patch.object(
            archive,
            "MAX_CHECKSUM_MANIFEST_BYTES",
            len(record),
        ):
            archive.parse_checksum_manifest(record)

            with self.assertRaises(archive.ArchiveError):
                archive.parse_checksum_manifest(record + b"x")

    def test_manifest_regular_file(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "SHA256SUMS"
            path.write_bytes(self.record())

            self.assertEqual(
                archive.read_checksum_manifest(path),
                {self.filename: DIGEST},
            )

    def test_manifest_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            path = root / "SHA256SUMS"
            path.write_bytes(self.record())

            link = root / "link"
            link.symlink_to(path)

            with self.assertRaises(OSError):
                archive.read_checksum_manifest(link)

    def test_manifest_fifo_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "fifo"
            os.mkfifo(path)

            with self.assertRaisesRegex(
                archive.ArchiveError,
                "regular file",
            ):
                archive.read_checksum_manifest(path)


class ResourceBoundaryTests(unittest.TestCase):

    def test_final_resource_policy(self):
        expected = {
            "MAX_COMPRESSED_BYTES": 512 * 1024**2,
            "MAX_EXPANDED_BYTES": 2 * 1024**3,
            "MAX_MEMBER_BYTES": 512 * 1024**2,
            "MAX_MEMBERS": 25_000,
            "MAX_METADATA_BYTES": 1024**2,
            "MAX_PATH_BYTES": 4096,
            "MAX_LINK_HOPS": 40,
            "INSPECTION_TIMEOUT": 300,
            "PROCESS_CLEANUP_TIMEOUT": 30,
            "ZSTD_MEMORY_LIMIT": "-M128MB",
            "MAX_CHECKSUM_MANIFEST_BYTES": 16 * 1024,
        }

        for field, value in expected.items():
            with self.subTest(field=field):
                self.assertEqual(
                    getattr(archive, field), value
                )

    def test_bounded_hashing(self):
        data = b"12345678"
        stream = io.BytesIO(data)

        result = archive.file_digest(
            stream,
            len(data),
            time.monotonic() + 5,
        )

        self.assertEqual(
            result, hashlib.sha256(data).hexdigest()
        )
        self.assertEqual(stream.tell(), 0)

        for size in (len(data) - 1, len(data) + 1, 0):
            with self.subTest(size=size):
                with self.assertRaises(archive.ArchiveError):
                    archive.file_digest(
                        io.BytesIO(data),
                        size,
                        time.monotonic() + 5,
                    )

    def test_expired_hashing_deadline(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "deadline",
        ):
            archive.file_digest(
                io.BytesIO(b"x"),
                1,
                time.monotonic() - 1,
            )

    def test_compressed_size_boundary(self):
        with patch.object(
            archive, "MAX_COMPRESSED_BYTES", 8
        ):
            archive.file_digest(
                io.BytesIO(bytes(8)),
                8,
                time.monotonic() + 5,
            )

            with self.assertRaises(archive.ArchiveError):
                archive.file_digest(
                    io.BytesIO(bytes(9)),
                    9,
                    time.monotonic() + 5,
                )

    def test_expanded_size_boundary(self):
        reader = archive.BoundedReader(
            io.BytesIO(bytes(8)), 8
        )

        self.assertEqual(reader.read(8), bytes(8))
        self.assertEqual(reader.read(1), b"")

        reader = archive.BoundedReader(
            io.BytesIO(bytes(9)), 8
        )

        with self.assertRaises(archive.ArchiveError):
            reader.read(9)

    def test_member_size_boundary(self):
        # Set the scaled limit above all fixture metadata.
        limit = 128

        with patch.object(
            archive, "MAX_MEMBER_BYTES", limit
        ):
            inspect(
                body()
                + member("example", bytes(limit))
                + ZERO * 2
            )

            with self.assertRaisesRegex(
                archive.ArchiveError,
                "Member size outside policy",
            ):
                inspect(
                    body()
                    + member("example", bytes(limit + 1))
                    + ZERO * 2
                )

    def test_member_count_boundary(self):
        with patch.object(archive, "MAX_MEMBERS", 6):
            inspect(body() + ZERO * 2)

            with self.assertRaisesRegex(
                archive.ArchiveError,
                "member count exceeds limit",
            ):
                inspect(
                    body()
                    + member("extra")
                    + ZERO * 2
                )

    def test_pipe_read_and_eof(self):
        read_fd, write_fd = os.pipe()

        try:
            with os.fdopen(
                read_fd, "rb", buffering=0
            ) as stream:
                os.write(write_fd, b"fixture")
                os.close(write_fd)
                write_fd = None

                with archive.DeadlinePipeReader(
                    stream,
                    time.monotonic() + 5,
                ) as reader:
                    self.assertEqual(reader.read(3), b"fix")
                    self.assertEqual(reader.read(4), b"ture")
                    self.assertEqual(reader.read(1), b"")
        finally:
            if write_fd is not None:
                os.close(write_fd)

    def test_stalled_pipe_deadline(self):
        read_fd, write_fd = os.pipe()

        try:
            with os.fdopen(
                read_fd, "rb", buffering=0
            ) as stream:
                started = time.monotonic()

                with archive.DeadlinePipeReader(
                    stream,
                    started + 0.2,
                ) as reader:
                    with self.assertRaises(
                        archive.ArchiveError
                    ):
                        reader.read(1)

                self.assertLess(
                    time.monotonic() - started,
                    3,
                )
        finally:
            os.close(write_fd)


class DescriptorValidationTests(unittest.TestCase):

    def assert_rejected_without_descriptor_leak(
        self, operation, message
    ):
        real_open = os.open
        descriptors = []

        def record_open(*args, **kwargs):
            descriptor = real_open(*args, **kwargs)
            descriptors.append(descriptor)
            return descriptor

        with patch.object(
            archive.os, "open", side_effect=record_open
        ):
            with self.assertRaisesRegex(
                archive.ArchiveError, message
            ):
                operation()

        self.assertEqual(len(descriptors), 1)

        for descriptor in descriptors:
            with self.assertRaises(OSError) as error:
                os.fstat(descriptor)

            self.assertEqual(error.exception.errno, errno.EBADF)

    def test_directory_package_rejected_and_closed(self):
        with tempfile.TemporaryDirectory() as scratch:
            with patch.object(
                archive, "require_unprivileged"
            ):
                self.assert_rejected_without_descriptor_leak(
                    lambda: archive.inspect_package(scratch),
                    "Package input must be a regular file",
                )

    def test_fifo_package_rejected_and_closed(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "fifo"
            os.mkfifo(path)

            with patch.object(
                archive, "require_unprivileged"
            ):
                self.assert_rejected_without_descriptor_leak(
                    lambda: archive.inspect_package(path),
                    "Package input must be a regular file",
                )

    def test_empty_package_rejected_and_closed(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "empty"
            path.touch()

            with patch.object(
                archive, "require_unprivileged"
            ):
                self.assert_rejected_without_descriptor_leak(
                    lambda: archive.inspect_package(path),
                    "Compressed package size outside policy",
                )

    def test_directory_manifest_rejected_and_closed(self):
        with tempfile.TemporaryDirectory() as scratch:
            self.assert_rejected_without_descriptor_leak(
                lambda: archive.read_checksum_manifest(scratch),
                "Checksum manifest must be a regular file",
            )

    def test_fifo_manifest_rejected_and_closed(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "fifo"
            os.mkfifo(path)

            self.assert_rejected_without_descriptor_leak(
                lambda: archive.read_checksum_manifest(path),
                "Checksum manifest must be a regular file",
            )

    def test_empty_manifest_rejected_and_closed(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "empty"
            path.touch()

            self.assert_rejected_without_descriptor_leak(
                lambda: archive.read_checksum_manifest(path),
                "Checksum manifest size outside policy",
            )


class SelectedMemberTests(unittest.TestCase):

    def inspect_selected(self, data, requested):
        return archive.inspect_tar_stream(
            io.BytesIO(data),
            requested_members=requested,
        )

    def archive_with(self, *members):
        return (
            body()
            + b"".join(members)
            + b"\0" * 1024
        )

    def test_default_inventory_unchanged(self):
        data = self.archive_with()

        result = self.inspect_selected(data, ())

        self.assertEqual(result, inspect(data))
        self.assertNotIn("selected_members", result)

    def test_exact_selected_member_digest(self):
        import hashlib

        payload = b"license contents\n"

        result = self.inspect_selected(
            self.archive_with(
                member("usr/share/license", payload),
            ),
            ("usr/share/license",),
        )

        self.assertEqual(
            result["selected_members"],
            {
                "usr/share/license": {
                    "size": len(payload),
                    "sha256": hashlib.sha256(
                        payload
                    ).hexdigest(),
                },
            },
        )

    def test_multiple_selected_members(self):
        import hashlib

        payloads = {
            "usr/share/first": b"first",
            "usr/share/second": b"second",
        }

        result = self.inspect_selected(
            self.archive_with(
                *(
                    member(name, payload)
                    for name, payload in payloads.items()
                ),
                member("usr/share/unselected", b"ignored"),
            ),
            tuple(reversed(payloads)),
        )

        self.assertEqual(
            set(result["selected_members"]),
            set(payloads),
        )

        for name, payload in payloads.items():
            self.assertEqual(
                result["selected_members"][name]["sha256"],
                hashlib.sha256(payload).hexdigest(),
            )

    def test_empty_regular_member(self):
        import hashlib

        result = self.inspect_selected(
            self.archive_with(
                member("usr/share/empty", b""),
            ),
            ("usr/share/empty",),
        )

        self.assertEqual(
            result["selected_members"]["usr/share/empty"],
            {
                "size": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
            },
        )

    def test_multichunk_member_digest(self):
        import hashlib

        payload = b"x" * (archive.TAR_READ_CHUNK + 17)

        result = self.inspect_selected(
            self.archive_with(
                member("usr/share/large", payload),
            ),
            ("usr/share/large",),
        )

        self.assertEqual(
            result["selected_members"]["usr/share/large"],
            {
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            },
        )

    def test_missing_selected_member(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Missing selected archive members",
        ):
            self.inspect_selected(
                self.archive_with(),
                ("usr/share/missing",),
            )

    def test_duplicate_requests(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Duplicate selected member",
        ):
            self.inspect_selected(
                self.archive_with(),
                ("usr/bin/broot", "usr/bin/broot"),
            )

    def test_invalid_member_requests(self):
        for value in (
            "/usr/bin/broot",
            "./usr/bin/broot",
            "usr//bin/broot",
            "usr/bin/../broot",
            "usr/bin/broot/",
            ".",
            "",
            None,
            ".PKGINFO",
            ".BUILDINFO",
            ".MTREE",
        ):
            with self.subTest(value=value):
                with self.assertRaises(
                    archive.ArchiveError
                ):
                    self.inspect_selected(
                        self.archive_with(),
                        (value,),
                    )

    def test_invalid_request_collection(self):
        for value in (
            "usr/bin/broot",
            {"usr/bin/broot"},
            None,
            17,
        ):
            with self.subTest(value=value):
                with self.assertRaises(
                    archive.ArchiveError
                ):
                    self.inspect_selected(
                        self.archive_with(),
                        value,
                    )

    def test_selected_member_count_limit(self):
        requests = tuple(
            f"usr/share/member-{index}"
            for index in range(
                archive.MAX_SELECTED_MEMBERS + 1
            )
        )

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Selected member count exceeds policy",
        ):
            self.inspect_selected(
                self.archive_with(),
                requests,
            )

    def test_selected_directory_rejected(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Selected member is not regular",
        ):
            self.inspect_selected(
                self.archive_with(),
                ("usr/bin",),
            )

    def test_selected_symbolic_link_rejected(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Selected member is not regular",
        ):
            self.inspect_selected(
                self.archive_with(
                    member(
                        "usr/bin/alias",
                        kind=tarfile.SYMTYPE,
                        target="broot",
                    ),
                ),
                ("usr/bin/alias",),
            )

    def test_duplicate_archive_member_rejected(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Duplicate archive member",
        ):
            self.inspect_selected(
                self.archive_with(
                    member("usr/share/notice", b"one"),
                    member("usr/share/notice", b"two"),
                ),
                ("usr/share/notice",),
            )

    def test_invalid_trailing_archive_data(self):
        data = self.archive_with(
            member("usr/share/notice", b"valid payload"),
        ) + b"x" * 512

        with self.assertRaises(archive.ArchiveError):
            self.inspect_selected(
                data,
                ("usr/share/notice",),
            )

    def test_truncated_selected_payload(self):
        payload = member(
            "usr/share/notice",
            b"selected bytes",
        )

        data = body() + payload[:515]

        with self.assertRaises(archive.ArchiveError):
            self.inspect_selected(
                data,
                ("usr/share/notice",),
            )

    def test_selected_member_requires_expected_archive_digest(self):
        from unittest.mock import patch

        with (
            patch.object(
                archive,
                "require_unprivileged",
            ),
            patch.object(
                archive.os,
                "open",
            ) as opener,
        ):
            with self.assertRaisesRegex(
                archive.ArchiveError,
                "requires an expected archive digest",
            ):
                archive.inspect_package(
                    "/unused/package.pkg.tar.zst",
                    requested_members=("usr/bin/broot",),
                )

            opener.assert_not_called()

    def test_invalid_expected_digest_precedes_open(self):
        from unittest.mock import patch

        with (
            patch.object(
                archive,
                "require_unprivileged",
            ),
            patch.object(
                archive.os,
                "open",
            ) as opener,
        ):
            with self.assertRaisesRegex(
                archive.ArchiveError,
                "Invalid expected package digest",
            ):
                archive.inspect_package(
                    "/unused/package.pkg.tar.zst",
                    expected_sha256="invalid",
                )

            opener.assert_not_called()

    def test_digest_mismatch_precedes_decompression(self):
        import tempfile

        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.pkg.tar.zst"
            path.write_bytes(b"not the expected bytes")

            with (
                patch.object(
                    archive,
                    "require_unprivileged",
                ),
                patch.object(
                    archive.subprocess,
                    "Popen",
                ) as decompressor,
            ):
                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "Package digest does not match protected intake",
                ):
                    archive.inspect_package(
                        path,
                        expected_sha256="0" * 64,
                        requested_members=("usr/bin/broot",),
                    )

                decompressor.assert_not_called()


class FamilyMemberSelectionTests(unittest.TestCase):

    def setUp(self):
        self.filename = "broot-1.0-1-x86_64.pkg.tar.zst"
        self.member = "usr/bin/broot"

        self.expected = {
            self.filename: "broot",
        }

        self.inventory = {
            "entries": {
                self.member: {
                    "type": "file",
                    "mode": 0o755,
                    "size": 5,
                },
            },
            "selected_members": {
                self.member: {
                    "size": 5,
                    "sha256": "a" * 64,
                },
            },
        }

    def test_default_family_member_requests(self):
        for requests in (None, {}):
            self.assertEqual(
                archive.validate_family_member_requests(
                    requests, self.expected
                ),
                {},
            )

    def test_exact_family_member_requests(self):
        requests = {
            self.filename: (
                "usr/share/license",
                self.member,
            ),
        }

        self.assertEqual(
            archive.validate_family_member_requests(
                requests, self.expected
            ),
            {
                self.filename: (
                    self.member,
                    "usr/share/license",
                ),
            },
        )

    def test_unknown_package_request(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "unexpected package",
        ):
            archive.validate_family_member_requests(
                {"unexpected.pkg.tar.zst": (self.member,)},
                self.expected,
            )

    def test_invalid_family_request_collection(self):
        for requests in ("invalid", [], 7):
            with self.subTest(requests=requests):
                with self.assertRaises(
                    archive.ArchiveError
                ):
                    archive.validate_family_member_requests(
                        requests, self.expected
                    )

    def test_empty_package_request(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Empty package member request",
        ):
            archive.validate_family_member_requests(
                {self.filename: ()},
                self.expected,
            )

    def test_invalid_member_path_in_family_request(self):
        with self.assertRaises(archive.ArchiveError):
            archive.validate_family_member_requests(
                {self.filename: ("../unsafe",)},
                self.expected,
            )

    def test_selected_result_identity(self):
        result = archive.validate_selected_member_results(
            self.inventory,
            (self.member,),
        )

        self.assertEqual(
            result,
            self.inventory["selected_members"],
        )

        self.assertIsNot(
            result[self.member],
            self.inventory["selected_members"][self.member],
        )

    def test_default_inventory_has_no_member_results(self):
        self.inventory.pop("selected_members")

        self.assertEqual(
            archive.validate_selected_member_results(
                self.inventory, ()
            ),
            {},
        )

    def test_unrequested_results_rejected(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Unexpected selected member results",
        ):
            archive.validate_selected_member_results(
                self.inventory, ()
            )

    def test_missing_selected_result_rejected(self):
        self.inventory["selected_members"] = {}

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "result inventory mismatch",
        ):
            archive.validate_selected_member_results(
                self.inventory, (self.member,)
            )

    def test_additional_selected_result_rejected(self):
        self.inventory["selected_members"]["extra"] = {
            "size": 5,
            "sha256": "b" * 64,
        }

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "result inventory mismatch",
        ):
            archive.validate_selected_member_results(
                self.inventory, (self.member,)
            )

    def test_selected_result_size_mismatch(self):
        self.inventory["selected_members"][self.member]["size"] = 6

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Invalid selected member identity",
        ):
            archive.validate_selected_member_results(
                self.inventory, (self.member,)
            )

    def test_selected_result_invalid_digest(self):
        self.inventory["selected_members"][self.member]["sha256"] = "invalid"

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Invalid selected member identity",
        ):
            archive.validate_selected_member_results(
                self.inventory, (self.member,)
            )

    def test_selected_result_nonregular_member(self):
        self.inventory["entries"][self.member]["type"] = "symlink"

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Invalid selected member record",
        ):
            archive.validate_selected_member_results(
                self.inventory, (self.member,)
            )

    def test_family_inspection_passes_expected_digest(self):
        from unittest.mock import Mock, patch

        registry = Mock()
        expected_digest = "a" * 64

        checksums = {
            self.filename: expected_digest,
        }

        package = Path("/protected") / self.filename

        with (
            patch.object(
                archive,
                "require_unprivileged",
            ),
            patch.object(
                archive,
                "expected_batch_names",
                return_value=self.expected,
            ),
            patch.object(
                archive,
                "inspect_package",
                return_value=self.inventory,
            ) as inspector,
            patch.object(
                archive,
                "validate_family_inventories",
                return_value={"verified": True},
            ) as validator,
        ):
            result = archive.inspect_family(
                "broot",
                "1.0-1",
                [package],
                checksums,
                registry=registry,
            )

            inspector.assert_called_once_with(
                package,
                expected_sha256=expected_digest,
                requested_members=(),
            )

            validator.assert_called_once_with(
                "broot",
                "1.0-1",
                {self.filename: self.inventory},
                checksums,
                registry=registry,
                requested_members={},
            )

        self.assertEqual(result, {"verified": True})

    def test_family_inspection_passes_member_requests(self):
        from unittest.mock import Mock, patch

        registry = Mock()

        checksums = {
            self.filename: "a" * 64,
        }

        requests = {
            self.filename: (self.member,),
        }

        package = Path("/protected") / self.filename

        with (
            patch.object(
                archive,
                "require_unprivileged",
            ),
            patch.object(
                archive,
                "expected_batch_names",
                return_value=self.expected,
            ),
            patch.object(
                archive,
                "inspect_package",
                return_value=self.inventory,
            ) as inspector,
            patch.object(
                archive,
                "validate_family_inventories",
            ) as validator,
        ):
            archive.inspect_family(
                "broot",
                "1.0-1",
                [package],
                checksums,
                registry=registry,
                requested_members=requests,
            )

            inspector.assert_called_once_with(
                package,
                expected_sha256=checksums[self.filename],
                requested_members=(self.member,),
            )

            validator.assert_called_once_with(
                "broot",
                "1.0-1",
                {self.filename: self.inventory},
                checksums,
                registry=registry,
                requested_members=requests,
            )

    def test_unknown_package_rejected_before_inspection(self):
        from unittest.mock import Mock, patch

        with (
            patch.object(
                archive,
                "require_unprivileged",
            ),
            patch.object(
                archive,
                "expected_batch_names",
                return_value=self.expected,
            ),
            patch.object(
                archive,
                "inspect_package",
            ) as inspector,
        ):
            with self.assertRaisesRegex(
                archive.ArchiveError,
                "unexpected package",
            ):
                archive.inspect_family(
                    "broot",
                    "1.0-1",
                    [Path("/protected") / self.filename],
                    {self.filename: "a" * 64},
                    registry=Mock(),
                    requested_members={
                        "unexpected.pkg.tar.zst": (
                            self.member,
                        ),
                    },
                )

            inspector.assert_not_called()


class MemberStreamingTests(unittest.TestCase):

    def setUp(self):
        import hashlib

        self.name = "usr/share/selected-executable"
        self.payload = b"candidate executable fixture\n"
        self.digest = hashlib.sha256(
            self.payload
        ).hexdigest()

        self.output = io.BytesIO()

    def archive_with(self, *members):
        return (
            body()
            + b"".join(members)
            + bytes(1024)
        )

    def valid_archive(self):
        return self.archive_with(
            member(self.name, self.payload)
        )

    def request(self):
        return (
            self.name,
            len(self.payload),
            self.digest,
            self.output,
        )

    def stream(self, data, transfer=None, requests=None):
        if transfer is None:
            transfer = self.request()

        if requests is None:
            requests = (self.name,)

        return archive.inspect_tar_stream(
            io.BytesIO(data),
            requested_members=requests,
            member_transfer=transfer,
        )

    def test_exact_streamed_bytes(self):
        result = self.stream(self.valid_archive())

        self.assertEqual(
            self.output.getvalue(),
            self.payload,
        )

        self.assertEqual(
            result["selected_members"],
            {
                self.name: {
                    "size": len(self.payload),
                    "sha256": self.digest,
                },
            },
        )

    def test_streaming_inventory_matches_hashing(self):
        data = self.valid_archive()

        ordinary = archive.inspect_tar_stream(
            io.BytesIO(data),
            requested_members=(self.name,),
        )

        self.assertEqual(
            self.stream(data),
            ordinary,
        )

    def test_only_requested_transfer_member_streamed(self):
        import hashlib

        other = "usr/share/other-member"
        other_payload = b"other selected bytes"

        result = self.stream(
            self.archive_with(
                member(other, other_payload),
                member(self.name, self.payload),
                member("usr/share/unselected", b"ignored"),
            ),
            requests=(other, self.name),
        )

        self.assertEqual(
            self.output.getvalue(),
            self.payload,
        )

        self.assertEqual(
            set(result["selected_members"]),
            {self.name, other},
        )

        self.assertEqual(
            result["selected_members"][other],
            {
                "size": len(other_payload),
                "sha256": hashlib.sha256(
                    other_payload
                ).hexdigest(),
            },
        )

    def test_multichunk_streaming(self):
        import hashlib

        class RecordingOutput(io.BytesIO):
            def __init__(self):
                super().__init__()
                self.lengths = []

            def write(self, data):
                self.lengths.append(len(data))
                return super().write(data)

        payload = b"x" * (archive.TAR_READ_CHUNK + 17)
        digest = hashlib.sha256(payload).hexdigest()
        output = RecordingOutput()

        result = self.stream(
            self.archive_with(
                member(self.name, payload)
            ),
            transfer=(
                self.name,
                len(payload),
                digest,
                output,
            ),
        )

        self.assertEqual(
            output.lengths,
            [archive.TAR_READ_CHUNK, 17],
        )

        self.assertEqual(output.getvalue(), payload)

        self.assertEqual(
            result["selected_members"][self.name],
            {
                "size": len(payload),
                "sha256": digest,
            },
        )

    def test_materialized_size_policy_boundary(self):
        limit = archive.MAX_MATERIALIZED_MEMBER_BYTES

        self.assertEqual(limit, 128 * 1024**2)

        request = (
            self.name,
            limit,
            self.digest,
            self.output,
        )

        self.assertEqual(
            archive.validate_member_transfer(
                request, {self.name}
            ),
            request,
        )

    def test_invalid_transfer_request_structure(self):
        for request in (
            [],
            [self.name, 1, self.digest, self.output],
            (),
            (self.name,),
            (self.name, 1, self.digest),
            17,
        ):
            with self.subTest(request=request):
                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "Invalid member transfer request",
                ):
                    self.stream(
                        self.valid_archive(),
                        transfer=request,
                    )

        self.assertEqual(self.output.getvalue(), b"")

    def test_transfer_member_must_be_selected(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "must be explicitly selected",
        ):
            self.stream(
                self.valid_archive(),
                requests=("usr/share/other",),
            )

        self.assertEqual(self.output.getvalue(), b"")

    def test_invalid_expected_member_sizes(self):
        for size in (
            0,
            -1,
            True,
            1.5,
            "17",
            archive.MAX_MATERIALIZED_MEMBER_BYTES + 1,
        ):
            with self.subTest(size=size):
                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "Materialized member size outside policy",
                ):
                    self.stream(
                        self.valid_archive(),
                        transfer=(
                            self.name,
                            size,
                            self.digest,
                            self.output,
                        ),
                    )

        self.assertEqual(self.output.getvalue(), b"")

    def test_invalid_expected_member_digests(self):
        for digest in (
            "",
            "invalid",
            "A" * 64,
            "a" * 63,
            "a" * 65,
            None,
            17,
        ):
            with self.subTest(digest=digest):
                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "Invalid expected member digest",
                ):
                    self.stream(
                        self.valid_archive(),
                        transfer=(
                            self.name,
                            len(self.payload),
                            digest,
                            self.output,
                        ),
                    )

        self.assertEqual(self.output.getvalue(), b"")

    def test_invalid_output_stream(self):
        for output in (
            None,
            17,
            "not a stream",
            object(),
        ):
            with self.subTest(output=output):
                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "Invalid member output stream",
                ):
                    self.stream(
                        self.valid_archive(),
                        transfer=(
                            self.name,
                            len(self.payload),
                            self.digest,
                            output,
                        ),
                    )

    def test_member_size_mismatch_precedes_output(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Materialized member size mismatch",
        ):
            self.stream(
                self.valid_archive(),
                transfer=(
                    self.name,
                    len(self.payload) + 1,
                    self.digest,
                    self.output,
                ),
            )

        self.assertEqual(self.output.getvalue(), b"")

    def test_empty_materialized_member_rejected(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Materialized member size mismatch",
        ):
            self.stream(
                self.archive_with(
                    member(self.name, b"")
                )
            )

        self.assertEqual(self.output.getvalue(), b"")

    def test_wrong_member_digest_rejects_provisional_bytes(self):
        wrong_digest = (
            "0" if self.digest[0] != "0" else "1"
        ) + self.digest[1:]

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Materialized member digest mismatch",
        ):
            self.stream(
                self.valid_archive(),
                transfer=(
                    self.name,
                    len(self.payload),
                    wrong_digest,
                    self.output,
                ),
            )

        # The receiver, not the parser, owns cleanup.
        self.assertEqual(
            self.output.getvalue(),
            self.payload,
        )

    def test_incomplete_output_write_rejected(self):
        class ShortOutput:
            def write(self, data):
                return len(data) - 1

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Incomplete selected member write",
        ):
            self.stream(
                self.valid_archive(),
                transfer=(
                    self.name,
                    len(self.payload),
                    self.digest,
                    ShortOutput(),
                ),
            )

    def test_invalid_output_write_results_rejected(self):
        class InvalidOutput:
            def __init__(self, result):
                self.result = result

            def write(self, data):
                return self.result

        for result in (
            None,
            True,
            -1,
            len(self.payload) + 1,
        ):
            with self.subTest(result=result):
                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "Incomplete selected member write",
                ):
                    self.stream(
                        self.valid_archive(),
                        transfer=(
                            self.name,
                            len(self.payload),
                            self.digest,
                            InvalidOutput(result),
                        ),
                    )

    def test_output_exception_propagates(self):
        class FailedOutput:
            def write(self, data):
                raise OSError("fixture write failure")

        with self.assertRaisesRegex(
            OSError,
            "fixture write failure",
        ):
            self.stream(
                self.valid_archive(),
                transfer=(
                    self.name,
                    len(self.payload),
                    self.digest,
                    FailedOutput(),
                ),
            )

    def test_truncated_member_payload_rejected(self):
        data = (
            body()
            + member(self.name, self.payload)[:515]
        )

        with self.assertRaises(
            archive.ArchiveError
        ):
            self.stream(data)

        self.assertEqual(self.output.getvalue(), b"")

    def test_missing_transfer_member_rejected(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Missing selected archive members",
        ):
            self.stream(self.archive_with())

        self.assertEqual(self.output.getvalue(), b"")

    def test_nonregular_transfer_members_rejected(self):
        cases = (
            member(
                self.name,
                kind=tarfile.DIRTYPE,
            ),
            member(
                self.name,
                kind=tarfile.SYMTYPE,
                target="other",
            ),
        )

        for entry in cases:
            with self.subTest(entry=entry[:100]):
                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "Selected member is not regular",
                ):
                    self.stream(
                        self.archive_with(entry)
                    )

        self.assertEqual(self.output.getvalue(), b"")

    def test_duplicate_after_streaming_rejected(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Duplicate archive member",
        ):
            self.stream(
                self.archive_with(
                    member(self.name, self.payload),
                    member(self.name, b"duplicate"),
                )
            )

        self.assertEqual(
            self.output.getvalue(),
            self.payload,
        )

    def test_invalid_trailing_data_after_streaming(self):
        with self.assertRaises(
            archive.ArchiveError
        ):
            self.stream(
                self.valid_archive() + b"x" * 512
            )

        self.assertEqual(
            self.output.getvalue(),
            self.payload,
        )

    def test_streaming_requires_expected_archive_digest(self):
        from unittest.mock import patch

        with (
            patch.object(
                archive,
                "require_unprivileged",
            ),
            patch.object(
                archive.os,
                "open",
            ) as opener,
        ):
            with self.assertRaisesRegex(
                archive.ArchiveError,
                "requires an expected archive digest",
            ):
                archive.inspect_package(
                    "/unused/package.pkg.tar.zst",
                    requested_members=(self.name,),
                    member_transfer=self.request(),
                )

            opener.assert_not_called()

        self.assertEqual(self.output.getvalue(), b"")

    def test_archive_digest_mismatch_precedes_streaming(self):
        import tempfile

        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.pkg.tar.zst"
            path.write_bytes(b"wrong archive bytes")

            with (
                patch.object(
                    archive,
                    "require_unprivileged",
                ),
                patch.object(
                    archive.subprocess,
                    "Popen",
                ) as decompressor,
            ):
                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "Package digest does not match protected intake",
                ):
                    archive.inspect_package(
                        path,
                        expected_sha256="0" * 64,
                        requested_members=(self.name,),
                        member_transfer=self.request(),
                    )

                decompressor.assert_not_called()

        self.assertEqual(self.output.getvalue(), b"")



class VerifiedMemberReaderTests(unittest.TestCase):

    def setUp(self):
        from unittest.mock import Mock

        class PrivilegeError(RuntimeError):
            pass

        self.privilege_error = PrivilegeError
        self.guard = Mock()

        self.member = "usr/bin/broot"
        self.payload = b"fixture"
        self.digest = hashlib.sha256(
            self.payload
        ).hexdigest()

        self.package = Path(
            "/protected/broot-1.0-1-x86_64.pkg.tar.zst"
        )

        self.output = Mock(spec=io.BytesIO)
        self.buffer = io.BytesIO()
        self.output.write.side_effect = self.buffer.write
        self.output.flush.side_effect = self.buffer.flush

        self.arguments = {
            "name": "broot",
            "version": VERSION,
            "architecture": "x86_64",
            "archive_sha256": DIGEST,
            "member": self.member,
            "member_size": len(self.payload),
            "member_sha256": self.digest,
            "output": self.output,
        }

        self.basic_guard = self.enterContext(
            patch.object(
                archive,
                "require_unprivileged",
            )
        )

        self.guard_loader = self.enterContext(
            patch.object(
                archive,
                "load_member_privilege_guard",
                return_value={
                    "PrivilegeError": PrivilegeError,
                    "require_inspection_identity": self.guard,
                },
            )
        )

        self.inspector = self.enterContext(
            patch.object(
                archive,
                "inspect_package",
                side_effect=self.inspect_fixture,
            )
        )

    def inspect_fixture(
        self,
        package,
        *,
        expected_sha256,
        requested_members,
        member_transfer,
    ):
        result = archive.inspect_tar_stream(
            io.BytesIO(body() + ZERO * 2),
            requested_members=requested_members,
            member_transfer=member_transfer,
        )

        result.update({
            "package": package.name,
            "sha256": DIGEST,
            "compressed_bytes": 1024,
        })

        return result

    def read(self, package=None, **overrides):
        arguments = dict(self.arguments)
        arguments.update(overrides)

        if package is None:
            package = self.package

        return archive.stream_verified_member(
            package,
            **arguments,
        )

    def assert_no_inspection(self):
        self.inspector.assert_not_called()
        self.output.write.assert_not_called()
        self.output.flush.assert_not_called()

    def test_exact_verified_member_result(self):
        result = self.read()

        self.basic_guard.assert_called_once_with()
        self.guard_loader.assert_called_once_with()
        self.guard.assert_called_once_with()

        self.inspector.assert_called_once_with(
            self.package,
            expected_sha256=DIGEST,
            requested_members=(self.member,),
            member_transfer=(
                self.member,
                len(self.payload),
                self.digest,
                self.output,
            ),
        )

        self.assertEqual(
            self.buffer.getvalue(),
            self.payload,
        )

        self.output.flush.assert_called_once_with()

        self.assertEqual(
            result,
            {
                "identity": {
                    "pkgname": "broot",
                    "pkgver": VERSION,
                    "arch": "x86_64",
                    "filename": self.package.name,
                    "sha256": DIGEST,
                },
                "selected_members": {
                    self.member: {
                        "size": len(self.payload),
                        "sha256": self.digest,
                    },
                },
            },
        )

    def test_basic_privilege_rejection_precedes_guard_loading(self):
        self.basic_guard.side_effect = archive.ArchiveError(
            "Unprivileged identity required"
        )

        with self.assertRaises(archive.ArchiveError):
            self.read()

        self.guard_loader.assert_not_called()
        self.guard.assert_not_called()
        self.assert_no_inspection()

    def test_guard_loading_failure_precedes_inspection(self):
        self.guard_loader.side_effect = archive.ArchiveError(
            "Untrusted member privilege guard"
        )

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Untrusted member privilege guard",
        ):
            self.read()

        self.guard.assert_not_called()
        self.assert_no_inspection()

    def test_full_privilege_rejection_precedes_inspection(self):
        failure = self.privilege_error(
            "NoNewPrivs must be enabled"
        )

        self.guard.side_effect = failure

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "NoNewPrivs must be enabled",
        ) as caught:
            self.read()

        self.assertIs(
            caught.exception.__cause__,
            failure,
        )

        self.assert_no_inspection()

    def test_unsafe_source_paths_rejected(self):
        filename = self.package.name

        paths = (
            filename,
            f"//protected/{filename}",
            f"/protected//{filename}",
            f"/protected/./{filename}",
            f"/protected/../{filename}",
            f"/protected/{filename}/",
            f"/protected/wrong-{filename}",
        )

        for package in paths:
            with self.subTest(package=package):
                with self.assertRaises(archive.ArchiveError):
                    self.read(package)

        self.assert_no_inspection()

    def test_invalid_expected_package_identity_rejected(self):
        cases = (
            {"name": "../broot"},
            {"name": ""},
            {"version": "../1.0-1"},
            {"version": ""},
            {"architecture": "aarch64"},
            {"architecture": ""},
            {"archive_sha256": None},
            {"archive_sha256": "a" * 63},
            {"archive_sha256": "G" * 64},
        )

        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(archive.ArchiveError):
                    self.read(**overrides)

        self.assert_no_inspection()

    def test_invalid_member_identity_rejected(self):
        cases = (
            {"member": "../broot"},
            {"member": "/usr/bin/broot"},
            {"member": "./usr/bin/broot"},
            {"member": ".PKGINFO"},
            {"member": ""},
            {"member_size": 0},
            {"member_size": -1},
            {"member_size": True},
            {"member_size": 1.5},
            {
                "member_size":
                    archive.MAX_MATERIALIZED_MEMBER_BYTES + 1
            },
            {"member_sha256": None},
            {"member_sha256": "a" * 63},
            {"member_sha256": "G" * 64},
        )

        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(archive.ArchiveError):
                    self.read(**overrides)

        self.assert_no_inspection()

    def test_output_without_flush_rejected(self):
        class WriteOnly:
            def write(self, data):
                raise AssertionError("Unexpected output")

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Invalid member output flush operation",
        ):
            self.read(output=WriteOnly())

        self.assert_no_inspection()

    def test_archive_failure_does_not_flush_output(self):
        self.inspector.side_effect = archive.ArchiveError(
            "Package changed during inspection"
        )

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Package changed during inspection",
        ):
            self.read()

        self.output.flush.assert_not_called()

    def test_wrong_member_size_rejected_before_output(self):
        with self.assertRaises(archive.ArchiveError):
            self.read(member_size=len(self.payload) + 1)

        self.assertEqual(self.buffer.getvalue(), b"")
        self.output.flush.assert_not_called()

    def test_wrong_member_digest_invalidates_output(self):
        with self.assertRaises(archive.ArchiveError):
            self.read(member_sha256="0" * 64)

        self.output.flush.assert_not_called()

    def test_late_archive_failure_invalidates_provisional_bytes(self):
        def inspect_and_fail(*args, **kwargs):
            self.inspect_fixture(*args, **kwargs)

            raise archive.ArchiveError(
                "Package changed during inspection"
            )

        self.inspector.side_effect = inspect_and_fail

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Package changed during inspection",
        ):
            self.read()

        self.assertEqual(
            self.buffer.getvalue(),
            self.payload,
        )

        self.output.flush.assert_not_called()

    def test_metadata_identity_mismatch_invalidates_output(self):
        def wrong_identity(*args, **kwargs):
            result = self.inspect_fixture(*args, **kwargs)

            result["metadata"][".PKGINFO"] = pkginfo(
                name="other"
            )

            return result

        self.inspector.side_effect = wrong_identity

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Package identity mismatch",
        ):
            self.read()

        self.assertEqual(
            self.buffer.getvalue(),
            self.payload,
        )

        self.output.flush.assert_not_called()

    def test_selected_result_mismatch_invalidates_output(self):
        def wrong_result(*args, **kwargs):
            result = self.inspect_fixture(*args, **kwargs)

            result["selected_members"][self.member]["sha256"] = (
                "0" * 64
            )

            return result

        self.inspector.side_effect = wrong_result

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Verified member result differs from expected identity",
        ):
            self.read()

        self.assertEqual(
            self.buffer.getvalue(),
            self.payload,
        )

        self.output.flush.assert_not_called()

    def test_missing_selected_result_invalidates_output(self):
        def missing_result(*args, **kwargs):
            result = self.inspect_fixture(*args, **kwargs)
            del result["selected_members"]
            return result

        self.inspector.side_effect = missing_result

        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Selected member result inventory mismatch",
        ):
            self.read()

        self.output.flush.assert_not_called()

    def test_output_flush_failure_propagates(self):
        self.output.flush.side_effect = OSError(
            "Output flush failed"
        )

        with self.assertRaisesRegex(
            OSError,
            "Output flush failed",
        ):
            self.read()

        self.assertEqual(
            self.buffer.getvalue(),
            self.payload,
        )

        self.output.flush.assert_called_once_with()


class FamilyMemberArgumentTests(unittest.TestCase):

    FILENAME = "broot-1.0-1-x86_64.pkg.tar.zst"
    DEBUG = "broot-debug-1.0-1-x86_64.pkg.tar.zst"

    def expected_names(self):
        return {
            self.FILENAME: "broot",
            self.DEBUG: "broot-debug",
        }

    def parse(self, arguments):
        return archive.parse_family_member_arguments(
            arguments,
            self.expected_names(),
        )

    def test_no_member_arguments_preserves_default(self):
        self.assertEqual(self.parse(None), {})
        self.assertEqual(self.parse([]), {})

    def test_exact_member_argument(self):
        self.assertEqual(
            self.parse([
                [self.FILENAME, "usr/bin/broot"],
            ]),
            {
                self.FILENAME: ("usr/bin/broot",),
            },
        )

    def test_multiple_members_sorted_per_archive(self):
        self.assertEqual(
            self.parse([
                [self.FILENAME, "usr/bin/z"],
                [self.DEBUG, "usr/lib/debug/fixture"],
                [self.FILENAME, "usr/bin/a"],
            ]),
            {
                self.FILENAME: (
                    "usr/bin/a",
                    "usr/bin/z",
                ),
                self.DEBUG: (
                    "usr/lib/debug/fixture",
                ),
            },
        )

    def test_duplicate_member_argument_rejected(self):
        with self.assertRaisesRegex(
            archive.ArchiveError,
            "Duplicate selected member argument",
        ):
            self.parse([
                [self.FILENAME, "usr/bin/broot"],
                [self.FILENAME, "usr/bin/broot"],
            ])

    def test_unexpected_archive_rejected(self):
        for filename in (
            "../" + self.FILENAME,
            "unexpected.pkg.tar.zst",
            "",
            None,
        ):
            with self.subTest(filename=filename):
                with self.assertRaisesRegex(
                    archive.ArchiveError,
                    "unexpected package",
                ):
                    self.parse([
                        [filename, "usr/bin/broot"],
                    ])

    def test_invalid_argument_pairs_rejected(self):
        for arguments in (
            {},
            "usr/bin/broot",
            [None],
            [[]],
            [[self.FILENAME]],
            [[self.FILENAME, "usr/bin/broot", "extra"]],
            [[self.FILENAME, None]],
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(
                    archive.ArchiveError
                ):
                    self.parse(arguments)

    def test_existing_member_path_policy_enforced(self):
        for member in (
            "",
            "/usr/bin/broot",
            "../usr/bin/broot",
            "usr/../bin/broot",
            "usr//bin/broot",
        ):
            with self.subTest(member=member):
                with self.assertRaises(
                    archive.ArchiveError
                ):
                    self.parse([
                        [self.FILENAME, member],
                    ])

    def test_family_cli_forwards_exact_requests(self):
        arguments = [
            "candidate_archive.py",
            "validate-family",
            "--family=broot",
            "--version=1.0-1",
            "--checksums=/protected/checksums",
            "--package=/protected/" + self.FILENAME,
            "--select-member",
            self.FILENAME,
            "usr/bin/broot",
        ]

        checksums = {
            self.FILENAME: "a" * 64,
        }

        class Registry:
            def output_contract(self, family):
                return object()

        registry = Registry()

        import contextlib

        with (
            patch.object(sys, "argv", arguments),
            patch.object(
                archive, "require_unprivileged"
            ),
            patch.object(
                archive,
                "load_release_registry",
                return_value=registry,
            ),
            patch.object(
                archive,
                "read_checksum_manifest",
                return_value=checksums,
            ),
            patch.object(
                archive,
                "expected_batch_names",
                return_value={
                    self.FILENAME: "broot",
                },
            ),
            patch.object(
                archive,
                "inspect_family",
                return_value={"schema": 1},
            ) as inspector,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(archive.main(), 0)

        inspector.assert_called_once_with(
            "broot",
            "1.0-1",
            ["/protected/" + self.FILENAME],
            checksums,
            registry=registry,
            requested_members={
                self.FILENAME: ("usr/bin/broot",),
            },
        )


class RestrictedFamilyReceiptTests(unittest.TestCase):

    def fixture(self):
        return {
            "schema": 1,
            "family": "broot",
            "version": "1.0-1",
            "architecture": "x86_64",
            "structural_and_identity_validation": True,
            "packages": {
                "broot": {
                    "identity": {
                        "pkgname": "broot",
                        "pkgver": "1.0-1",
                        "arch": "x86_64",
                        "filename":
                            "broot-1.0-1-x86_64.pkg.tar.zst",
                        "sha256": "a" * 64,
                    },
                    "entries": {
                        "usr/bin/broot": {
                            "type": "file",
                            "size": 4096,
                        },
                        "usr/share/doc/fixture": {
                            "type": "file",
                            "size": 1024,
                        },
                    },
                    "selected_members": {
                        "usr/bin/broot": {
                            "size": 4096,
                            "sha256": "b" * 64,
                        },
                    },
                    "symbolic_links": {},
                    "member_count": 2,
                    "compressed_bytes": 1024,
                    "expanded_bytes": 8192,
                    "symlink_count": 0,
                },
            },
        }

    def test_compact_receipt_preserves_exact_member_evidence(self):
        original = self.fixture()

        result = archive.compact_family_receipt(
            original
        )

        package = result["packages"]["broot"]

        self.assertEqual(
            set(package),
            {"identity", "entries", "selected_members"},
        )

        self.assertEqual(
            package["identity"],
            original["packages"]["broot"]["identity"],
        )

        self.assertEqual(
            package["selected_members"],
            original["packages"]["broot"]["selected_members"],
        )

        self.assertEqual(
            package["entries"],
            {
                "usr/bin/broot": {
                    "type": "file",
                    "size": 4096,
                },
            },
        )

        self.assertEqual(
            len(original["packages"]["broot"]["entries"]),
            2,
        )

    def test_unselected_package_preserves_only_identity(self):
        original = self.fixture()

        package = original["packages"]["broot"]

        del package["selected_members"]

        result = archive.compact_family_receipt(
            original
        )

        self.assertEqual(
            result["packages"]["broot"],
            {"identity": package["identity"]},
        )

    def test_invalid_validation_marker_rejected(self):
        for marker in (False, None, 1, "true"):
            with self.subTest(marker=marker):
                original = self.fixture()

                original[
                    "structural_and_identity_validation"
                ] = marker

                with self.assertRaises(
                    archive.ArchiveError
                ):
                    archive.compact_family_receipt(
                        original
                    )

    def test_invalid_selected_member_rejected(self):
        for field, value in (
            ("size", 4097),
            ("size", True),
            ("sha256", "invalid"),
        ):
            with self.subTest(field=field):
                original = self.fixture()

                original["packages"]["broot"][
                    "selected_members"
                ]["usr/bin/broot"][field] = value

                with self.assertRaises(
                    archive.ArchiveError
                ):
                    archive.compact_family_receipt(
                        original
                    )

    def test_nonregular_selected_member_rejected(self):
        original = self.fixture()

        original["packages"]["broot"][
            "entries"
        ]["usr/bin/broot"]["type"] = "symlink"

        with self.assertRaises(
            archive.ArchiveError
        ):
            archive.compact_family_receipt(original)

    def test_compact_json_receipt_framing(self):
        import json

        original = self.fixture()

        encoded = (
            archive.encode_restricted_family_receipt(
                original
            )
        )

        self.assertEqual(encoded.count("\n"), 1)
        self.assertTrue(encoded.endswith("\n"))
        self.assertNotIn("\r", encoded)

        encoded.encode("ascii")

        self.assertEqual(
            json.loads(encoded),
            archive.compact_family_receipt(original),
        )

    def test_receipt_size_limit(self):
        original = self.fixture()

        with patch.object(
            archive,
            "MAX_RESTRICTED_FAMILY_RECEIPT_BYTES",
            10,
        ):
            with self.assertRaisesRegex(
                archive.ArchiveError,
                "receipt exceeds size policy",
            ):
                archive.encode_restricted_family_receipt(
                    original
                )

    def test_restricted_identity_calls_complete_guard(self):
        calls = []

        def unprivileged():
            calls.append("unprivileged")

        def guard():
            calls.append("complete-guard")

        class PrivilegeError(RuntimeError):
            pass

        with (
            patch.object(
                archive,
                "require_unprivileged",
                side_effect=unprivileged,
            ),
            patch.object(
                archive,
                "load_member_privilege_guard",
                return_value={
                    "require_inspection_identity": guard,
                    "PrivilegeError": PrivilegeError,
                },
            ),
        ):
            archive.require_restricted_family_identity()

        self.assertEqual(
            calls,
            ["unprivileged", "complete-guard"],
        )

    def test_incomplete_privilege_identity_rejected(self):
        class PrivilegeError(RuntimeError):
            pass

        def reject():
            raise PrivilegeError(
                "Synthetic incomplete privilege identity"
            )

        with (
            patch.object(
                archive,
                "require_unprivileged",
            ),
            patch.object(
                archive,
                "load_member_privilege_guard",
                return_value={
                    "require_inspection_identity": reject,
                    "PrivilegeError": PrivilegeError,
                },
            ),
        ):
            with self.assertRaisesRegex(
                archive.ArchiveError,
                "Synthetic incomplete privilege identity",
            ):
                archive.require_restricted_family_identity()

    def cli_arguments(self):
        return [
            "candidate_archive.py",
            "validate-family",
            "--family=broot",
            "--version=1.0-1",
            "--checksums=/protected/checksums",
            "--package=/protected/broot-1.0-1-x86_64.pkg.tar.zst",
            "--restricted-receipt",
        ]

    def test_cli_guard_failure_prevents_archive_inspection(self):
        import contextlib

        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch.object(
                sys, "argv", self.cli_arguments()
            ),
            patch.object(
                archive, "require_unprivileged"
            ),
            patch.object(
                archive,
                "require_restricted_family_identity",
                side_effect=archive.ArchiveError(
                    "Synthetic restricted identity failure"
                ),
            ),
            patch.object(
                archive,
                "load_release_registry",
            ) as registry,
            patch.object(
                archive,
                "inspect_family",
            ) as inspector,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(archive.main(), 1)

        registry.assert_not_called()
        inspector.assert_not_called()

        self.assertEqual(stdout.getvalue(), "")

        self.assertIn(
            "Synthetic restricted identity failure",
            stderr.getvalue(),
        )

    def test_cli_emits_compact_receipt_after_inspection(self):
        import contextlib
        import json

        stdout = io.StringIO()
        stderr = io.StringIO()

        original = self.fixture()

        with (
            patch.object(
                sys, "argv", self.cli_arguments()
            ),
            patch.object(
                archive, "require_unprivileged"
            ),
            patch.object(
                archive,
                "require_restricted_family_identity",
            ) as guard,
            patch.object(
                archive,
                "load_release_registry",
            ),
            patch.object(
                archive,
                "read_checksum_manifest",
                return_value={
                    "broot-1.0-1-x86_64.pkg.tar.zst":
                        "a" * 64,
                },
            ),
            patch.object(
                archive,
                "inspect_family",
                return_value=original,
            ) as inspector,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(archive.main(), 0)

        guard.assert_called_once_with()
        inspector.assert_called_once()

        self.assertEqual(stderr.getvalue(), "")

        self.assertEqual(
            stdout.getvalue().count("\n"),
            1,
        )

        self.assertEqual(
            json.loads(stdout.getvalue()),
            archive.compact_family_receipt(original),
        )


if __name__ == "__main__":
    unittest.main()
