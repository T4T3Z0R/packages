"""Portable regression coverage for candidate archive inspection."""

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


if __name__ == "__main__":
    unittest.main()
