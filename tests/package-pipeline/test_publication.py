"""Offline publication contract tests: the gh executable is always a local stub."""
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/package-pipeline/publish-repository.sh"
PACKAGE = "yazi-2.0-1-any.pkg.tar.zst"
ASSETS = (
    PACKAGE, PACKAGE + ".sig", "t4t3z0r-package-signing.asc",
    "SHA256SUMS", "t4t3z0r.files", "t4t3z0r.files.sig",
    "t4t3z0r.db", "t4t3z0r.db.sig",
)

MOCK_GH = """#!/usr/bin/env python3
import os
import sys
from pathlib import Path
args = sys.argv[1:]
if args[:2] == ["release", "view"]:
    operation = "inventory" if "--json" in args else "lookup"
elif args[:2] == ["release", "upload"]:
    paths = [Path(a).name for a in args[3:] if a != "--clobber"]
    operation = "upload:" + ",".join(paths)
elif args[:2] == ["release", "delete-asset"]:
    operation = "delete:" + args[3]
else:
    operation = "unexpected"
with open(os.environ["TEST_GH_LOG"], "a", encoding="utf-8") as stream:
    stream.write(operation + "\\n")
fail = os.environ.get("TEST_FAIL_OP", "")
if fail and (operation == fail or operation.startswith(fail)):
    sys.exit(17)
if operation == "inventory":
    print("obsolete.pkg.tar.zst")
    omit = os.environ.get("TEST_OMIT_ASSET", "")
    for asset in os.environ["TEST_EXPECTED_ASSETS"].split(","):
        if asset != omit:
            print(asset)
    if os.environ.get("TEST_DUPLICATE_ASSET"):
        print(os.environ["TEST_DUPLICATE_ASSET"])
    if os.environ.get("TEST_EXTRA_ASSET"):
        print(os.environ["TEST_EXTRA_ASSET"])
if operation == "unexpected":
    sys.exit(98)
"""


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        output = self.root / "repo-output"
        output.mkdir()
        for name in ASSETS:
            (output / name).write_bytes(b"offline-fixture")
        checksum_lines = []
        for name in ASSETS:
            if name == "SHA256SUMS":
                continue
            digest = hashlib.sha256((output / name).read_bytes()).hexdigest()
            checksum_lines.append(f"{digest}  {name}")
        (output / "SHA256SUMS").write_text(chr(10).join(checksum_lines) + chr(10))
        (self.root / "archive-state.txt").write_text(
            "yazi" + chr(10) + PACKAGE + chr(10) + chr(10)
        )
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "gh"
        stub.write_text(MOCK_GH)
        stub.chmod(0o755)
        self.log = self.root / "gh.log"
        self.env = os.environ.copy()
        self.env.update({
            "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
            "RELEASE_TAG": "fixture-release",
            "PACKAGE_FILE": PACKAGE,
            "PACKAGE_NAME": "yazi",
            "GH_TOKEN": "offline-test-token",
            "GH_REPO": "fixture/offline",
            "TEST_GH_LOG": str(self.log),
            "TEST_EXPECTED_ASSETS": ",".join(ASSETS),
        })

    def execute(self, fail=None):
        env = self.env.copy()
        if fail:
            env["TEST_FAIL_OP"] = fail
        return subprocess.run(
            ["bash", str(SCRIPT)], cwd=self.root, env=env,
            text=True, capture_output=True,
        )

    def operations(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def setup_batch_publication(self):
        extra = "wezterm-debug-2.0-1-any.pkg.tar.zst"
        output = self.root / "repo-output"

        for name, filename in (
            ("yazi", PACKAGE),
            ("wezterm-debug", extra),
        ):
            build = self.root / "build" / name
            build.mkdir(parents=True)
            (build / ".PKGINFO").write_text(
                f"pkgname = {name}\n"
            )
            subprocess.run(
                ["bsdtar", "-c", "--zstd", "-f",
                 str(output / filename), ".PKGINFO"],
                cwd=build, check=True, capture_output=True,
            )

        (output / (extra + ".sig")).write_bytes(b"test-signature")

        lines = [
            f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}"
            for f in sorted(output.iterdir())
            if f.name != "SHA256SUMS"
        ]
        (output / "SHA256SUMS").write_text(
            "\n".join(lines) + "\n"
        )

        (self.root / "archive-state.txt").write_text(
            "\n".join((
                "batch-v2",
                "yazi", PACKAGE, "",
                "wezterm-debug", extra, "",
            )) + "\n"
        )

        self.env["ADDITIONAL_PACKAGE_FILES"] = extra
        self.env["TEST_EXPECTED_ASSETS"] = ",".join(
            ASSETS + (extra, extra + ".sig")
        )
        return extra

    def test_batch_upload_order(self):
        extra = self.setup_batch_publication()
        result = self.execute()

        self.assertEqual(
            result.returncode, 0, result.stderr + result.stdout
        )

        ops = self.operations()
        self.assertEqual(ops[0], "lookup")
        self.assertEqual(
            ops[1],
            "upload:" + ",".join((
                PACKAGE, PACKAGE + ".sig",
                extra, extra + ".sig",
            )),
        )
        self.assertTrue(ops[2].startswith("upload:"))
        self.assertEqual(
            ops[3], "upload:t4t3z0r.db,t4t3z0r.db.sig"
        )

    def test_batch_missing_debug_signature(self):
        extra = self.setup_batch_publication()
        (self.root / "repo-output" / (extra + ".sig")).unlink()

        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.operations(), [])

    def test_batch_identity_mismatch(self):
        self.setup_batch_publication()
        state = self.root / "archive-state.txt"
        state.write_text(
            state.read_text().replace(
                "wezterm-debug\n", "wrong-name\n", 1
            )
        )

        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("metadata mismatch", result.stderr)
        self.assertEqual(self.operations(), [])

    def test_batch_upload_failure_stops_database(self):
        self.setup_batch_publication()
        result = self.execute("upload")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            [op.split(":")[0] for op in self.operations()],
            ["lookup", "upload"],
        )

    def test_batch_second_archive_failure_blocks_live_release(self):
        extra = self.setup_batch_publication()

        old_main = "yazi-1.0-1-any.pkg.tar.zst"
        old_debug = "wezterm-debug-1.0-1-any.pkg.tar.zst"

        archive = self.root / "archive-output"
        archive.mkdir()

        for old in (old_main, old_debug):
            (archive / old).write_bytes(b"fixture-package")
            (archive / (old + ".sig")).write_bytes(b"fixture-signature")

        (self.root / "archive-state.txt").write_text(
            "\n".join((
                "batch-v2",
                "yazi", PACKAGE, old_main,
                "wezterm-debug", extra, old_debug,
            )) + "\n"
        )

        # First archive gate succeeds; second fails.
        shim = self.root / "bin" / "python3"
        shim.write_text(
            '#!/usr/bin/env bash\n'
            'if [[ "${1:-}" == */publication-archive-gate.py ]]; then\n'
            '  printf "%s\\n" "$*" >> "$TEST_GATE_LOG"\n'
            '  case " $* " in\n'
            '    *" --package wezterm-debug "*) exit 17 ;;\n'
            '  esac\n'
            '  printf "%s\\n" \'{"gate_passed":true}\'\n'
            '  exit 0\n'
            'fi\n'
            'exec "$TEST_REAL_PYTHON" "$@"\n'
        )
        shim.chmod(0o755)

        log = self.root / "archive-gates.log"
        self.env["TEST_GATE_LOG"] = str(log)
        self.env["TEST_REAL_PYTHON"] = sys.executable

        result = self.execute()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Archive authorization failed: wezterm-debug",
            result.stderr,
        )
        self.assertEqual(self.operations(), [])

        calls = log.read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertIn("--package yazi", calls[0])
        self.assertIn("--package wezterm-debug", calls[1])

    def test_batch_retry_after_failed_upload(self):
        self.setup_batch_publication()

        first = self.execute("upload")
        self.assertNotEqual(first.returncode, 0)

        self.assertEqual(
            [op.split(":")[0] for op in self.operations()],
            ["lookup", "upload"],
        )

        second = self.execute()
        self.assertEqual(
            second.returncode, 0,
            second.stderr + second.stdout,
        )

        ops = self.operations()
        retry_ops = ops[2:]

        self.assertEqual(retry_ops[0], "lookup")
        self.assertEqual(
            [op.split(":")[0] for op in retry_ops[1:4]],
            ["upload", "upload", "upload"],
        )
        self.assertEqual(retry_ops[4], "inventory")

    def test_batch_unexpected_archive_blocks_publication(self):
        self.setup_batch_publication()

        archive = self.root / "archive-output"
        archive.mkdir()
        (archive / "unexpected").write_bytes(b"unrelated-file")

        result = self.execute()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Unexpected batch archive staging",
            result.stderr,
        )
        self.assertEqual(self.operations(), [])

    def test_missing_assembly_state_blocks_github(self):
        (self.root / "archive-state.txt").unlink()

        result = self.execute()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing assembly state", result.stderr)
        self.assertEqual(self.operations(), [])

    def test_assembly_identity_mismatch_blocks_github(self):
        state = self.root / "archive-state.txt"
        state.write_text(
            "gameshell" + chr(10) + PACKAGE + chr(10) + chr(10)
        )

        result = self.execute()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Assembly identity mismatch", result.stderr)
        self.assertEqual(self.operations(), [])

    def test_missing_displaced_pair_blocks_github(self):
        old = "yazi-1.0-1-any.pkg.tar.zst"
        state = self.root / "archive-state.txt"
        state.write_text(
            "yazi" + chr(10) + PACKAGE + chr(10)
            + old + chr(10)
        )

        result = self.execute()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing displaced package", result.stderr)
        self.assertEqual(self.operations(), [])

    def test_extra_staged_asset_blocks_github(self):
        old = "yazi-1.0-1-any.pkg.tar.zst"
        archive = self.root / "archive-output"
        archive.mkdir()
        (archive / old).write_bytes(b"old package")
        (archive / (old + ".sig")).write_bytes(b"old signature")
        (archive / "unexpected.txt").write_bytes(b"extra")

        state = self.root / "archive-state.txt"
        state.write_text(
            "yazi" + chr(10) + PACKAGE + chr(10)
            + old + chr(10)
        )

        result = self.execute()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unexpected archive staging", result.stderr)
        self.assertEqual(self.operations(), [])

    def test_staging_without_displacement_blocks_github(self):
        archive = self.root / "archive-output"
        archive.mkdir()
        (archive / "stale-package").write_bytes(b"stale")

        result = self.execute()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unexpected archive staging", result.stderr)
        self.assertEqual(self.operations(), [])

    def install_gate_shim(self, mode):
        shim = self.root / "bin" / "python3"
        shim.write_text('#!/usr/bin/env bash\nif [[ "$1" == */publication-archive-gate.py ]]; then\n  case "$TEST_GATE_MODE" in\n    fail) exit 17 ;;\n    deny) echo "{\\"gate_passed\\":false}"; exit 0 ;;\n    invalid) echo not-json; exit 0 ;;\n  esac\nfi\nexec "$TEST_REAL_PYTHON" "$@"\n')
        shim.chmod(0o755)
        self.env["TEST_GATE_MODE"] = mode
        self.env["TEST_REAL_PYTHON"] = sys.executable

    def test_invalid_displaced_package_blocks_live_github(self):
        old = "yazi-1.0-1-any.pkg.tar.zst"
        archive = self.root / "archive-output"
        archive.mkdir()

        (archive / old).write_bytes(b"not a valid Arch package")
        (archive / (old + ".sig")).write_bytes(
            b"not a valid signature"
        )

        (self.root / "archive-state.txt").write_text(
            chr(10).join(("yazi", PACKAGE, old)) + chr(10)
        )
        self.env["SIGNING_SUBKEY"] = "A" * 40

        result = self.execute()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Archive authorization failed", result.stderr)
        self.assertEqual(self.operations(), [])

    def test_archive_gate_failure_blocks_live_github(self):
        self.install_gate_shim("fail")

        result = self.execute()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Archive authorization failed", result.stderr)
        self.assertEqual(self.operations(), [])

    def test_archive_gate_denial_blocks_live_github(self):
        self.install_gate_shim("deny")

        result = self.execute()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not confirm authorization", result.stderr)
        self.assertEqual(self.operations(), [])

    def test_invalid_archive_gate_response_blocks_live_github(self):
        self.install_gate_shim("invalid")

        result = self.execute()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.operations(), [])

    def test_corrupted_asset_stops_before_github(self):
        asset = self.root / "repo-output/t4t3z0r.db"
        asset.write_bytes(b"corrupted database")
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum verification failed", result.stderr)
        self.assertEqual(self.operations(), [])

    def test_unlisted_asset_stops_before_github(self):
        asset = self.root / "repo-output/extra.pkg.tar.zst"
        asset.write_bytes(b"unexpected package")
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest does not match", result.stderr)
        self.assertEqual(self.operations(), [])

    def test_missing_asset_stops_before_github(self):
        (self.root / "repo-output/t4t3z0r.db.sig").unlink()
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.operations(), [])

    def test_missing_credentials_stops_before_github(self):
        self.env.pop("GH_TOKEN")
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.operations(), [])

    def test_release_lookup_failure_stops_uploads(self):
        self.assertNotEqual(self.execute("lookup").returncode, 0)
        self.assertEqual(self.operations(), ["lookup"])

    def test_package_upload_failure_stops_metadata(self):
        self.assertNotEqual(self.execute("upload").returncode, 0)
        self.assertEqual(self.operations()[0], "lookup")
        self.assertEqual(len(self.operations()), 2)

    def test_supporting_upload_failure_stops_database(self):
        # Fail on the second upload only, by matching its first filename.
        self.assertNotEqual(self.execute("upload:t4t3z0r-package-signing.asc").returncode, 0)
        ops = self.operations()
        self.assertEqual([op.split(":")[0] for op in ops], ["lookup", "upload", "upload"])

    def test_database_upload_failure_prevents_cleanup(self):
        self.assertNotEqual(self.execute("upload:t4t3z0r.db").returncode, 0)
        ops = self.operations()
        self.assertEqual([op.split(":")[0] for op in ops], ["lookup", "upload", "upload", "upload"])

    def test_inventory_failure_prevents_cleanup(self):
        self.assertNotEqual(self.execute("inventory").returncode, 0)
        self.assertEqual(self.operations()[-1], "inventory")
        self.assertFalse(any(op.startswith("delete:") for op in self.operations()))

    def test_incomplete_inventory_prevents_cleanup(self):
        self.env["TEST_OMIT_ASSET"] = "t4t3z0r.db"
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Expected release asset missing", result.stderr)
        self.assertFalse(any(op.startswith("delete:") for op in self.operations()))

    def test_duplicate_inventory_prevents_cleanup(self):
        self.env["TEST_DUPLICATE_ASSET"] = PACKAGE
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Duplicate remote asset", result.stderr)
        self.assertFalse(any(op.startswith("delete:") for op in self.operations()))

    def test_unknown_metadata_prevents_cleanup(self):
        self.env["TEST_EXTRA_ASSET"] = "unexpected-metadata.json"
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unexpected non-package release asset", result.stderr)
        self.assertFalse(any(op.startswith("delete:") for op in self.operations()))

    def test_successful_upload_order_and_cleanup(self):
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        ops = self.operations()
        self.assertEqual(ops[0], "lookup")
        self.assertEqual(ops[1], "upload:" + PACKAGE + "," + PACKAGE + ".sig")
        self.assertEqual(ops[2], "upload:t4t3z0r-package-signing.asc,SHA256SUMS,t4t3z0r.files,t4t3z0r.files.sig")
        self.assertEqual(ops[3], "upload:t4t3z0r.db,t4t3z0r.db.sig")
        self.assertEqual(ops[4:], ["inventory", "delete:obsolete.pkg.tar.zst"])


if __name__ == "__main__":
    unittest.main()
