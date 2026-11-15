"""Offline publication contract tests: the gh executable is always a local stub."""
import hashlib
import os
import subprocess
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
