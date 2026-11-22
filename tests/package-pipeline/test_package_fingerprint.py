import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from package_fingerprint import fingerprint


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

        self.git("init", "-q")
        self.git("config", "user.name", "Package Test")
        self.git(
            "config", "user.email", "test@example.invalid"
        )

        self.manifest_path = (
            self.root / "arch/packages/manifest.json"
        )
        self.recipe_path = (
            self.root / "arch/ghostty/PKGBUILD"
        )
        self.workflow_path = (
            self.root / ".github/workflows/publish-ghostty.yml"
        )

        for path in (
            self.manifest_path,
            self.recipe_path,
            self.workflow_path,
        ):
            path.parent.mkdir(parents=True, exist_ok=True)

        self.config = {
            "source_ref": "v1.4.0",
            "release_policy": "stable-tag",
            "recipe": "arch/ghostty/PKGBUILD",
            "status": "approved",
            "auto_publish": False,
        }
        self.write_manifest()
        self.recipe_path.write_text("pkgver=1.4.0\n")
        self.workflow_path.write_text("name: Ghostty\n")

        self.base = self.commit("baseline")

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.root), *args],
            stderr=subprocess.PIPE,
        ).decode().strip()

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps({
            "packages": {"ghostty": self.config}
        }))

    def commit(self, message):
        self.git("add", ".")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def test_unrelated_commit_preserves_fingerprint(self):
        before = fingerprint(
            self.root, self.base, "ghostty"
        )
        (self.root / "README.md").write_text("documentation\n")
        after_commit = self.commit("documentation")
        self.assertEqual(
            before,
            fingerprint(
                self.root, after_commit, "ghostty"
            ),
        )

    def test_source_selection_changes_fingerprint(self):
        before = fingerprint(
            self.root, self.base, "ghostty"
        )
        self.config["source_ref"] = "v1.4.1"
        self.write_manifest()
        revision = self.commit("new source")
        self.assertNotEqual(
            before, fingerprint(self.root, revision, "ghostty")
        )

    def test_recipe_changes_fingerprint(self):
        before = fingerprint(
            self.root, self.base, "ghostty"
        )
        self.recipe_path.write_text("pkgver=1.4.1\n")
        revision = self.commit("new recipe")
        self.assertNotEqual(
            before, fingerprint(self.root, revision, "ghostty")
        )

    def test_workflow_changes_fingerprint(self):
        before = fingerprint(
            self.root, self.base, "ghostty"
        )
        self.workflow_path.write_text(
            "name: Ghostty\n# changed\n"
        )
        revision = self.commit("workflow update")
        self.assertNotEqual(
            before, fingerprint(self.root, revision, "ghostty")
        )

    def test_unapproved_package_rejected(self):
        self.config["status"] = "candidate"
        self.write_manifest()
        revision = self.commit("revoke approval")
        with self.assertRaises(ValueError):
            fingerprint(self.root, revision, "ghostty")

    def test_auto_publication_rejected(self):
        self.config["auto_publish"] = True
        self.write_manifest()
        revision = self.commit("unsafe manifest")
        with self.assertRaises(ValueError):
            fingerprint(self.root, revision, "ghostty")

    def test_unrecognized_package_rejected(self):
        with self.assertRaises(ValueError):
            fingerprint(self.root, self.base, "moonlight-qt")

    def test_missing_workflow_fails_closed(self):
        self.workflow_path.unlink()
        revision = self.commit("remove workflow")
        with self.assertRaises(
            subprocess.CalledProcessError
        ):
            fingerprint(self.root, revision, "ghostty")


if __name__ == "__main__":
    unittest.main()
