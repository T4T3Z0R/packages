import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

import select_package_validation as selector


def manifest(ref="v1.4.0", approved=True):
    return {
        "packages": {
            "ghostty": {
                "source_ref": ref,
                "release_policy": "stable-tag",
                "recipe": "arch/ghostty/PKGBUILD",
                "status": "approved" if approved else "candidate",
                "auto_publish": False,
            },
            "keepassxc": {
                "source_ref": "2.8.0",
                "release_policy": "stable-tag",
                "recipe": "arch/keepassxc/PKGBUILD",
                "status": "approved",
                "auto_publish": False,
            },
        }
    }


class SelectionTests(unittest.TestCase):
    def test_unrelated_change_selects_nothing(self):
        m = manifest()
        self.assertEqual(
            selector.select(
                m, m, {"README.md", "scripts/other.py"}
            ), []
        )

    def test_one_source_change(self):
        self.assertEqual(
            selector.select(
                manifest(),
                manifest("v1.4.1"),
                {"arch/packages/manifest.json"},
            ),
            ["ghostty"],
        )

    def test_one_recipe_change(self):
        m = manifest()
        self.assertEqual(
            selector.select(
                m, m, {"arch/keepassxc/PKGBUILD"}
            ),
            ["keepassxc"],
        )

    def test_one_workflow_change(self):
        m = manifest()
        self.assertEqual(
            selector.select(
                m, m,
                {".github/workflows/publish-ghostty.yml"},
            ),
            ["ghostty"],
        )

    def test_multiple_packages(self):
        m = manifest()
        self.assertEqual(
            selector.select(
                m, m,
                {
                    "arch/ghostty/PKGBUILD",
                    "arch/keepassxc/botan.patch",
                },
            ),
            ["ghostty", "keepassxc"],
        )

    def test_unapproved_excluded(self):
        m = manifest(approved=False)
        self.assertEqual(
            selector.select(
                m, m, {"arch/ghostty/PKGBUILD"}
            ),
            [],
        )

    def test_unapproved_becomes_approved(self):
        self.assertEqual(
            selector.select(
                manifest(approved=False),
                manifest(approved=True),
                {"arch/packages/manifest.json"},
            ),
            ["ghostty"],
        )

    def test_automatic_publication_rejected(self):
        m = manifest()
        m["packages"]["ghostty"]["auto_publish"] = True
        with self.assertRaises(ValueError):
            selector.select(
                manifest(), m,
                {"arch/ghostty/PKGBUILD"},
            )

    def test_git_tree_comparison_including_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", str(root), *args],
                    stderr=subprocess.PIPE,
                ).decode().strip()

            git("init", "-q")
            git("config", "user.name", "Package Test")
            git("config", "user.email", "test@example.invalid")

            path = root / "arch/packages/manifest.json"
            path.parent.mkdir(parents=True)

            def commit(ref, message):
                path.write_text(json.dumps(manifest(ref)))
                git("add", ".")
                git("commit", "-qm", message)
                return git("rev-parse", "HEAD")

            base = commit("v1.4.0", "base")
            newer = commit("v1.4.1", "update")

            self.assertEqual(
                selector.select_revisions(
                    root, base, newer
                ),
                ["ghostty"],
            )

            # A rewritten tip whose final tree matches the
            # original must not request another build.
            git("reset", "--hard", base)
            git("commit", "--allow-empty", "-qm", "equivalent")
            equivalent = git("rev-parse", "HEAD")
            self.assertNotEqual(base, equivalent)
            self.assertEqual(
                git("rev-parse", f"{base}^{{tree}}"),
                git("rev-parse", f"{equivalent}^{{tree}}"),
            )
            self.assertEqual(
                selector.select_revisions(
                    root, base, equivalent
                ),
                [],
            )

            # Compare complete trees, including a non-ancestor
            # previous tip after a force-push.
            self.assertEqual(
                selector.select_revisions(
                    root, newer, equivalent
                ),
                ["ghostty"],
            )


if __name__ == "__main__":
    unittest.main()
