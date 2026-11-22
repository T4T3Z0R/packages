import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

import report_upstream


class UpstreamReportTests(unittest.TestCase):
    def config(self, policy, source, status="approved"):
        return {
            "upstream": "example/project",
            "release_policy": policy,
            "source_ref": source,
            "status": status,
            "auto_publish": False,
        }

    def test_unapproved_package_is_excluded(self):
        manifest = {
            "packages": {
                "yazi": self.config(
                    "stable-tag", "v26.9.1", "candidate"
                )
            }
        }

        def no_network(url):
            self.fail(f"Unexpected network call: {url}")

        self.assertEqual(
            report_upstream.report(manifest, fetch=no_network), []
        )

    def test_unchanged_stable_release(self):
        manifest = {
            "packages": {
                "ghostty": self.config("stable-tag", "v1.4.0")
            }
        }

        def fetch(url):
            return {
                "tag_name": "v1.4.0",
                "draft": False,
                "prerelease": False,
            }

        # No comparison is required for an identical source ref.
        result = report_upstream.report(
            manifest, fetch=fetch
        )
        self.assertEqual(result[0]["status"], "unchanged")

    def test_newer_stable_release(self):
        manifest = {
            "packages": {
                "ghostty": self.config("stable-tag", "v1.4.0")
            }
        }

        def fetch(url):
            return {
                "tag_name": "v1.4.1",
                "draft": False,
                "prerelease": False,
            }

        # Use the real Arch vercmp implementation in CI.
        result = report_upstream.report(
            manifest, fetch=fetch
        )

        self.assertEqual(result[0]["status"], "update")
        self.assertEqual(result[0]["candidate"], "v1.4.1")

    def test_newer_development_commit(self):
        old = "a" * 40
        new = "b" * 40
        manifest = {
            "packages": {
                "wezterm": self.config(
                    "development-commit", old
                )
            }
        }
        checked = []

        def fetch(url):
            if url.endswith("/example/project"):
                return {"default_branch": "main"}
            return {"sha": new}

        def ancestry(upstream, selected, candidate):
            checked.append((upstream, selected, candidate))
            return True

        result = report_upstream.report(
            manifest, fetch=fetch, ancestry_check=ancestry
        )

        self.assertEqual(result[0]["status"], "update")
        self.assertEqual(
            checked, [("example/project", old, new)]
        )

    def test_divergent_development_commit_is_blocked(self):
        manifest = {
            "packages": {
                "wezterm": self.config(
                    "development-commit", "a" * 40
                )
            }
        }

        def fetch(url):
            if url.endswith("/example/project"):
                return {"default_branch": "main"}
            return {"sha": "b" * 40}

        result = report_upstream.report(
            manifest,
            fetch=fetch,
            ancestry_check=lambda *args: False,
        )

        self.assertEqual(result[0]["status"], "blocked")

    def test_unchanged_commit_skips_ancestry(self):
        selected = "a" * 40
        manifest = {
            "packages": {
                "wezterm": self.config(
                    "development-commit", selected
                )
            }
        }

        def fetch(url):
            if url.endswith("/example/project"):
                return {"default_branch": "main"}
            return {"sha": selected}

        def no_git(*args):
            self.fail("Unchanged source fetched Git history")

        result = report_upstream.report(
            manifest, fetch=fetch, ancestry_check=no_git
        )
        self.assertEqual(result[0]["status"], "unchanged")

    def test_auto_publish_is_rejected(self):
        config = self.config("stable-tag", "v1.4.0")
        config["auto_publish"] = True
        with self.assertRaises(ValueError):
            report_upstream.report({
                "packages": {"ghostty": config}
            }, fetch=lambda url: None)


if __name__ == "__main__":
    unittest.main()
