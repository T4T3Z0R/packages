import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))
SCRIPT = ROOT / "scripts/package-pipeline/discover_upstream.py"

spec = importlib.util.spec_from_file_location("upstream_discovery", SCRIPT)
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)


class DiscoveryTests(unittest.TestCase):
    def config(self, policy="stable-tag", ref="v2.1.7"):
        return {
            "upstream": "example/project",
            "release_policy": policy,
            "source_ref": ref,
        }

    def test_stable_release(self):
        calls = []

        def fetch(url):
            calls.append(url)
            return {
                "tag_name": "v2.1.8",
                "draft": False,
                "prerelease": False,
            }

        result = discovery.discover(
            "example", self.config(), fetch
        )
        self.assertEqual(result["candidate"], "v2.1.8")
        self.assertEqual(result["channel"], "stable-release")
        self.assertEqual(
            calls,
            ["https://api.github.com/repos/example/project/releases/latest"],
        )

    def test_stable_git_tags(self):
        calls = []

        def fetch(url):
            calls.append(url)
            return [
                {"ref": "refs/tags/v1.4.0"},
                {"ref": "refs/tags/v1.3.1"},
                {"ref": "refs/tags/vt-1.0.1"},
                {"ref": "refs/tags/v1.10.0"},
                {"ref": "refs/tags/v1.9.9"},
            ]

        result = discovery.discover(
            "ghostty",
            self.config("stable-git-tag", "v1.4.0"),
            fetch,
        )
        self.assertEqual(
            result["candidate"], "v1.10.0"
        )
        self.assertEqual(
            result["channel"], "stable-git-tag"
        )
        self.assertEqual(calls, [
            "https://api.github.com/repos/"
            "example/project/git/matching-refs/tags/v"
        ])

    def test_stable_git_tags_reject_empty(self):
        with self.assertRaises(ValueError):
            discovery.discover(
                "ghostty",
                self.config("stable-git-tag", "v1.4.0"),
                lambda url: [
                    {"ref": "refs/tags/vt-1.0.1"}
                ],
            )

    def test_stable_git_tags_reject_malformed(self):
        with self.assertRaises(ValueError):
            discovery.discover(
                "ghostty",
                self.config("stable-git-tag", "v1.4.0"),
                lambda url: [{"unexpected": "tag"}],
            )

    def test_reject_prerelease(self):
        with self.assertRaises(ValueError):
            discovery.discover(
                "example", self.config(),
                lambda url: {
                    "tag_name": "v2.1.8",
                    "prerelease": True,
                },
            )

    def test_reject_malformed_tag(self):
        with self.assertRaises(ValueError):
            discovery.discover(
                "example", self.config(),
                lambda url: {"tag_name": "release-latest"},
            )

    def test_development_default_branch(self):
        calls = []

        def fetch(url):
            calls.append(url)
            if url.endswith("/example/project"):
                return {"default_branch": "main"}
            return {"sha": "b" * 40}

        result = discovery.discover(
            "example",
            self.config("development-commit", "a" * 40),
            fetch,
        )
        self.assertEqual(result["candidate"], "b" * 40)
        self.assertEqual(
            calls[-1],
            "https://api.github.com/repos/example/project/commits/main",
        )

    def test_explicit_branch_tracking(self):
        config = self.config("reviewed-commit", "a" * 40)
        config["tracking_ref"] = "refs/heads/custom"
        calls = []

        def fetch(url):
            calls.append(url)
            return {
                "ref": "refs/heads/custom",
                "object": {"type": "commit", "sha": "b" * 40},
            }

        result = discovery.discover("custom", config, fetch)
        self.assertEqual(result["candidate"], "b" * 40)
        self.assertEqual(result["channel"], "tracked-ref")
        self.assertEqual(calls, [
            "https://api.github.com/repos/"
            "example/project/git/ref/heads/custom"
        ])

    def test_moving_tag_tracking(self):
        config = self.config("development-commit", "a" * 40)
        config["tracking_ref"] = "refs/tags/latest"

        result = discovery.discover(
            "gameshell", config,
            lambda url: {
                "ref": "refs/tags/latest",
                "object": {"type": "commit", "sha": "b" * 40},
            },
        )
        self.assertEqual(result["candidate"], "b" * 40)

    def test_noncommit_tracking_ref_fails_closed(self):
        config = self.config("development-commit", "a" * 40)
        config["tracking_ref"] = "refs/tags/latest"
        with self.assertRaises(ValueError):
            discovery.discover(
                "gameshell", config,
                lambda url: {
                    "ref": "refs/tags/latest",
                    "object": {"type": "tag", "sha": "b" * 40},
                },
            )

    def test_development_invalid_sha(self):
        def fetch(url):
            if url.endswith("/example/project"):
                return {"default_branch": "main"}
            return {"sha": "main"}

        with self.assertRaises(ValueError):
            discovery.discover(
                "example",
                self.config("development-commit", "a" * 40),
                fetch,
            )

    def test_pinned_tag_makes_no_requests(self):
        def forbidden(url):
            self.fail("Pinned package must not contact upstream")

        result = discovery.discover(
            "example",
            self.config("pinned-tag", "v2.1.7"),
            forbidden,
        )
        self.assertEqual(result["candidate"], "v2.1.7")
        self.assertEqual(result["channel"], "pinned")

    def test_pinned_commit_makes_no_requests(self):
        def forbidden(url):
            self.fail("Pinned package must not contact upstream")

        result = discovery.discover(
            "example",
            self.config("pinned-commit", "a" * 40),
            forbidden,
        )
        self.assertEqual(result["candidate"], "a" * 40)

    def test_unsupported_policy(self):
        with self.assertRaises(ValueError):
            discovery.discover(
                "example", self.config("automatic-chaos"),
                lambda url: {},
            )

    def test_invalid_repository(self):
        config = self.config()
        config["upstream"] = "../example"
        with self.assertRaises(ValueError):
            discovery.discover(
                "example", config, lambda url: {},
            )


if __name__ == "__main__":
    unittest.main()
