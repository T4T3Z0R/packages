import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts/package-pipeline"
sys.path.insert(0, str(SCRIPTS))

spec = importlib.util.spec_from_file_location(
    "upstream_checker",
    SCRIPTS / "check_upstream.py",
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def compare(old, new):
    def version(ref):
        return tuple(map(int, ref[1:].split(".")))
    return (version(old) > version(new)) - (
        version(old) < version(new)
    )


class UpstreamCheckerTests(unittest.TestCase):
    def config(self, policy="stable-tag", ref="v2.1.7"):
        return {
            "upstream": "example/project",
            "release_policy": policy,
            "source_ref": ref,
        }

    def release(self, tag):
        return lambda url: {
            "tag_name": tag,
            "draft": False,
            "prerelease": False,
        }

    def test_new_stable_release(self):
        result = checker.check(
            "example", self.config(),
            fetch=self.release("v2.1.8"),
            compare=compare,
        )
        self.assertEqual(result["status"], "update")
        self.assertEqual(result["reason"], "newer-version")
        self.assertEqual(result["candidate"], "v2.1.8")

    def test_git_tag_uses_stable_version_comparison(self):
        result = checker.check(
            "ghostty",
            self.config("stable-git-tag", "v1.4.0"),
            fetch=lambda url: [
                {"ref": "refs/tags/v1.4.0"},
                {"ref": "refs/tags/v1.5.0"},
            ],
            compare=compare,
        )
        self.assertEqual(result["status"], "update")
        self.assertEqual(result["candidate"], "v1.5.0")

    def test_same_stable_release(self):
        result = checker.check(
            "example", self.config(),
            fetch=self.release("v2.1.7"),
            compare=compare,
        )
        self.assertEqual(result["status"], "unchanged")

    def test_older_release(self):
        result = checker.check(
            "example", self.config(),
            fetch=self.release("v2.1.6"),
            compare=compare,
        )
        self.assertEqual(result["status"], "blocked")

    def test_pinned_makes_no_network_requests(self):
        def forbidden(url):
            self.fail("Pinned package contacted upstream")

        result = checker.check(
            "example",
            self.config("pinned-tag", "v2.1.7"),
            fetch=forbidden,
        )
        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(result["channel"], "pinned")

    def test_development_descendant(self):
        def fetch(url):
            if url.endswith("/example/project"):
                return {"default_branch": "main"}
            return {"sha": "b" * 40}

        result = checker.check(
            "example",
            self.config("development-commit", "a" * 40),
            fetch=fetch,
            ancestry=lambda old, new: True,
        )
        self.assertEqual(result["status"], "update")

    def test_development_divergence(self):
        def fetch(url):
            if url.endswith("/example/project"):
                return {"default_branch": "main"}
            return {"sha": "b" * 40}

        result = checker.check(
            "example",
            self.config("development-commit", "a" * 40),
            fetch=fetch,
            ancestry=lambda old, new: False,
        )
        self.assertEqual(result["status"], "blocked")

    def test_development_requires_ancestry(self):
        def fetch(url):
            if url.endswith("/example/project"):
                return {"default_branch": "main"}
            return {"sha": "b" * 40}

        with self.assertRaises(ValueError):
            checker.check(
                "example",
                self.config("development-commit", "a" * 40),
                fetch=fetch,
            )

    def test_invalid_upstream_release(self):
        with self.assertRaises(ValueError):
            checker.check(
                "example", self.config(),
                fetch=self.release("latest"),
                compare=compare,
            )


if __name__ == "__main__":
    unittest.main()
