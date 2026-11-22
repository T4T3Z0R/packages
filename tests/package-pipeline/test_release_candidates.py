import importlib.util
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/package-pipeline/resolve_candidate.py"

spec = importlib.util.spec_from_file_location(
    "release_candidates", SCRIPT
)
resolver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resolver)


def fake_compare(current, candidate):
    def parts(ref):
        return tuple(map(int, ref.removeprefix("v").split(".")))
    return (parts(current) > parts(candidate)) - (
        parts(current) < parts(candidate)
    )


class CandidateTests(unittest.TestCase):
    def decide(self, policy, old, new, ancestry=None):
        return resolver.decide(
            policy, old, new,
            compare=fake_compare,
            ancestry=ancestry,
        )

    def test_new_stable_release(self):
        result = self.decide(
            "stable-tag", "v2.1.7", "v2.1.8"
        )
        self.assertEqual(result["status"], "update")

    def test_equal_stable_release(self):
        result = self.decide(
            "stable-tag", "v2.1.7", "v2.1.7"
        )
        self.assertEqual(result["status"], "unchanged")

    def test_older_stable_release(self):
        result = self.decide(
            "stable-tag", "v2.1.7", "v2.1.6"
        )
        self.assertEqual(result["status"], "blocked")

    def test_pinned_tag_blocks_upgrade(self):
        result = self.decide(
            "pinned-tag", "v2.1.7", "v2.1.8"
        )
        self.assertEqual(result["reason"], "pinned")

    def test_pinned_tag_same_ref(self):
        result = self.decide(
            "pinned-tag", "v2.1.7", "v2.1.7"
        )
        self.assertEqual(result["status"], "unchanged")

    def test_pinned_commit_blocks_change(self):
        result = self.decide(
            "pinned-commit", "a" * 40, "b" * 40
        )
        self.assertEqual(result["status"], "blocked")

    def test_development_descendant(self):
        result = self.decide(
            "development-commit", "a" * 40, "b" * 40,
            ancestry=lambda old, new: True,
        )
        self.assertEqual(result["status"], "update")

    def test_development_divergence(self):
        result = self.decide(
            "development-commit", "a" * 40, "b" * 40,
            ancestry=lambda old, new: False,
        )
        self.assertEqual(result["status"], "blocked")

    def test_development_same_commit(self):
        result = self.decide(
            "development-commit", "a" * 40, "a" * 40
        )
        self.assertEqual(result["status"], "unchanged")

    def test_development_requires_ancestry(self):
        with self.assertRaises(ValueError):
            self.decide(
                "development-commit", "a" * 40, "b" * 40
            )

    def test_invalid_stable_ref(self):
        with self.assertRaises(ValueError):
            self.decide("stable-tag", "v2.1.7", "main")

    def test_invalid_commit_ref(self):
        with self.assertRaises(ValueError):
            self.decide(
                "development-commit", "a" * 40, "main"
            )

    def test_unknown_policy(self):
        with self.assertRaises(ValueError):
            self.decide("nightly-magic", "v1.0.0", "v1.1.0")

    @unittest.skipUnless(
        shutil.which("vercmp"), "vercmp requires Arch/pacman"
    )
    def test_real_arch_version_comparison(self):
        self.assertEqual(
            resolver.compare_versions("v2.1.7", "v2.1.8"), -1
        )
        self.assertEqual(
            resolver.compare_versions("v2.1.8", "v2.1.7"), 1
        )
        self.assertEqual(
            resolver.compare_versions("v2.1.7", "v2.1.7"), 0
        )


if __name__ == "__main__":
    unittest.main()
