import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from candidate_review import plan


def candidate(package="ghostty", status="update"):
    return {
        "package": package,
        "status": status,
        "selected": "v1.4.0",
        "candidate": "v1.5.0",
    }


class CandidateReviewTests(unittest.TestCase):
    def test_update_creates_proposal(self):
        result = plan([candidate()])
        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["title"],
            "Package candidate: ghostty @ v1.5.0",
        )
        self.assertIn("Approve", result[0]["body"])
        self.assertIn("Deny", result[0]["body"])
        self.assertIn("Postpone", result[0]["body"])
        self.assertIn("Pin", result[0]["body"])
        self.assertIn(
            "<!-- t4t3z0r:candidate-alert:v1 -->",
            result[0]["body"],
        )

    def test_decisions_explain_candidate_scope(self):
        body = plan([candidate()])[0]["body"]
        self.assertIn("a different upstream candidate", body)
        self.assertIn("separately reviewed manifest change", body)

    def test_migrated_packages_registered(self):
        for name in (
            "gameshell",
            "noctalia-custom",
            "noctalia-greeter-t4t3z0r",
        ):
            with self.subTest(package=name):
                result = plan([candidate(package=name)])
                self.assertEqual(result[0]["package"], name)

    def test_unchanged_skipped(self):
        self.assertEqual(
            plan([candidate(status="unchanged")]), []
        )

    def test_blocked_skipped(self):
        self.assertEqual(
            plan([candidate(status="blocked")]), []
        )

    def test_multiple_updates(self):
        result = plan([
            candidate("ghostty"),
            candidate("syncthing"),
        ])
        self.assertEqual(len(result), 2)

    def test_duplicate_package_rejected(self):
        with self.assertRaises(ValueError):
            plan([candidate(), candidate()])

    def test_unknown_package_rejected(self):
        with self.assertRaises(ValueError):
            plan([candidate("moonlight-qt")])

    def test_unknown_status_rejected(self):
        with self.assertRaises(ValueError):
            plan([candidate(status="mystery")])

    def test_invalid_reference_rejected(self):
        item = candidate()
        item["candidate"] = "v1.5.0\nInjected"
        with self.assertRaises(ValueError):
            plan([item])

    def test_unchanged_update_rejected(self):
        item = candidate()
        item["candidate"] = item["selected"]
        with self.assertRaises(ValueError):
            plan([item])

    def test_invalid_report_rejected(self):
        with self.assertRaises(ValueError):
            plan({})

    def test_deterministic_proposal(self):
        self.assertEqual(
            plan([candidate()]),
            plan([candidate()]),
        )


if __name__ == "__main__":
    unittest.main()
