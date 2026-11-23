import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from candidate_issue_state import classify

PROPOSAL = {
    "title": "Package candidate: ghostty @ v1.5.0",
}


def issue(labels=None, state="open", number=42):
    return {
        "number": number,
        "title": PROPOSAL["title"],
        "state": state,
        "labels": labels if labels is not None else [],
    }


class CandidateIssueStateTests(unittest.TestCase):
    def check(self, issues):
        return classify(PROPOSAL, issues)

    def test_new_candidate(self):
        self.assertEqual(
            self.check([]),
            {"action": "create", "issue_number": None},
        )

    def test_existing_pending_review(self):
        self.assertEqual(
            self.check([issue()])["action"],
            "pending",
        )

    def test_approved(self):
        result = self.check([
            issue(["candidate:approved"])
        ])
        self.assertEqual(result["action"], "approved")

    def test_denied_closed_issue(self):
        result = self.check([
            issue(["candidate:denied"], "closed")
        ])
        self.assertEqual(result["action"], "denied")
        self.assertEqual(result["issue_number"], 42)

    def test_postponed(self):
        self.assertEqual(
            self.check([
                issue(["candidate:postponed"])
            ])["action"],
            "postponed",
        )

    def test_pinned(self):
        self.assertEqual(
            self.check([
                issue(["candidate:pinned"])
            ])["action"],
            "pinned",
        )

    def test_holds_apply_only_to_exact_candidate(self):
        next_candidate = {
            "title": "Package candidate: ghostty @ v1.6.0"
        }
        for label in ("candidate:postponed", "candidate:pinned"):
            with self.subTest(label=label):
                held = issue([label])
                self.assertEqual(
                    self.check([held])["action"],
                    label.removeprefix("candidate:"),
                )
                self.assertEqual(
                    classify(next_candidate, [held])["action"],
                    "create",
                )

    def test_removing_hold_restores_pending_review(self):
        self.assertEqual(
            self.check([issue(labels=[])])["action"],
            "pending",
        )

    def test_github_label_objects(self):
        self.assertEqual(
            self.check([
                issue([{"name": "candidate:denied"}])
            ])["action"],
            "denied",
        )

    def test_unrelated_issue_ignored(self):
        other = issue()
        other["title"] = "Something else"
        self.assertEqual(
            self.check([other])["action"],
            "create",
        )

    def test_duplicate_issues_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.check([issue(), issue(number=43)])

    def test_conflicting_decisions_rejected(self):
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            self.check([
                issue([
                    "candidate:approved",
                    "candidate:denied",
                ])
            ])

    def test_closed_without_decision_rejected(self):
        with self.assertRaises(ValueError):
            self.check([issue(state="closed")])

    def test_malformed_issue_rejected(self):
        with self.assertRaises(ValueError):
            self.check([{"title": PROPOSAL["title"]}])

    def test_incomplete_collection_rejected(self):
        with self.assertRaises(ValueError):
            self.check(None)

    def test_pr_collision_rejected(self):
        record = issue()
        record["pull_request"] = {"url": "example"}
        with self.assertRaises(ValueError):
            self.check([record])


if __name__ == "__main__":
    unittest.main()
