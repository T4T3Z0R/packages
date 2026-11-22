import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from github_candidate_issues import (
    evaluate_proposals,
    issue_history,
)


def issue(number, title="Package candidate: ghostty @ v1.5.0",
          labels=None, state="open"):
    return {
        "id": number + 1000,
        "number": number,
        "title": title,
        "state": state,
        "labels": labels if labels is not None else [],
    }


PROPOSAL = {
    "package": "ghostty",
    "candidate": "v1.5.0",
    "title": "Package candidate: ghostty @ v1.5.0",
}


class GitHubCandidateIssueTests(unittest.TestCase):
    def test_empty_history(self):
        self.assertEqual(issue_history(lambda _: []), [])

    def test_open_and_closed_issues(self):
        results = issue_history(
            lambda _: [
                issue(1),
                issue(2, state="closed"),
            ]
        )
        self.assertEqual(len(results), 2)

    def test_multiple_pages(self):
        calls = []

        def api(endpoint):
            calls.append(endpoint)
            if endpoint.endswith("&page=1"):
                return [issue(i) for i in range(1, 101)]
            if endpoint.endswith("&page=2"):
                return [issue(101)]
            raise AssertionError(endpoint)

        results = issue_history(api)
        self.assertEqual(len(results), 101)
        self.assertEqual(len(calls), 2)
        self.assertIn("state=all", calls[0])

    def test_exact_full_page_requires_followup(self):
        calls = []

        def api(endpoint):
            calls.append(endpoint)
            if endpoint.endswith("&page=1"):
                return [issue(i) for i in range(1, 101)]
            return []

        self.assertEqual(len(issue_history(api)), 100)
        self.assertEqual(len(calls), 2)

    def test_overlapping_pages_rejected(self):
        def api(endpoint):
            if endpoint.endswith("&page=1"):
                return [issue(i) for i in range(1, 101)]
            return [issue(100)]

        with self.assertRaisesRegex(ValueError, "Overlapping"):
            issue_history(api)

    def test_invalid_response_rejected(self):
        with self.assertRaises(ValueError):
            issue_history(lambda _: {"items": []})

    def test_missing_identity_rejected(self):
        with self.assertRaises(ValueError):
            issue_history(lambda _: [{"number": 1}])

    def test_missing_number_rejected(self):
        with self.assertRaises(ValueError):
            issue_history(lambda _: [{"id": 1}])

    def test_wrong_repository_rejected(self):
        with self.assertRaises(ValueError):
            issue_history(lambda _: [], "someone/else")

    def test_api_error_propagates(self):
        def api(_):
            raise RuntimeError("API unavailable")

        with self.assertRaises(RuntimeError):
            issue_history(api)

    def test_existing_denial_suppressed(self):
        result = evaluate_proposals(
            lambda _: [
                issue(
                    42,
                    labels=["candidate:denied"],
                    state="closed",
                )
            ],
            [PROPOSAL],
        )
        self.assertEqual(result[0]["action"], "denied")
        self.assertEqual(result[0]["issue_number"], 42)

    def test_new_candidate_requests_creation(self):
        result = evaluate_proposals(
            lambda _: [], [PROPOSAL]
        )
        self.assertEqual(result[0]["action"], "create")

    def test_pending_candidate_suppressed(self):
        result = evaluate_proposals(
            lambda _: [issue(12)], [PROPOSAL]
        )
        self.assertEqual(result[0]["action"], "pending")

    def test_duplicate_proposals_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_proposals(
                lambda _: [], [PROPOSAL, PROPOSAL]
            )

    def test_pr_not_mistaken_for_issue(self):
        record = issue(8, title="Unrelated PR")
        record["pull_request"] = {"url": "example"}

        result = evaluate_proposals(
            lambda _: [record], [PROPOSAL]
        )
        self.assertEqual(result[0]["action"], "create")


if __name__ == "__main__":
    unittest.main()
