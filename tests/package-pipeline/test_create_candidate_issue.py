import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from create_candidate_issue import create_if_missing

PROPOSAL = {
    "package": "ghostty",
    "selected": "v1.4.0",
    "candidate": "v1.5.0",
    "title": "Package candidate: ghostty @ v1.5.0",
    "body": "Review candidate v1.5.0",
}


def issue(number=42, labels=None, state="open"):
    return {
        "id": 1000 + number,
        "number": number,
        "title": PROPOSAL["title"],
        "state": state,
        "labels": labels if labels is not None else [],
    }


class CandidateCreationTests(unittest.TestCase):
    def test_missing_issue_created(self):
        writes = []

        def create(title, body):
            writes.append((title, body))
            return issue()

        result = create_if_missing(
            PROPOSAL, lambda _: [], create
        )

        self.assertEqual(result["action"], "created")
        self.assertEqual(result["issue_number"], 42)
        self.assertEqual(len(writes), 1)

    def test_pending_issue_not_created_twice(self):
        writes = []

        result = create_if_missing(
            PROPOSAL,
            lambda _: [issue()],
            lambda *args: writes.append(args),
        )

        self.assertEqual(result["action"], "existing")
        self.assertEqual(result["decision"], "pending")
        self.assertEqual(writes, [])

    def test_denied_issue_not_recreated(self):
        result = create_if_missing(
            PROPOSAL,
            lambda _: [
                issue(labels=["candidate:denied"], state="closed")
            ],
            lambda *args: self.fail("Unexpected write"),
        )
        self.assertEqual(result["decision"], "denied")

    def test_postponed_issue_not_recreated(self):
        result = create_if_missing(
            PROPOSAL,
            lambda _: [
                issue(labels=["candidate:postponed"])
            ],
            lambda *args: self.fail("Unexpected write"),
        )
        self.assertEqual(result["decision"], "postponed")

    def test_approved_issue_not_recreated(self):
        result = create_if_missing(
            PROPOSAL,
            lambda _: [
                issue(labels=["candidate:approved"])
            ],
            lambda *args: self.fail("Unexpected write"),
        )
        self.assertEqual(result["decision"], "approved")

    def test_pinned_issue_not_recreated(self):
        result = create_if_missing(
            PROPOSAL,
            lambda _: [
                issue(labels=["candidate:pinned"])
            ],
            lambda *args: self.fail("Unexpected write"),
        )
        self.assertEqual(result["decision"], "pinned")

    def test_duplicate_history_blocks_write(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            create_if_missing(
                PROPOSAL,
                lambda _: [issue(42), issue(43)],
                lambda *args: self.fail("Unexpected write"),
            )

    def test_api_failure_blocks_write(self):
        def api(_):
            raise RuntimeError("GitHub unavailable")

        with self.assertRaises(RuntimeError):
            create_if_missing(
                PROPOSAL,
                api,
                lambda *args: self.fail("Unexpected write"),
            )

    def test_invalid_proposal_blocks_write(self):
        broken = dict(PROPOSAL)
        broken["title"] = "Unexpected title"

        with self.assertRaises(ValueError):
            create_if_missing(
                broken,
                lambda _: [],
                lambda *args: self.fail("Unexpected write"),
            )

    def test_created_issue_identity_verified(self):
        with self.assertRaisesRegex(ValueError, "mismatch"):
            create_if_missing(
                PROPOSAL,
                lambda _: [],
                lambda title, body: {
                    **issue(),
                    "title": "Wrong issue",
                },
            )

    def test_created_pr_rejected(self):
        with self.assertRaises(ValueError):
            create_if_missing(
                PROPOSAL,
                lambda _: [],
                lambda title, body: {
                    **issue(),
                    "pull_request": {"url": "example"},
                },
            )

    def test_closed_created_issue_rejected(self):
        with self.assertRaises(ValueError):
            create_if_missing(
                PROPOSAL,
                lambda _: [],
                lambda title, body: issue(state="closed"),
            )

    def test_invalid_history_blocks_write(self):
        with self.assertRaises(ValueError):
            create_if_missing(
                PROPOSAL,
                lambda _: {"items": []},
                lambda *args: self.fail("Unexpected write"),
            )


if __name__ == "__main__":
    unittest.main()
