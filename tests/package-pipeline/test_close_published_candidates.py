import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from close_published_candidates import apply, receipt

REV = "a" * 40
CANDIDATE = "b" * 40
REPO = "T4T3Z0R/packages"
ISSUE = f"repos/{REPO}/issues/26"

RECORD = {
    "issue_number": 26,
    "package": "noctalia-custom",
    "candidate": CANDIDATE,
    "selection_pr": 27,
    "selection_revision": "c" * 40,
    "decision": "close_published",
    "publication": {
        "run_id": 123,
        "attempt": 1,
        "revision": "d" * 40,
        "fingerprint": "e" * 64,
    },
}


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.issue = {
            "number": 26,
            "state": "open",
            "title": (
                "Package candidate: noctalia-custom @ "
                + CANDIDATE
            ),
            "body": "<!-- t4t3z0r:candidate-alert:v1 -->",
            "user": {"login": "github-actions[bot]"},
            "labels": [{"name": "candidate:approved"}],
        }

        self.comments = []
        self.writes = []
        self.current = REV
        self.records = [copy.deepcopy(RECORD)]

    def api(self, endpoint):
        if endpoint == f"repos/{REPO}/branches/main":
            return {"commit": {"sha": self.current}}

        if endpoint == ISSUE:
            return copy.deepcopy(self.issue)

        if endpoint.startswith(f"{ISSUE}/comments?"):
            return copy.deepcopy(self.comments)

        raise AssertionError(endpoint)

    def planner(self, root, api, revision):
        if self.issue["state"] == "closed":
            return []

        return copy.deepcopy(self.records)

    def mutate(self, endpoint, method, data):
        self.writes.append((endpoint, method, data))

        if endpoint == f"{ISSUE}/comments" and method == "POST":
            comment = {
                "id": len(self.comments) + 1,
                "body": data["body"],
                "user": {"login": "github-actions[bot]"},
            }
            self.comments.append(comment)
            return copy.deepcopy(comment)

        if endpoint == ISSUE and method == "PATCH":
            self.issue.update(data)
            return copy.deepcopy(self.issue)

        raise AssertionError((endpoint, method))

    def run_writer(self):
        return apply(
            ROOT, self.api, self.mutate, REV,
            planner=self.planner,
        )

    def test_verified_publication_closes_issue(self):
        results = self.run_writer()

        self.assertEqual(
            results[0]["decision"], "closed_published"
        )
        self.assertEqual(self.issue["state"], "closed")
        self.assertEqual(
            self.issue["state_reason"], "completed"
        )
        self.assertEqual(
            [method for _, method, _ in self.writes],
            ["POST", "PATCH"],
        )

    def test_second_run_is_noop(self):
        self.run_writer()
        self.writes.clear()

        self.assertEqual(self.run_writer(), [])
        self.assertEqual(self.writes, [])

    def test_existing_receipt_is_reused(self):
        _, body = receipt(RECORD)

        self.comments.append({
            "id": 1,
            "body": body,
            "user": {"login": "github-actions[bot]"},
        })

        self.run_writer()

        self.assertEqual(
            [method for _, method, _ in self.writes],
            ["PATCH"],
        )

    def test_untrusted_receipt_blocks_closure(self):
        _, body = receipt(RECORD)

        self.comments.append({
            "id": 1,
            "body": body,
            "user": {"login": "someone-else"},
        })

        with self.assertRaises(ValueError):
            self.run_writer()

        self.assertEqual(self.writes, [])

    def test_duplicate_receipts_block_closure(self):
        _, body = receipt(RECORD)

        self.comments = [
            {
                "id": number,
                "body": body,
                "user": {"login": "github-actions[bot]"},
            }
            for number in (1, 2)
        ]

        with self.assertRaises(ValueError):
            self.run_writer()

        self.assertEqual(self.writes, [])

    def test_unpublished_candidate_stays_open(self):
        self.records[0]["decision"] = "awaiting_publication"

        self.assertEqual(self.run_writer(), [])
        self.assertEqual(self.writes, [])
        self.assertEqual(self.issue["state"], "open")

    def test_revoked_approval_blocks_closure(self):
        self.issue["labels"] = [
            {"name": "candidate:denied"}
        ]

        with self.assertRaises(ValueError):
            self.run_writer()

        self.assertEqual(self.writes, [])

    def test_moved_main_blocks_closure(self):
        self.current = "f" * 40

        with self.assertRaises(ValueError):
            self.run_writer()

        self.assertEqual(self.writes, [])

    def test_changed_evidence_after_receipt_blocks_close(self):
        original = self.mutate

        def changed(endpoint, method, data):
            result = original(endpoint, method, data)

            if method == "POST":
                self.records[0]["publication"]["attempt"] = 2

            return result

        with self.assertRaises(ValueError):
            apply(
                ROOT, self.api, changed, REV,
                planner=self.planner,
            )

        self.assertEqual(self.issue["state"], "open")
        self.assertEqual(
            [method for _, method, _ in self.writes],
            ["POST"],
        )


if __name__ == "__main__":
    unittest.main()
