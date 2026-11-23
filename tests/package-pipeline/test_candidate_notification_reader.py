import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from candidate_notification_state import ISSUE_MARKER, record_body
from candidate_notification_reader import inspect_outbox, issue_comments


MANIFEST = {"packages": {
    "ghostty": {"status": "approved", "auto_publish": False},
    "yazi": {"status": "candidate", "auto_publish": False},
}}


def issue(number=42, *, marker=True, author="github-actions[bot]",
          state="open", labels=None, count=0):
    return {
        "id": number + 1000,
        "number": number,
        "title": "Package candidate: ghostty @ v1.5.0",
        "body": ISSUE_MARKER if marker else "Legacy issue",
        "state": state,
        "user": {"login": author},
        "labels": [] if labels is None else labels,
        "comments": count,
    }


def comment(kind, ident, run=400):
    return {
        "id": ident,
        "user": {"login": "github-actions[bot]"},
        "body": record_body(kind, 42, "ghostty", "v1.5.0", run),
    }


def api_for(issues, comments=None):
    comments = [] if comments is None else comments

    def api(endpoint):
        if endpoint.startswith("repos/T4T3Z0R/packages/issues?"):
            return issues
        if endpoint.startswith(
            "repos/T4T3Z0R/packages/issues/42/comments?"
        ):
            page = int(endpoint.rsplit("page=", 1)[1])
            return comments[(page - 1) * 100:page * 100]
        raise AssertionError("Unexpected API read: " + endpoint)

    return api


class ReaderTests(unittest.TestCase):
    def test_new_issue_is_deliverable(self):
        item = inspect_outbox(MANIFEST, api_for([issue()]))[0]
        self.assertEqual(item["state"], "unclaimed")
        self.assertTrue(item["deliverable"])

    def test_legacy_issue_is_ignored(self):
        self.assertEqual(
            inspect_outbox(MANIFEST, api_for([issue(marker=False)])), []
        )

    def test_claim_does_not_send_again(self):
        rows = inspect_outbox(
            MANIFEST,
            api_for([issue(count=1)], [comment("claimed", 4)]),
        )
        self.assertEqual(rows[0]["state"], "claimed")
        self.assertFalse(rows[0]["deliverable"])

    def test_accepted_does_not_send_again(self):
        rows = inspect_outbox(
            MANIFEST,
            api_for([issue(count=2)], [
                comment("claimed", 4), comment("accepted", 5)
            ]),
        )
        self.assertEqual(rows[0]["state"], "accepted")
        self.assertFalse(rows[0]["deliverable"])

    def test_reviewed_candidate_not_deliverable(self):
        rows = inspect_outbox(
            MANIFEST,
            api_for([issue(labels=[{"name": "candidate:approved"}])]),
        )
        self.assertFalse(rows[0]["deliverable"])
        self.assertEqual(rows[0]["decision"], "candidate:approved")

    def test_closed_issue_not_deliverable(self):
        rows = inspect_outbox(MANIFEST, api_for([issue(state="closed")]))
        self.assertEqual(rows[0]["state"], "closed-unclaimed")
        self.assertFalse(rows[0]["deliverable"])

    def test_spoofed_issue_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Untrusted"):
            inspect_outbox(MANIFEST, api_for([issue(author="someone")]))

    def test_unknown_package_fails_closed(self):
        bad = issue()
        bad["title"] = "Package candidate: moonlight-qt @ v1.0.0"
        with self.assertRaisesRegex(ValueError, "not approved"):
            inspect_outbox(MANIFEST, api_for([bad]))

    def test_malformed_marker_on_pr_fails_closed(self):
        bad = issue()
        bad["pull_request"] = {"url": "somewhere"}
        with self.assertRaisesRegex(ValueError, "PR"):
            inspect_outbox(MANIFEST, api_for([bad]))

    def test_incomplete_comments_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            inspect_outbox(MANIFEST, api_for([issue(count=1)], []))

    def test_extra_comments_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            inspect_outbox(
                MANIFEST,
                api_for([issue(count=0)], [comment("claimed", 4)]),
            )

    def test_exactly_full_page_is_complete(self):
        notes = [
            {
                "id": i + 1,
                "user": {"login": "reviewer"},
                "body": "note",
            }
            for i in range(100)
        ]
        rows = inspect_outbox(
            MANIFEST,
            api_for([issue(count=100)], notes),
        )
        self.assertTrue(rows[0]["deliverable"])

    def test_extra_comment_after_full_page_rejected(self):
        notes = [
            {
                "id": i + 1,
                "user": {"login": "reviewer"},
                "body": "note",
            }
            for i in range(101)
        ]
        with self.assertRaisesRegex(
            ValueError, "Incomplete or changed"
        ):
            inspect_outbox(
                MANIFEST,
                api_for([issue(count=100)], notes),
            )

    def test_101_comments_paginated(self):
        notes = [
            {"id": i + 1, "user": {"login": "reviewer"}, "body": "note"}
            for i in range(101)
        ]
        result = inspect_outbox(
            MANIFEST, api_for([issue(count=101)], notes)
        )
        self.assertTrue(result[0]["deliverable"])

    def test_conflicting_decisions_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            inspect_outbox(MANIFEST, api_for([
                issue(labels=["candidate:approved", "candidate:denied"])
            ]))

    def test_duplicate_outbox_identity_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Duplicate outbox"):
            inspect_outbox(MANIFEST, api_for([issue(), issue(number=43)]))

    def test_invalid_comment_count_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "comment count"):
            issue_comments(lambda _: [], 42, True)

    def test_does_not_read_comments_for_legacy(self):
        result = inspect_outbox(
            MANIFEST, api_for([issue(marker=False)])
        )
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
