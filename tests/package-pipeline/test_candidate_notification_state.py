import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from candidate_notification_state import (
    ISSUE_MARKER,
    classify,
    record_body,
)


def issue(body=ISSUE_MARKER, state="open"):
    return {
        "number": 42,
        "title": "Package candidate: ghostty @ v1.5.0",
        "body": body,
        "state": state,
    }


def comment(state, ident, run=100):
    return {
        "id": ident,
        "user": {"login": "github-actions[bot]"},
        "body": record_body(
            state, 42, "ghostty", "v1.5.0", run
        ),
    }


class NotificationStateTests(unittest.TestCase):
    def test_new_issue_is_unclaimed(self):
        self.assertEqual(
            classify(issue(), [])["state"], "unclaimed"
        )

    def test_legacy_issue_is_ignored(self):
        self.assertEqual(
            classify(issue(body="Old review"), [])["state"],
            "legacy",
        )

    def test_claim_is_not_retried(self):
        self.assertEqual(
            classify(issue(), [
                comment("claimed", 4)
            ])["state"],
            "claimed",
        )

    def test_accepted_message_is_not_retried(self):
        self.assertEqual(
            classify(issue(), [
                comment("claimed", 4),
                comment("accepted", 5),
            ])["state"],
            "accepted",
        )

    def test_closed_unclaimed_issue(self):
        self.assertEqual(
            classify(issue(state="closed"), [])["state"],
            "closed-unclaimed",
        )

    def test_out_of_order_ack_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "acknowledgment"
        ):
            classify(issue(), [
                comment("claimed", 7),
                comment("accepted", 5),
            ])

    def test_different_run_ack_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "acknowledgment"
        ):
            classify(issue(), [
                comment("claimed", 4),
                comment("accepted", 5, run=101),
            ])

    def test_duplicate_claim_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "duplicate notification"
        ):
            classify(issue(), [
                comment("claimed", 4),
                comment("claimed", 5),
            ])

    def test_ack_without_claim_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "without claim"
        ):
            classify(issue(), [
                comment("accepted", 5),
            ])

    def test_untrusted_claim_rejected(self):
        forged = comment("claimed", 4)
        forged["user"]["login"] = "untrusted-user"

        with self.assertRaisesRegex(
            ValueError, "Untrusted"
        ):
            classify(issue(), [forged])

    def test_incomplete_history_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "Incomplete"
        ):
            classify(issue(), None)

    def test_wrong_issue_title_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "Invalid candidate"
        ):
            classify({
                **issue(), "title": "Other issue"
            }, [])

    def test_wrong_issue_number_rejected(self):
        forged = comment("claimed", 4)
        forged["body"] = record_body(
            "claimed", 43, "ghostty", "v1.5.0", 100
        )

        with self.assertRaisesRegex(
            ValueError, "identity mismatch"
        ):
            classify(issue(), [forged])

    def test_invalid_run_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "Invalid workflow"
        ):
            record_body(
                "claimed", 42, "ghostty", "v1.5.0", 0
            )

    def test_normal_user_comments_ignored(self):
        result = classify(issue(), [{
            "id": 3,
            "user": {"login": "reviewer"},
            "body": "Reviewing this version.",
        }])

        self.assertEqual(result["state"], "unclaimed")

    def test_duplicate_issue_marker_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "Duplicate issue"
        ):
            classify(
                issue(body=ISSUE_MARKER * 2), []
            )


if __name__ == "__main__":
    unittest.main()
