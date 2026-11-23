import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from candidate_notification_state import (
    ISSUE_MARKER,
    TRUSTED_AUTHOR,
    classify,
    record_body,
)
from candidate_notification_reader import inspect_outbox


PACKAGE = "ghostty"
CANDIDATE = "v1.5.0"
ISSUE = 42
RUN = 100
RECEIPT = "abcd-1234"


def issue():
    return {
        "id": 900,
        "number": ISSUE,
        "title": f"Package candidate: {PACKAGE} @ {CANDIDATE}",
        "body": ISSUE_MARKER,
        "state": "open",
        "comments": 2,
        "labels": [],
        "user": {"login": TRUSTED_AUTHOR},
    }


def comment(kind, comment_id, *, receipt=None):
    return {
        "id": comment_id,
        "user": {"login": TRUSTED_AUTHOR},
        "body": record_body(
            kind, ISSUE, PACKAGE, CANDIDATE, RUN,
            pushover_request=receipt,
        ),
    }


class ReceiptTests(unittest.TestCase):
    def test_record_contains_receipt(self):
        body = record_body(
            "accepted", ISSUE, PACKAGE, CANDIDATE, RUN,
            pushover_request=RECEIPT,
        )
        record = json.loads(body.split("\n", 1)[1])
        self.assertEqual(record["pushover_request"], RECEIPT)

    def test_state_exposes_receipt(self):
        result = classify(issue(), [
            comment("claimed", 4),
            comment("accepted", 5, receipt=RECEIPT),
        ])
        self.assertEqual(result["state"], "accepted")
        self.assertEqual(result["pushover_request"], RECEIPT)

    def test_historical_acceptance_remains_readable(self):
        result = classify(issue(), [
            comment("claimed", 4),
            comment("accepted", 5),
        ])
        self.assertEqual(result["state"], "accepted")
        self.assertNotIn("pushover_request", result)

    def test_invalid_receipt_rejected(self):
        for value in ("", "bad receipt", "x" * 101):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    record_body(
                        "accepted", ISSUE, PACKAGE, CANDIDATE, RUN,
                        pushover_request=value,
                    )

    def test_claim_cannot_contain_receipt(self):
        with self.assertRaises(ValueError):
            record_body(
                "claimed", ISSUE, PACKAGE, CANDIDATE, RUN,
                pushover_request=RECEIPT,
            )

    def test_forged_invalid_receipt_rejected(self):
        accepted = comment("accepted", 5, receipt=RECEIPT)
        accepted["body"] = accepted["body"].replace(
            RECEIPT, "invalid receipt", 1
        )

        with self.assertRaisesRegex(ValueError, "receipt"):
            classify(issue(), [
                comment("claimed", 4),
                accepted,
            ])

    def test_reader_preserves_receipt(self):
        candidate_issue = issue()
        comments = [
            comment("claimed", 4),
            comment("accepted", 5, receipt=RECEIPT),
        ]

        def api(endpoint):
            if endpoint.startswith(
                "repos/T4T3Z0R/packages/issues?"
            ):
                return [candidate_issue]

            if endpoint == (
                "repos/T4T3Z0R/packages/issues/42/comments"
                "?per_page=100&page=1"
            ):
                return comments

            raise AssertionError(
                f"Unexpected read: {endpoint}"
            )

        manifest = {
            "packages": {
                PACKAGE: {
                    "status": "approved",
                    "auto_publish": False,
                }
            }
        }

        rows = inspect_outbox(manifest, api)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "accepted")
        self.assertEqual(
            rows[0]["pushover_request"], RECEIPT
        )
        self.assertFalse(rows[0]["deliverable"])


if __name__ == "__main__":
    unittest.main()
