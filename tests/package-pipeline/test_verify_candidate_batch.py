import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from verify_candidate_batch import verify_batch


REPORT = [
    {
        "package": "ghostty",
        "status": "update",
        "selected": "v1.4.0",
        "candidate": "v1.5.0",
    },
    {
        "package": "syncthing",
        "status": "update",
        "selected": "v2.1.7",
        "candidate": "v2.1.8",
    },
]


def record(item, action, number, decision=None):
    result = {
        "package": item["package"],
        "candidate": item["candidate"],
        "action": action,
        "issue_number": number,
    }
    if decision is not None:
        result["decision"] = decision
    return result


class BatchVerificationTests(unittest.TestCase):
    def setUp(self):
        self.before = [
            record(REPORT[0], "create", None),
            record(REPORT[1], "pending", 51),
        ]
        self.writes = [
            record(REPORT[0], "created", 50, "pending"),
            record(REPORT[1], "existing", 51, "pending"),
        ]

    def reader(self, item):
        number = 50 if item["package"] == "ghostty" else 51
        return [record(item, "pending", number)]

    def test_only_newly_created_issues_are_returned(self):
        result = verify_batch(
            REPORT, self.before, self.writes,
            self.reader,
            pause=lambda _: None,
        )
        self.assertEqual(result, [{
            "package": "ghostty",
            "candidate": "v1.5.0",
            "issue_number": 50,
        }])

    def test_existing_issues_create_no_notifications(self):
        before = [
            record(item, "pending", number)
            for item, number in zip(REPORT, (50, 51))
        ]
        writes = [
            record(item, "existing", number, "pending")
            for item, number in zip(REPORT, (50, 51))
        ]

        result = verify_batch(
            REPORT, before, writes,
            self.reader,
            pause=lambda _: None,
        )
        self.assertEqual(result, [])

    def test_new_issue_history_lag_is_bounded(self):
        reads = []
        pauses = []

        def reader(item):
            if item["package"] == "ghostty":
                reads.append(1)
                if len(reads) == 1:
                    return [record(item, "create", None)]
            return self.reader(item)

        result = verify_batch(
            REPORT, self.before, self.writes,
            reader,
            pause=pauses.append,
        )

        self.assertEqual(len(reads), 2)
        self.assertEqual(pauses, [2])
        self.assertEqual(len(result), 1)

    def test_wrong_issue_identity_fails_closed(self):
        def reader(item):
            if item["package"] == "ghostty":
                return [record(item, "pending", 999)]
            return self.reader(item)

        with self.assertRaisesRegex(ValueError, "identity"):
            verify_batch(
                REPORT, self.before, self.writes,
                reader,
                pause=lambda _: None,
            )

    def test_missing_write_rejected(self):
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            verify_batch(
                REPORT, self.before, self.writes[:1],
                self.reader,
                pause=lambda _: None,
            )

    def test_duplicate_write_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            verify_batch(
                REPORT, self.before,
                self.writes + [self.writes[0]],
                self.reader,
                pause=lambda _: None,
            )

    def test_unexpected_write_rejected(self):
        unexpected = record(
            REPORT[0], "created", 60, "pending"
        )
        unexpected["candidate"] = "v99.0.0"

        with self.assertRaisesRegex(ValueError, "unexpected"):
            verify_batch(
                REPORT, self.before,
                self.writes + [unexpected],
                self.reader,
                pause=lambda _: None,
            )

    def test_no_updates_requires_no_issue_reads(self):
        result = verify_batch(
            [], [], [],
            lambda _: self.fail("Unexpected GitHub read"),
        )
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
