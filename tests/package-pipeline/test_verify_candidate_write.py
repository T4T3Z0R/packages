import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from verify_candidate_write import MAX_READS, verify

PACKAGE = "wezterm"
CANDIDATE = "ee6f3044d09f83f21a32aead8dac2bc2a32e7fcb"


def entry(action, number):
    return [{
        "package": PACKAGE,
        "candidate": CANDIDATE,
        "action": action,
        "issue_number": number,
    }]


class PostwriteConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.before = entry("create", None)[0]
        self.created = {
            "package": PACKAGE,
            "candidate": CANDIDATE,
            "action": "created",
            "decision": "pending",
            "issue_number": 16,
        }
        self.pending = entry("pending", 16)
        self.stale = entry("create", None)

    def run_history(self, snapshots, *, write=None, before=None):
        reads = []
        sleeps = []
        observations = []
        iterator = iter(snapshots)

        def read():
            reads.append(1)
            return next(iterator)

        try:
            result = verify(
                self.before if before is None else before,
                self.created if write is None else write,
                read,
                pause=sleeps.append,
                record=observations.append,
            )
        except Exception:
            self.last_counts = (
                len(reads), sleeps, observations
            )
            raise

        self.last_counts = (
            len(reads), sleeps, observations
        )
        return result

    def test_immediate_visibility(self):
        self.assertEqual(
            self.run_history([self.pending]),
            self.pending[0],
        )
        self.assertEqual(self.last_counts[:2], (1, []))

    def test_stale_then_visible(self):
        self.assertEqual(
            self.run_history([self.stale, self.pending]),
            self.pending[0],
        )
        self.assertEqual(self.last_counts[:2], (2, [2]))
        self.assertEqual(
            self.last_counts[2],
            [self.stale, self.pending],
        )

    def test_four_stale_reads_then_visible(self):
        self.run_history(
            [self.stale] * (MAX_READS - 1)
            + [self.pending]
        )
        self.assertEqual(
            self.last_counts[:2],
            (MAX_READS, [2] * 4),
        )

    def test_exhausted_history_fails_closed(self):
        with self.assertRaisesRegex(
            RuntimeError, "absent after"
        ):
            self.run_history([self.stale] * MAX_READS)
        self.assertEqual(
            self.last_counts[:2],
            (MAX_READS, [2] * 4),
        )

    def test_wrong_issue_number_fails_immediately(self):
        with self.assertRaisesRegex(
            ValueError, "issue identity"
        ):
            self.run_history([entry("pending", 17)])
        self.assertEqual(self.last_counts[:2], (1, []))

    def test_wrong_decision_fails_immediately(self):
        with self.assertRaisesRegex(
            ValueError, "decision mismatch"
        ):
            self.run_history([entry("approved", 16)])
        self.assertEqual(self.last_counts[:2], (1, []))

    def test_wrong_candidate_fails_immediately(self):
        other = [
            {**self.pending[0], "candidate": "wrong"}
        ]
        with self.assertRaisesRegex(
            ValueError, "candidate identity"
        ):
            self.run_history([other])
        self.assertEqual(self.last_counts[:2], (1, []))

    def test_existing_issue_is_not_retried(self):
        existing = {
            **self.created,
            "action": "existing",
        }
        self.assertEqual(
            self.run_history([self.pending], write=existing),
            self.pending[0],
        )
        with self.assertRaisesRegex(
            ValueError, "issue identity"
        ):
            self.run_history([self.stale], write=existing)
        self.assertEqual(self.last_counts[:2], (1, []))

    def test_api_failure_is_not_retried(self):
        def broken():
            raise RuntimeError("GitHub unavailable")

        with self.assertRaisesRegex(
            RuntimeError, "GitHub unavailable"
        ):
            verify(
                self.before,
                self.created,
                broken,
                pause=lambda _: self.fail("Unexpected retry"),
            )

    def test_duplicate_results_fail_immediately(self):
        with self.assertRaisesRegex(
            ValueError, "Expected exactly one"
        ):
            self.run_history(
                [self.pending + self.pending]
            )
        self.assertEqual(self.last_counts[:2], (1, []))

    def test_invalid_write_never_queries(self):
        invalid = {
            **self.created,
            "issue_number": None,
        }
        with self.assertRaisesRegex(
            ValueError, "Invalid write issue"
        ):
            verify(
                self.before,
                invalid,
                lambda: self.fail("Unexpected read"),
            )


if __name__ == "__main__":
    unittest.main()
