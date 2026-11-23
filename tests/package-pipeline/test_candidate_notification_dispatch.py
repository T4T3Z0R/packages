import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from candidate_notification_dispatch import dispatch_one

TARGET = {
    "issue_number": 42,
    "package": "ghostty",
    "candidate": "v1.5.0",
}
RUN = 100


class Fake:
    def __init__(self):
        self.state = "unclaimed"
        self.run_id = None
        self.decision = None
        self.send_count = 0
        self.claim_count = 0
        self.ack_count = 0
        self.receipt = "abcd-1234"
        self.fail = None

    def read(self, number):
        if self.fail == "read":
            raise RuntimeError("GitHub unavailable")

        return {
            **TARGET,
            "state": self.state,
            "deliverable": (
                self.state == "unclaimed"
                and self.decision is None
            ),
            "decision": self.decision,
            "run_id": self.run_id,
            "pushover_request": (
                self.receipt if self.state == "accepted" else None
            ),
        }

    def claim(self, number, package, candidate, run):
        self.claim_count += 1

        if self.fail == "claim":
            raise RuntimeError("Claim response lost")

        self.state = "claimed"
        self.run_id = run

    def send(self, number, package, candidate):
        self.send_count += 1

        if self.fail == "send":
            raise TimeoutError("Pushover timed out")

        if self.fail == "bad_response":
            return {
                "http_status": 200,
                "status": 0,
                "request": self.receipt,
            }

        if self.fail == "missing_receipt":
            return {
                "http_status": 200,
                "status": 1,
            }

        return {
            "http_status": 200,
            "status": 1,
            "request": self.receipt,
        }

    def acknowledge(
        self, number, package, candidate, run, receipt
    ):
        self.ack_count += 1

        if self.fail == "ack":
            raise RuntimeError("Ack response lost")

        self.state = "accepted"

    def run(self, target=TARGET, run_id=RUN):
        return dispatch_one(
            target,
            run_id,
            read=self.read,
            claim=self.claim,
            send=self.send,
            acknowledge=self.acknowledge,
        )


class DispatcherTests(unittest.TestCase):
    def test_happy_path(self):
        backend = Fake()
        result = backend.run()

        self.assertEqual(result["state"], "accepted")
        self.assertEqual(
            result["pushover_request"], "abcd-1234"
        )
        self.assertEqual(
            (
                backend.claim_count,
                backend.send_count,
                backend.ack_count,
            ),
            (1, 1, 1),
        )

    def test_rerun_never_sends(self):
        backend = Fake()
        backend.run()

        with self.assertRaisesRegex(
            ValueError, "state changed"
        ):
            backend.run()

        self.assertEqual(backend.send_count, 1)

    def test_already_claimed_never_sends(self):
        backend = Fake()
        backend.state = "claimed"
        backend.run_id = RUN

        with self.assertRaisesRegex(
            ValueError, "state changed"
        ):
            backend.run()

        self.assertEqual(backend.send_count, 0)

    def test_reviewed_candidate_never_claims(self):
        backend = Fake()
        backend.decision = "candidate:approved"

        with self.assertRaisesRegex(
            ValueError, "eligible"
        ):
            backend.run()

        self.assertEqual(backend.claim_count, 0)

    def test_claim_failure_never_sends(self):
        backend = Fake()
        backend.fail = "claim"

        with self.assertRaisesRegex(
            RuntimeError, "Claim"
        ):
            backend.run()

        self.assertEqual(backend.send_count, 0)

    def test_send_timeout_not_acknowledged(self):
        backend = Fake()
        backend.fail = "send"

        with self.assertRaises(TimeoutError):
            backend.run()

        self.assertEqual(backend.state, "claimed")
        self.assertEqual(backend.ack_count, 0)

    def test_api_rejection_not_acknowledged(self):
        backend = Fake()
        backend.fail = "bad_response"

        with self.assertRaisesRegex(
            ValueError, "Unconfirmed"
        ):
            backend.run()

        self.assertEqual(backend.state, "claimed")
        self.assertEqual(backend.ack_count, 0)

    def test_missing_receipt_not_acknowledged(self):
        backend = Fake()
        backend.fail = "missing_receipt"

        with self.assertRaisesRegex(
            ValueError, "Unconfirmed"
        ):
            backend.run()

        self.assertEqual(backend.state, "claimed")

    def test_ack_failure_not_retried(self):
        backend = Fake()
        backend.fail = "ack"

        with self.assertRaisesRegex(
            RuntimeError, "Ack"
        ):
            backend.run()

        self.assertEqual(backend.send_count, 1)
        self.assertEqual(backend.ack_count, 1)
        self.assertEqual(backend.state, "claimed")

    def test_stale_identity_never_claims(self):
        backend = Fake()
        original_read = backend.read

        backend.read = lambda number: {
            **original_read(number),
            "candidate": "v1.6.0",
        }

        with self.assertRaisesRegex(
            ValueError, "identity changed"
        ):
            backend.run()

        self.assertEqual(backend.claim_count, 0)

    def test_wrong_run_after_claim_never_sends(self):
        backend = Fake()
        original_claim = backend.claim

        def wrong_run(number, package, candidate, run):
            original_claim(
                number, package, candidate, run + 1
            )

        backend.claim = wrong_run

        with self.assertRaisesRegex(
            ValueError, "run changed"
        ):
            backend.run()

        self.assertEqual(backend.send_count, 0)

    def test_unreadable_issues_never_claims(self):
        backend = Fake()
        backend.fail = "read"

        with self.assertRaisesRegex(
            RuntimeError, "unavailable"
        ):
            backend.run()

        self.assertEqual(backend.claim_count, 0)

    def test_invalid_input_fails_before_read(self):
        backend = Fake()

        for target in (
            {**TARGET, "issue_number": True},
            {**TARGET, "candidate": "main;rm"},
        ):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    backend.run(target)

        self.assertEqual(backend.claim_count, 0)

    def test_post_ack_state_mismatch_errors(self):
        backend = Fake()

        def bad_ack(*args):
            backend.ack_count += 1

        backend.acknowledge = bad_ack

        with self.assertRaisesRegex(
            ValueError, "state changed"
        ):
            backend.run()

        self.assertEqual(backend.send_count, 1)

    def test_post_ack_wrong_receipt_rejected(self):
        backend = Fake()
        original_read = backend.read

        def conflicting_receipt(number):
            row = original_read(number)
            if backend.state == "accepted":
                row["pushover_request"] = "different-receipt"
            return row

        backend.read = conflicting_receipt

        with self.assertRaisesRegex(
            ValueError, "receipt changed"
        ):
            backend.run()

        self.assertEqual(backend.send_count, 1)
        self.assertEqual(backend.ack_count, 1)


if __name__ == "__main__":
    unittest.main()
