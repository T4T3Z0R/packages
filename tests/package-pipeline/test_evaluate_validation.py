import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from evaluate_validation import evaluate

REPO = "T4T3Z0R/packages"
FP = "a" * 64
OLD = "b" * 64
SHA = "c" * 40


def run(run_id=123, status="completed", conclusion="success"):
    return {
        "id": run_id,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "head_sha": SHA,
        "status": status,
        "conclusion": conclusion,
    }


def api_with_runs(runs, *, valid_artifact=True, published=False,
                  validation_conclusion="success"):
    def api(url):
        if "/publish-wezterm.yml/runs?" in url:
            return {
                "total_count": len(runs),
                "workflow_runs": runs,
            }
        if "/jobs?" in url:
            return {
                "total_count": 3,
                "jobs": [
                    {
                        "id": 1,
                        "name": "Build and validate unsigned WezTerm pair",
                        "conclusion": validation_conclusion,
                        "steps": [{
                            "name": "Upload unsigned candidate and evidence",
                            "conclusion": "success",
                        }],
                    },
                    {
                        "id": 2,
                        "name": "Notify signing approval ready",
                        "conclusion": "success" if published else "skipped",
                    },
                    {
                        "id": 3,
                        "name": "Sign and publish approved WezTerm pair",
                        "conclusion": "success" if published else "skipped",
                    },
                ],
            }
        if "/artifacts?" in url:
            return {
                "total_count": 1 if valid_artifact else 0,
                "artifacts": [{
                    "id": 4,
                    "name": "wezterm-123-1-candidate",
                    "expired": False,
                    "size_in_bytes": 100,
                }] if valid_artifact else [],
            }
        raise AssertionError(url)

    return api


class EvaluationTests(unittest.TestCase):
    def check(self, runs, old=FP, **kwargs):
        return evaluate(
            api_with_runs(runs, **kwargs),
            REPO,
            "wezterm",
            FP,
            lambda sha, name: old,
        )

    def test_validated(self):
        result = self.check([run()])
        self.assertEqual(result["decision"], "validated")
        self.assertEqual(result["validated_runs"], [123])

    def test_completed_publication_is_not_dispatched_again(self):
        result = self.check([run()], published=True)
        self.assertEqual(result["decision"], "published")
        self.assertEqual(result["published_runs"], [123])

    def test_in_flight(self):
        result = self.check([
            run(status="in_progress", conclusion=None)
        ])
        self.assertEqual(result["decision"], "in_flight")

    def test_failed_run_allows_validation(self):
        result = self.check([
            run(conclusion="failure")
        ], validation_conclusion="failure")
        self.assertEqual(result["decision"], "needs_validation")

    def test_expired_or_missing_evidence(self):
        result = self.check(
            [run()], valid_artifact=False
        )
        self.assertEqual(result["decision"], "needs_validation")

    def test_legacy_history_excluded(self):
        result = self.check([run()], old=None)
        self.assertEqual(result["decision"], "needs_validation")

    def test_other_fingerprint_excluded(self):
        result = self.check([run()], old=OLD)
        self.assertEqual(result["decision"], "needs_validation")

    def test_empty_history(self):
        result = self.check([])
        self.assertEqual(result["decision"], "needs_validation")

    def test_duplicate_run_blocks(self):
        with self.assertRaises(ValueError):
            self.check([run(), run()])

    def test_missing_commit_blocks(self):
        def unavailable(sha, name):
            raise RuntimeError("Historical commit unavailable")

        with self.assertRaises(RuntimeError):
            evaluate(
                api_with_runs([run()]),
                REPO,
                "wezterm",
                FP,
                unavailable,
            )

    def test_api_failure_blocks(self):
        def unavailable(url):
            raise RuntimeError("GitHub unavailable")

        with self.assertRaises(RuntimeError):
            evaluate(
                unavailable,
                REPO,
                "wezterm",
                FP,
                lambda sha, name: FP,
            )

    def test_active_run_takes_priority_over_failed(self):
        result = self.check([
            run(124, "in_progress", None),
            run(125, "completed", "failure"),
        ])
        self.assertEqual(result["decision"], "in_flight")

    def test_active_run_precedes_successful_validation(self):
        result = self.check([
            run(124, "in_progress", None),
            run(123, "completed", "success"),
        ])

        self.assertEqual(result["decision"], "in_flight")
        self.assertEqual(result["active_runs"], [124])
        self.assertEqual(result["validated_runs"], [123])

    def test_rejected_approval_blocks_automatic_retry(self):
        result = self.check([
            run(conclusion="action_required")
        ])
        self.assertEqual(result["decision"], "manual_review")
        self.assertEqual(result["manual_review_runs"], [123])

    def test_cancelled_after_validation_blocks_retry(self):
        result = self.check([
            run(conclusion="cancelled")
        ])
        self.assertEqual(result["decision"], "manual_review")

    def test_failure_after_validation_blocks_retry(self):
        result = self.check([
            run(conclusion="failure")
        ])
        self.assertEqual(result["decision"], "manual_review")

    def test_published_release_survives_artifact_expiration(self):
        result = self.check(
            [run()], published=True, valid_artifact=False
        )
        self.assertEqual(result["decision"], "published")
        self.assertEqual(result["published_runs"], [123])

    def test_invalid_repository_rejected(self):
        with self.assertRaises(ValueError):
            evaluate(
                lambda url: None,
                "someone-else/packages",
                "wezterm",
                FP,
                lambda sha, name: FP,
            )


    def test_published_outweighs_unrelated_failure(self):
        successful = run(123)
        unrelated = run(124, conclusion="failure")
        unrelated["head_sha"] = "d" * 40

        result = evaluate(
            api_with_runs([successful, unrelated], published=True),
            REPO, "wezterm", FP,
            lambda sha, name: FP if sha == SHA else OLD,
        )

        self.assertEqual(result["decision"], "published")
        self.assertEqual(result["published_runs"], [123])
        self.assertEqual(result["manual_review_runs"], [])

    def test_failed_same_source_attempt_requires_review(self):
        result = self.check(
            [run(123), run(124, conclusion="failure")],
            published=True,
        )

        self.assertEqual(result["decision"], "manual_review")
        self.assertEqual(result["published_runs"], [123])
        self.assertEqual(result["manual_review_runs"], [124])

    def test_active_run_blocks_duplicate_after_publication(self):
        result = self.check(
            [run(123), run(124, status="waiting", conclusion=None)],
            published=True,
        )

        self.assertEqual(result["decision"], "in_flight")
        self.assertEqual(result["active_runs"], [124])
        self.assertEqual(result["published_runs"], [123])

    def test_missing_completed_job_evidence_requires_review(self):
        original = api_with_runs([run()])

        def incomplete(endpoint):
            if "/jobs?" in endpoint:
                return {"total_count": 0, "jobs": []}
            return original(endpoint)

        result = evaluate(
            incomplete, REPO, "wezterm", FP,
            lambda sha, name: FP,
        )

        self.assertEqual(result["decision"], "manual_review")
        self.assertEqual(result["manual_review_runs"], [123])

    def test_job_api_failure_aborts_evaluation(self):
        original = api_with_runs([run()])

        def unavailable(endpoint):
            if "/jobs?" in endpoint:
                raise RuntimeError("GitHub evidence unavailable")
            return original(endpoint)

        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            evaluate(
                unavailable, REPO, "wezterm", FP,
                lambda sha, name: FP,
            )

    def test_cancelled_before_validation_is_retryable(self):
        result = self.check(
            [run(conclusion="cancelled")],
            validation_conclusion="cancelled",
        )

        self.assertEqual(result["decision"], "needs_validation")


if __name__ == "__main__":
    unittest.main()
