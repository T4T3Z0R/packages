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


    def attempt_api(url):
        import re

        if "/attempts/" not in url:
            return api(url)

        pattern = (
            r"repos/T4T3Z0R/packages/actions/runs/"
            r"([1-9][0-9]*)/attempts/([1-9][0-9]*)"
            r"(/jobs\?per_page=100&page=1)?"
        )
        match = re.fullmatch(pattern, url)

        if match is None:
            raise AssertionError(
                "Unexpected attempt endpoint: " + url
            )

        run_id = int(match.group(1))
        attempt = int(match.group(2))

        matching = [
            item for item in runs
            if item["id"] == run_id
        ]
        assert len(matching) == 1

        latest = matching[0]

        # The original fixture describes exactly one execution.
        # Never invent missing evidence for an earlier attempt.
        assert latest["run_attempt"] == attempt == 1, (
            "Synthetic fixture cannot represent rerun history"
        )

        if match.group(3):
            response = api(url)

            for job in response["jobs"]:
                job["run_id"] = run_id
                job["run_attempt"] = attempt

            return response

        return dict(latest)

    return attempt_api




def attempt_fixture(
    number,
    *,
    conclusion="success",
    validation="success",
    notification="skipped",
    publication="skipped",
):
    metadata = run(conclusion=conclusion)
    metadata["run_attempt"] = number

    jobs = [
        {
            "id": number * 10 + 1,
            "run_id": 123,
            "run_attempt": number,
            "name": "Build and validate unsigned WezTerm pair",
            "conclusion": validation,
            "steps": [{
                "name": "Upload unsigned candidate and evidence",
                "conclusion": (
                    "success" if validation == "success"
                    else "failure"
                ),
            }],
        },
        {
            "id": number * 10 + 2,
            "run_id": 123,
            "run_attempt": number,
            "name": "Notify signing approval ready",
            "conclusion": notification,
        },
        {
            "id": number * 10 + 3,
            "run_id": 123,
            "run_attempt": number,
            "name": "Sign and publish approved WezTerm pair",
            "conclusion": publication,
        },
    ]
    return metadata, jobs


def api_with_attempts(*records):
    import re

    assert records
    assert [
        item[0]["run_attempt"] for item in records
    ] == list(range(1, len(records) + 1))

    latest = records[-1][0]

    def api(endpoint):
        if "/publish-wezterm.yml/runs?" in endpoint:
            return {
                "total_count": 1,
                "workflow_runs": [latest],
            }

        if "/artifacts?" in endpoint:
            return {"total_count": 0, "artifacts": []}

        match = re.fullmatch(
            r"repos/T4T3Z0R/packages/actions/runs/123/"
            r"attempts/([1-9][0-9]*)"
            r"(/jobs\?per_page=100&page=1)?",
            endpoint,
        )
        if match is None:
            raise AssertionError(endpoint)

        number = int(match.group(1))
        assert 1 <= number <= len(records)
        metadata, jobs = records[number - 1]

        if match.group(2):
            return {
                "total_count": len(jobs),
                "jobs": jobs,
            }
        return dict(metadata)

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


    def test_unrepresented_failed_rerun_is_rejected(self):
        latest = run(conclusion="failure")
        latest["run_attempt"] = 2

        with self.assertRaisesRegex(
            AssertionError, "cannot represent"
        ):
            self.check(
                [latest],
                validation_conclusion="failure",
            )

    def test_unrepresented_successful_rerun_is_rejected(self):
        latest = run()
        latest["run_attempt"] = 2

        with self.assertRaisesRegex(
            AssertionError, "cannot represent"
        ):
            self.check([latest], published=True)

    def test_active_rerun_remains_in_flight(self):
        latest = run(
            status="in_progress",
            conclusion=None,
        )
        latest["run_attempt"] = 2

        result = self.check([latest])

        self.assertEqual(result["decision"], "in_flight")
        self.assertEqual(result["active_runs"], [123])


    def test_fixture_supports_exact_attempt_evidence(self):
        api = api_with_runs([run()])

        base = (
            "repos/T4T3Z0R/packages/actions/runs/"
            "123/attempts/1"
        )

        metadata = api(base)
        response = api(
            base + "/jobs?per_page=100&page=1"
        )

        self.assertEqual(metadata["id"], 123)
        self.assertEqual(metadata["run_attempt"], 1)
        self.assertEqual(len(response["jobs"]), 3)

        for job in response["jobs"]:
            self.assertEqual(job["run_id"], 123)
            self.assertEqual(job["run_attempt"], 1)

    def test_fixture_refuses_invented_attempt_history(self):
        latest = run()
        latest["run_attempt"] = 2

        api = api_with_runs([latest])

        with self.assertRaisesRegex(
            AssertionError, "cannot represent"
        ):
            api(
                "repos/T4T3Z0R/packages/actions/"
                "runs/123/attempts/1"
            )


    def test_evaluator_uses_exact_attempt_jobs(self):
        calls = []
        original = api_with_runs([run()])

        def api(endpoint):
            calls.append(endpoint)
            if endpoint.endswith(
                "/runs/123/jobs?per_page=100&page=1"
            ):
                raise AssertionError("Unsafe latest-only jobs endpoint")
            return original(endpoint)

        result = evaluate(
            api, REPO, "wezterm", FP,
            lambda sha, name: FP,
        )

        self.assertEqual(result["decision"], "validated")
        self.assertTrue(any(
            "/runs/123/attempts/1/jobs?" in url
            for url in calls
        ))

    def test_changed_attempt_metadata_fails_closed(self):
        original = api_with_runs([run()])

        def api(endpoint):
            response = original(endpoint)
            if endpoint.endswith("/attempts/1"):
                return {
                    **response,
                    "head_sha": "d" * 40,
                }
            return response

        with self.assertRaisesRegex(
            ValueError, "source or event mismatch"
        ):
            evaluate(
                api, REPO, "wezterm", FP,
                lambda sha, name: FP,
            )


    def test_published_attempt_survives_failed_rerun(self):
        first = attempt_fixture(
            1, notification="success", publication="success"
        )
        second = attempt_fixture(
            2, conclusion="failure", validation="failure"
        )

        result = evaluate(
            api_with_attempts(first, second),
            REPO, "wezterm", FP,
            lambda sha, name: FP,
        )

        self.assertEqual(result["decision"], "published")
        self.assertEqual(result["published_runs"], [123])
        self.assertEqual(result["manual_review_runs"], [])

    def test_rejected_approval_survives_failed_rerun(self):
        first = attempt_fixture(
            1, conclusion="cancelled",
            notification="success", publication="skipped",
        )
        second = attempt_fixture(
            2, conclusion="failure", validation="failure"
        )

        result = evaluate(
            api_with_attempts(first, second),
            REPO, "wezterm", FP,
            lambda sha, name: FP,
        )

        self.assertEqual(result["decision"], "manual_review")
        self.assertEqual(result["manual_review_runs"], [123])

    def test_retryable_attempts_without_artifacts(self):
        first = attempt_fixture(
            1, conclusion="failure", validation="failure"
        )
        second = attempt_fixture(
            2, conclusion="failure", validation="failure"
        )

        result = evaluate(
            api_with_attempts(first, second),
            REPO, "wezterm", FP,
            lambda sha, name: FP,
        )

        self.assertEqual(result["decision"], "needs_validation")

    def test_earlier_attempt_source_mismatch_fails_closed(self):
        first = attempt_fixture(
            1, notification="success", publication="success"
        )
        first[0]["head_sha"] = "d" * 40
        second = attempt_fixture(
            2, conclusion="failure", validation="failure"
        )

        with self.assertRaisesRegex(ValueError, "source"):
            evaluate(
                api_with_attempts(first, second),
                REPO, "wezterm", FP,
                lambda sha, name: FP,
            )

    def test_multiple_published_attempts_not_double_counted(self):
        first = attempt_fixture(
            1, notification="success", publication="success"
        )
        second = attempt_fixture(
            2, notification="success", publication="success"
        )

        result = evaluate(
            api_with_attempts(first, second),
            REPO, "wezterm", FP,
            lambda sha, name: FP,
        )

        self.assertEqual(result["decision"], "published")
        self.assertEqual(result["published_runs"], [123])


if __name__ == "__main__":
    unittest.main()
