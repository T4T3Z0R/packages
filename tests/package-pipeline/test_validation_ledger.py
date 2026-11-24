import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from validation_ledger import classify

FP = "a" * 64
OTHER = "b" * 64
SHA = "c" * 40


def evidence():
    run = {
        "id": 44989886912,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "head_sha": SHA,
        "status": "completed",
        "conclusion": "success",
    }
    jobs = [
        {
            "name": "Build and validate unsigned WezTerm pair",
            "conclusion": "success",
            "steps": [{
                "name": "Upload unsigned candidate and evidence",
                "conclusion": "success",
            }],
        },
        {
            "name": "Sign and publish approved WezTerm pair",
            "conclusion": "skipped",
        },
        {
            "name": "Notify signing approval ready",
            "conclusion": "skipped",
        },
    ]
    artifacts = [{
        "name": "wezterm-44989886912-1-candidate",
        "expired": False,
        "size_in_bytes": 39074593,
    }]
    return run, jobs, artifacts


class LedgerTests(unittest.TestCase):
    def classify(self, run=None, jobs=None, artifacts=None,
                 historical=FP):
        base = evidence()
        return classify(
            copy.deepcopy(base[0] if run is None else run),
            copy.deepcopy(base[1] if jobs is None else jobs),
            copy.deepcopy(base[2] if artifacts is None else artifacts),
            package="wezterm",
            target=FP,
            fingerprint=lambda sha, package: historical,
        )

    def test_validated(self):
        self.assertEqual(self.classify(), "validated")

    def test_syncthing_real_job_name(self):
        run, jobs, artifacts = evidence()

        jobs[0]["name"] = "Build and validate unsigned Syncthing"
        artifacts[0]["name"] = (
            "syncthing-44989886912-1-candidate"
        )

        result = classify(
            run,
            jobs,
            artifacts,
            package="syncthing",
            target=FP,
            fingerprint=lambda sha, package: FP,
        )

        self.assertEqual(result, "validated")

    def test_validation_job_names_match_workflows(self):
        from validation_ledger import VALIDATION_JOBS
        from select_package_validation import workflow_file

        for package, expected in VALIDATION_JOBS.items():
            workflow = (
                ROOT / ".github/workflows"
                / workflow_file(package)
            ).read_text()

            with self.subTest(package=package):
                self.assertIn(
                    f"name: {expected}",
                    workflow,
                )

    def test_different_fingerprint(self):
        self.assertEqual(
            self.classify(historical=OTHER), "unrelated"
        )

    def test_running(self):
        run, jobs, artifacts = evidence()
        run["status"] = "in_progress"
        run["conclusion"] = None
        self.assertEqual(
            self.classify(run, jobs, artifacts), "in_flight"
        )

    def test_failed_build_can_retry(self):
        run, jobs, artifacts = evidence()
        run["conclusion"] = "failure"
        jobs[0]["conclusion"] = "failure"
        self.assertEqual(
            self.classify(run, jobs, artifacts), "retry"
        )

    def test_cancelled_build_can_retry(self):
        run, jobs, artifacts = evidence()
        run["conclusion"] = "cancelled"
        jobs[0]["conclusion"] = "cancelled"
        self.assertEqual(
            self.classify(run, jobs, artifacts), "retry"
        )

    def test_expired_artifact_can_retry(self):
        run, jobs, artifacts = evidence()
        artifacts[0]["expired"] = True
        self.assertEqual(
            self.classify(run, jobs, artifacts), "retry"
        )

    def test_missing_artifact_can_retry(self):
        run, jobs, artifacts = evidence()
        self.assertEqual(
            self.classify(run, jobs, []), "retry"
        )

    def test_inconsistent_upload_requires_review(self):
        run, jobs, artifacts = evidence()
        jobs[0]["steps"][0]["conclusion"] = "failure"
        self.assertEqual(
            self.classify(run, jobs, artifacts), "manual_review"
        )

    def test_inconsistent_publication_requires_review(self):
        run, jobs, artifacts = evidence()
        jobs[1]["conclusion"] = "success"
        self.assertEqual(
            self.classify(run, jobs, artifacts), "manual_review"
        )

    def test_successful_protected_publication(self):
        run, jobs, artifacts = evidence()
        jobs[1]["conclusion"] = "success"
        jobs[2]["conclusion"] = "success"
        self.assertEqual(
            self.classify(run, jobs, artifacts), "published"
        )

    def test_published_artifact_may_expire(self):
        run, jobs, artifacts = evidence()
        jobs[1]["conclusion"] = "success"
        jobs[2]["conclusion"] = "success"
        artifacts[0]["expired"] = True
        self.assertEqual(
            self.classify(run, jobs, artifacts), "published"
        )

    def test_waiting_for_environment_approval(self):
        run, jobs, artifacts = evidence()
        run["status"] = "waiting"
        run["conclusion"] = None
        self.assertEqual(
            self.classify(run, jobs, artifacts), "in_flight"
        )

    def test_rejected_or_cancelled_approval_requires_review(self):
        for conclusion in ("cancelled", "action_required", "failure"):
            with self.subTest(conclusion=conclusion):
                run, jobs, artifacts = evidence()
                run["conclusion"] = conclusion
                jobs[1]["conclusion"] = "cancelled"
                jobs[2]["conclusion"] = "success"
                self.assertEqual(
                    self.classify(run, jobs, artifacts),
                    "manual_review",
                )

    def test_failed_notification_requires_review(self):
        run, jobs, artifacts = evidence()
        run["conclusion"] = "failure"
        jobs[2]["conclusion"] = "failure"
        self.assertEqual(
            self.classify(run, jobs, artifacts), "manual_review"
        )

    def test_failed_publication_requires_review(self):
        run, jobs, artifacts = evidence()
        run["conclusion"] = "failure"
        jobs[1]["conclusion"] = "failure"
        jobs[2]["conclusion"] = "success"
        self.assertEqual(
            self.classify(run, jobs, artifacts), "manual_review"
        )

    def test_successful_publication_without_temporary_artifact(self):
        run, jobs, artifacts = evidence()
        jobs[1]["conclusion"] = "success"
        jobs[2]["conclusion"] = "success"
        self.assertEqual(
            self.classify(run, jobs, []), "published"
        )

    def test_wrong_attempt_artifact(self):
        run, jobs, artifacts = evidence()
        run["run_attempt"] = 2
        self.assertEqual(
            self.classify(run, jobs, artifacts), "retry"
        )

    def test_wrong_event_is_ignored(self):
        run, jobs, artifacts = evidence()
        run["event"] = "pull_request"
        self.assertEqual(
            self.classify(run, jobs, artifacts), "unrelated"
        )

    def test_missing_validation_job(self):
        run, jobs, artifacts = evidence()
        self.assertEqual(
            self.classify(run, jobs[1:], artifacts), "manual_review"
        )

    def test_unknown_package_fails(self):
        run, jobs, artifacts = evidence()
        with self.assertRaises(ValueError):
            classify(
                run, jobs, artifacts,
                package="unregistered-package",
                target=FP,
                fingerprint=lambda sha, package: FP,
            )


if __name__ == "__main__":
    unittest.main()
