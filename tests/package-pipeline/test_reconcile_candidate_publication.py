import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

import reconcile_candidate_publication as module

from package_release_contract import (
    SUPPORTED,
    VALIDATION_JOBS,
    TEMPLATE_PACKAGES,
)

REPO = module.REPO
SELECTION = "a" * 40
REVISION = "b" * 40
CURRENT = "c" * 40
CANDIDATE = "d" * 40
FP = "e" * 64


class CandidateTests(unittest.TestCase):
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

    def test_approved_candidate(self):
        self.assertEqual(
            module.approved_candidate(self.issue),
            ("noctalia-custom", CANDIDATE),
        )

    def test_closed_candidate_ignored(self):
        self.issue["state"] = "closed"
        self.assertIsNone(
            module.approved_candidate(self.issue)
        )

    def test_other_decisions_ignored(self):
        for label in (
            "candidate:denied",
            "candidate:postponed",
            "candidate:pinned",
        ):
            with self.subTest(label=label):
                self.issue["labels"] = [{"name": label}]
                self.assertIsNone(
                    module.approved_candidate(self.issue)
                )

    def test_conflicting_decisions_rejected(self):
        self.issue["labels"].append(
            {"name": "candidate:denied"}
        )
        with self.assertRaises(ValueError):
            module.approved_candidate(self.issue)

    def test_untrusted_author_rejected(self):
        self.issue["user"]["login"] = "unknown"
        with self.assertRaises(ValueError):
            module.approved_candidate(self.issue)

    def test_missing_marker_rejected(self):
        self.issue["body"] = "No evidence"
        with self.assertRaises(ValueError):
            module.approved_candidate(self.issue)

    def test_pull_request_ignored(self):
        self.issue["pull_request"] = {}
        self.assertIsNone(
            module.approved_candidate(self.issue)
        )


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.package = "noctalia-custom"

        self.run = {
            "id": 123,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": REVISION,
            "head_repository": {"full_name": REPO},
        }

        self.config = {
            "status": "approved",
            "source_ref": CANDIDATE,
            "auto_publish": False,
        }

        self.jobs = self.jobs_for(self.package)
        self.exact = None
        self.ancestry = True

    def jobs_for(self, package):
        steps = [{
            "name": "Upload unsigned candidate and evidence",
            "conclusion": "success",
        }]

        if package in TEMPLATE_PACKAGES:
            steps.append({
                "name": "Verify selected manifest source",
                "conclusion": "success",
            })

        return [
            {
                "name": VALIDATION_JOBS[package],
                "conclusion": "success",
                "steps": steps,
            },
            {
                "name": "Notify signing approval ready",
                "conclusion": "success",
            },
            {
                "name": "Sign and publish approved candidate",
                "conclusion": "success",
            },
        ]

    def check(self):
        with (
            patch.object(
                module, "validation_runs",
                return_value=[self.run],
            ),
            patch.object(
                module, "ancestor",
                side_effect=(
                    self.ancestry
                    if isinstance(self.ancestry, list)
                    else None
                ),
                return_value=True,
            ),
            patch.object(
                module, "manifest",
                return_value={
                    "packages": {
                        self.package: self.config
                    }
                },
            ),
            patch.object(
                module, "run_attempt_evidence",
                return_value=(
                    self.exact or copy.deepcopy(self.run),
                    self.jobs,
                ),
            ),
            patch.object(
                module, "run_artifacts",
                return_value=[],
            ),
            patch.object(
                module, "fingerprint",
                return_value=FP,
            ) as fingerprint,
        ):
            result = module.publication_evidence(
                ROOT, None, self.package, CANDIDATE,
                SELECTION, CURRENT,
            )

            for call in fingerprint.call_args_list:
                self.assertEqual(call.args[1], REVISION)

            return result

    def test_all_eight_publishers(self):
        for package in SUPPORTED:
            with self.subTest(package=package):
                self.package = package
                self.jobs = self.jobs_for(package)

                result = self.check()

                self.assertEqual(result["run_id"], 123)
                self.assertEqual(
                    result["revision"], REVISION
                )
                self.assertEqual(
                    result["fingerprint"], FP
                )

    def test_unsigned_validation_not_publication(self):
        self.jobs[1]["conclusion"] = "skipped"
        self.jobs[2]["conclusion"] = "skipped"

        self.assertIsNone(self.check())

    def test_failed_publication_not_accepted(self):
        self.jobs[2]["conclusion"] = "failure"

        self.assertIsNone(self.check())

    def test_missing_validation_job_not_accepted(self):
        self.jobs.pop(0)

        self.assertIsNone(self.check())

    def test_missing_source_binding_not_accepted(self):
        self.jobs[0]["steps"].pop()

        self.assertIsNone(self.check())

    def test_wrong_source_not_accepted(self):
        self.config["source_ref"] = "f" * 40

        self.assertIsNone(self.check())

    def test_failed_run_not_accepted(self):
        self.run["conclusion"] = "failure"

        self.assertIsNone(self.check())

    def test_active_run_not_accepted(self):
        self.run["status"] = "in_progress"

        self.assertIsNone(self.check())

    def test_non_main_run_not_accepted(self):
        self.run["head_branch"] = "feature/test"

        self.assertIsNone(self.check())

    def test_wrong_repository_rejected(self):
        self.run["head_repository"]["full_name"] = (
            "other/packages"
        )

        with self.assertRaises(ValueError):
            self.check()

    def test_pre_selection_run_ignored(self):
        self.ancestry = [False]

        self.assertIsNone(self.check())

    def test_nonproduction_revision_rejected(self):
        self.ancestry = [True, False]

        with self.assertRaises(ValueError):
            self.check()

    def test_changed_attempt_metadata_rejected(self):
        self.exact = copy.deepcopy(self.run)
        self.exact["head_sha"] = "f" * 40

        with self.assertRaises(ValueError):
            self.check()


if __name__ == "__main__":
    unittest.main()
