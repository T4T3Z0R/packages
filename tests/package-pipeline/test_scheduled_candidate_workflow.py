import os
import subprocess
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/check-package-upstream.yml"


class ScheduledCandidateWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text()
        cls.job = cls.source.split(
            "\n  write-reviews:\n", 1
        )[1]

    def test_manual_discovery_remains_read_only(self):
        discovery = self.source.split(
            "\n  write-reviews:\n", 1
        )[0]

        self.assertIn(
            "Evaluate candidate review history", discovery
        )
        self.assertNotIn(
            "CANDIDATE_ISSUE_WRITE_ENABLED", discovery
        )
        self.assertNotIn(
            "issues: write", discovery
        )

    def test_writer_is_schedule_only(self):
        self.assertIn(
            "if: ${{ github.repository == 'T4T3Z0R/packages' && github.ref == 'refs/heads/main' && (github.event_name == 'schedule') }}",
            self.job,
        )
        self.assertIn("needs: discover", self.job)

    def test_writer_permissions_and_serialization(self):
        self.assertEqual(
            self.source.count("      issues: write"), 1
        )
        self.assertNotIn("contents: write", self.job)
        self.assertIn(
            "group: package-candidate-issue-writes",
            self.job,
        )
        self.assertIn(
            "cancel-in-progress: false", self.job
        )

        manual = (
            ROOT / ".github/workflows/"
            "create-package-candidate-review.yml"
        ).read_text()

        self.assertIn(
            "group: package-candidate-issue-writes",
            manual,
        )

    def test_authorization_guard_executes(self):
        section = self.job.split(
            "      - name: Verify scheduled authorization\n", 1
        )[1].split(
            "      - name: Install discovery dependencies\n", 1
        )[0]

        script = textwrap.dedent(
            section.split("        run: |\n", 1)[1]
        )

        env = dict(os.environ)
        env.update({
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_REPOSITORY": "T4T3Z0R/packages",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ATTEMPT": "1",
        })

        def execute(values):
            return subprocess.run(
                ["bash"],
                input=script,
                text=True,
                capture_output=True,
                env=values,
            )

        success = execute(env)
        self.assertEqual(
            success.returncode, 0, success.stderr
        )

        for key, invalid in {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "other/repo",
            "GITHUB_REF": "refs/heads/feature",
            "GITHUB_RUN_ATTEMPT": "2",
        }.items():
            with self.subTest(rejected=key):
                changed = dict(env)
                changed[key] = invalid
                self.assertNotEqual(
                    execute(changed).returncode, 0
                )

    def test_discovery_evidence_is_same_run(self):
        artifact = (
            "upstream-report-${{ github.run_id }}"
        )

        self.assertEqual(
            self.source.count(
                "name: " + artifact
            ), 2
        )
        self.assertIn(
            "scheduled-input/upstream-report.json",
            self.job,
        )
        self.assertIn(
            "scheduled-input/candidate-review.json",
            self.job,
        )
        self.assertIn(
            'branches/main', self.job
        )

    def test_fresh_snapshot_precedes_issue_creation(self):
        self.assertIn(
            "verify_scheduled_snapshot.py", self.job
        )
        self.assertIn(
            "fresh-upstream-report.json", self.job
        )
        self.assertLess(
            self.job.index(
                "Revalidate upstream before candidate writes"
            ),
            self.job.index(
                "Create missing reviews with fresh history checks"
            ),
        )
        self.assertIn(
            "branches/main", self.job
        )

    def test_writer_and_verifier_are_separate(self):
        self.assertEqual(
            self.job.count(
                'CANDIDATE_ISSUE_WRITE_ENABLED: "1"'
            ), 1
        )
        self.assertIn(
            "run_candidate_reviews.py", self.job
        )
        self.assertIn(
            "verify_candidate_batch.py", self.job
        )
        self.assertLess(
            self.job.index("run_candidate_reviews.py"),
            self.job.index("verify_candidate_batch.py"),
        )
        self.assertIn(
            "created-review-issues.json", self.job
        )
        self.assertNotIn("makepkg", self.job)
        self.assertNotIn("publish-repository.sh", self.job)
        self.assertNotIn(
            "api.pushover.net", self.job
        )


if __name__ == "__main__":
    unittest.main()
