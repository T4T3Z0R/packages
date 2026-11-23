import os
import subprocess
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / (
    ".github/workflows/create-package-candidate-review.yml"
)


class CandidateWriteWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text()

    def test_only_manual_dispatch(self):
        self.assertIn(
            "on:\n  workflow_dispatch:\n", self.source
        )
        for event in (
            "  schedule:", "  push:", "  pull_request:",
            "  workflow_run:",
        ):
            self.assertNotIn(event, self.source)

    def test_owner_and_default_branch_guard(self):
        self.assertIn(
            'test "$GITHUB_EVENT_NAME" = workflow_dispatch',
            self.source,
        )
        self.assertIn(
            'test "$GITHUB_REF" = refs/heads/main',
            self.source,
        )
        self.assertIn(
            'test "$GITHUB_ACTOR" = T4T3Z0R',
            self.source,
        )
        self.assertIn(
            'test "$GITHUB_REPOSITORY" = T4T3Z0R/packages',
            self.source,
        )

    def test_ci_triggers_on_writer_changes(self):
        source = (
            ROOT / ".github/workflows/test-package-pipeline.yml"
        ).read_text()

        before, after = source.split("  pull_request:", 1)
        marker = (
            '      - ".github/workflows/'
            'create-package-candidate-review.yml"'
        )

        self.assertEqual(before.count(marker), 1)
        self.assertEqual(after.count(marker), 1)

    def test_authorization_guard_executes_correctly(self):
        lines = self.source.splitlines()

        start = lines.index(
            "      - name: Verify explicit owner authorization"
        )
        end = lines.index(
            "      - name: Install discovery dependencies"
        )
        self.assertLess(start, end)

        fragment = lines[start:end]
        marker = fragment.index("        run: |")

        script = textwrap.dedent(
            chr(10).join(fragment[marker + 1:])
        )
        self.assertTrue(
            script.startswith("set -euo pipefail")
        )

        env = dict(os.environ)
        env.update({
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "T4T3Z0R/packages",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_ACTOR": "T4T3Z0R",
            "GITHUB_TRIGGERING_ACTOR": "T4T3Z0R",
            "GITHUB_RUN_ATTEMPT": "1",
            "REQUESTED_CONFIRMATION": "CREATE REVIEW ISSUE",
        })

        def execute(context):
            return subprocess.run(
                ["bash"],
                input=script,
                env=context,
                text=True,
                capture_output=True,
            )

        success = execute(env)
        self.assertEqual(
            success.returncode, 0, success.stderr
        )

        invalid = {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REPOSITORY": "other/repo",
            "GITHUB_REF": "refs/heads/testing",
            "GITHUB_ACTOR": "intruder",
            "GITHUB_TRIGGERING_ACTOR": "intruder",
            "GITHUB_RUN_ATTEMPT": "2",
            "REQUESTED_CONFIRMATION": "wrong",
        }

        for key, value in invalid.items():
            with self.subTest(rejected=key):
                changed = dict(env)
                changed[key] = value
                self.assertNotEqual(
                    execute(changed).returncode, 0
                )

    def test_choices_match_approved_registry(self):
        import json

        manifest = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )

        expected = {
            name
            for name, config in manifest["packages"].items()
            if config["status"] == "approved"
            and config["auto_publish"] is False
        }

        choices = self.source.split(
            "        options:\n", 1
        )[1].split(
            "      candidate:\n", 1
        )[0]

        actual = {
            line.strip().removeprefix("- ")
            for line in choices.splitlines()
        }

        self.assertEqual(actual, expected)
        self.assertIn(
            "|".join(sorted(expected)), self.source
        )

    def test_explicit_confirmation(self):
        self.assertIn("type: choice", self.source)
        self.assertIn(
            "REQUESTED_CONFIRMATION: "
            "${{ inputs.confirmation }}",
            self.source,
        )
        self.assertIn(
            "test \"$REQUESTED_CONFIRMATION\" = "
            "'CREATE REVIEW ISSUE'",
            self.source,
        )

    def test_minimal_write_permissions(self):
        header = self.source.split(
            "\npermissions:", 1
        )[1].split("\nconcurrency:", 1)[0]
        self.assertIn("  contents: read", header)
        self.assertNotIn("issues: write", header)
        self.assertEqual(
            self.source.count("      issues: write"), 1
        )
        self.assertNotIn("actions: write", self.source)

    def test_serialized_and_not_cancelled(self):
        self.assertIn(
            "group: package-candidate-issue-writes",
            self.source,
        )
        self.assertIn(
            "cancel-in-progress: false", self.source
        )
        self.assertIn("queue: max", self.source)

    def test_live_exact_candidate_selection(self):
        for marker in (
            "report_upstream.py",
            "select_candidate_write.py",
            '--package "$REQUESTED_PACKAGE"',
            '--candidate "$REQUESTED_CANDIDATE"',
            "selected-report.json",
        ):
            self.assertIn(marker, self.source)
        self.assertLess(
            self.source.index("report_upstream.py"),
            self.source.index("select_candidate_write.py"),
        )

    def test_only_one_explicit_write(self):
        self.assertEqual(
            self.source.count(
                "CANDIDATE_ISSUE_WRITE_ENABLED:"
            ), 1
        )
        self.assertEqual(
            self.source.count(
                "selected-report.json --create"
            ), 1
        )
        self.assertIn("postwrite-review.json", self.source)
        self.assertIn("issue-write-result.json", self.source)

    def test_no_publication_access(self):
        for marker in (
            "ARCH_REPO_SIGNING_PASSPHRASE",
            "publish-repository.sh",
            "makepkg",
            "gh release upload",
        ):
            self.assertNotIn(marker, self.source)

    def test_new_candidate_notification_is_gated(self):
        self.assertIn(
            "id: verify_review", self.source
        )
        self.assertIn(
            "if: ${{ steps.verify_review.outputs.created_issue_number != '' }}",
            self.source,
        )
        self.assertIn(
            'if write["action"] == "created":',
            self.source,
        )
        self.assertIn(
            "created_issue_number=", self.source
        )
        self.assertEqual(
            self.source.count(
                "https://api.pushover.net/1/messages.json"
            ), 1
        )
        self.assertIn(
            "https://github.com/${GITHUB_REPOSITORY}/issues/${ISSUE_NUMBER}",
            self.source,
        )
        self.assertNotIn(
            "publish-repository.sh", self.source
        )

    def test_bounded_postwrite_verification(self):
        self.assertIn(
            "scripts/package-pipeline/verify_candidate_write.py",
            self.source,
        )
        self.assertNotIn(
            "selected-report.json | tee postwrite-review.json",
            self.source,
        )
        self.assertIn(
            "if: ${{ !cancelled() }}", self.source
        )

    def test_checkout_git_trust_is_command_scoped(self):
        self.assertEqual(
            self.source.count(
                'git -c safe.directory="$GITHUB_WORKSPACE" rev-parse HEAD'
            ), 1
        )
        self.assertNotIn("git config --global", self.source)
        self.assertNotIn("safe.directory=*", self.source)

    def test_checkout_credentials_disabled(self):
        self.assertIn(
            "uses: actions/checkout@v6", self.source
        )
        self.assertIn(
            "persist-credentials: false", self.source
        )
        self.assertIn(
            'test "$(git -c safe.directory="$GITHUB_WORKSPACE" rev-parse HEAD)" = "$GITHUB_SHA"',
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
