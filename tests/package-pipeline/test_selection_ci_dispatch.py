import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"


class SelectionCIDispatchTests(unittest.TestCase):
    def setUp(self):
        self.approval = (
            WORKFLOWS / "review-package-candidate-approval.yml"
        ).read_text()

        self.receiver = (
            WORKFLOWS / "test-package-pipeline.yml"
        ).read_text()

        self.pre_dispatch, self.dispatcher = self.approval.split(
            "\n  dispatch-selection-ci:", 1
        )

    def test_dispatch_permissions_are_isolated(self):
        self.assertNotIn("actions: write", self.pre_dispatch)
        self.assertIn("actions: write", self.dispatcher)

        for permission in (
            "contents: write",
            "pull-requests: write",
            "issues: write",
            "checks: write",
            "statuses: write",
            "id-token: write",
        ):
            self.assertNotIn(permission, self.dispatcher)

    def test_only_shared_ci_can_be_dispatched(self):
        self.assertEqual(
            self.dispatcher.count("gh workflow run "), 1
        )

        self.assertIn(
            "gh workflow run test-package-pipeline.yml",
            self.dispatcher,
        )

        self.assertIn(
            '--ref "$SELECTION_BRANCH"',
            self.dispatcher,
        )

        self.assertIn(
            'expected_revision="$EXPECTED_REVISION"',
            self.dispatcher,
        )

        self.assertNotIn("publish=true", self.dispatcher)
        self.assertNotIn("actions/checkout", self.dispatcher)
        self.assertNotIn("environment:", self.dispatcher)
        self.assertNotIn("secrets.", self.dispatcher)

    def test_receiver_remains_read_only(self):
        self.assertIn("workflow_dispatch:", self.receiver)
        self.assertIn("expected_revision:", self.receiver)
        self.assertIn("contents: read", self.receiver)

        self.assertNotIn(": write", self.receiver)
        self.assertNotIn("environment:", self.receiver)

        self.assertIn(
            "persist-credentials: false",
            self.receiver,
        )

    def test_receiver_revision_guard(self):
        self.assertIn(
            'test "$GITHUB_SHA" = "$EXPECTED_REVISION"',
            self.receiver,
        )

        self.assertIn(
            'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
            self.receiver,
        )

    def test_dispatcher_shell_syntax(self):
        script = self.dispatcher.split(
            "        run: |\n", 1
        )[1]

        script = "\n".join(
            line[10:] if line.startswith(" " * 10) else line
            for line in script.splitlines()
        ) + "\n"

        result = subprocess.run(
            ["bash", "-n"],
            input=script,
            text=True,
            capture_output=True,
        )

        self.assertEqual(
            result.returncode, 0, result.stderr
        )

    def test_workflow_ends_with_real_newline(self):
        self.assertTrue(self.approval.endswith("\n"))
        self.assertFalse(self.approval.endswith("\\n"))


if __name__ == "__main__":
    unittest.main()
