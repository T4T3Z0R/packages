import json
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from github_candidate_writer import create_issue

TITLE = "Package candidate: ghostty @ v1.5.0"
BODY = "Review upstream candidate."


def response(title=TITLE, number=42):
    return {
        "id": 1042,
        "number": number,
        "title": title,
        "state": "open",
        "labels": [],
    }


class CandidateWriterTests(unittest.TestCase):
    def test_authenticated_api_request(self):
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(
                stdout=json.dumps(response())
            )

        result = create_issue(TITLE, BODY, runner=runner)

        self.assertEqual(result["number"], 42)
        self.assertEqual(len(calls), 1)

        command, kwargs = calls[0]

        self.assertEqual(command[:3], [
            "gh", "api", "--method"
        ])
        self.assertIn("POST", command)
        self.assertIn(
            "repos/T4T3Z0R/packages/issues",
            command,
        )
        self.assertIn(f"title={TITLE}", command)
        self.assertIn(f"body={BODY}", command)
        self.assertTrue(kwargs["check"])

    def test_no_shell_interpretation(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(
                stdout=json.dumps(response())
            )

        body = "Text; $(touch /tmp/should-not-execute)"
        create_issue(TITLE, body, runner=runner)

        self.assertIn(f"body={body}", calls[0])
        self.assertEqual(len(calls), 1)

    def test_invalid_title_prevents_request(self):
        def runner(*args, **kwargs):
            self.fail("Unexpected GitHub request")

        with self.assertRaises(ValueError):
            create_issue(
                "Unrelated issue",
                BODY,
                runner=runner,
            )

    def test_empty_body_prevents_request(self):
        def runner(*args, **kwargs):
            self.fail("Unexpected GitHub request")

        with self.assertRaises(ValueError):
            create_issue(TITLE, " ", runner=runner)

    def test_api_failure_not_retried(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            raise subprocess.CalledProcessError(
                1, command
            )

        with self.assertRaises(
            subprocess.CalledProcessError
        ):
            create_issue(TITLE, BODY, runner=runner)

        self.assertEqual(len(calls), 1)

    def test_invalid_json_fails_closed(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(stdout="not-json")

        with self.assertRaises(json.JSONDecodeError):
            create_issue(TITLE, BODY, runner=runner)

        self.assertEqual(len(calls), 1)

    def test_non_object_response_rejected(self):
        def runner(command, **kwargs):
            return SimpleNamespace(stdout="[]")

        with self.assertRaises(ValueError):
            create_issue(TITLE, BODY, runner=runner)

    def test_development_commit_title(self):
        commit = "a" * 40
        title = f"Package candidate: wezterm @ {commit}"

        def runner(command, **kwargs):
            return SimpleNamespace(
                stdout=json.dumps(response(title))
            )

        result = create_issue(
            title, BODY, runner=runner
        )

        self.assertEqual(result["title"], title)


if __name__ == "__main__":
    unittest.main()
