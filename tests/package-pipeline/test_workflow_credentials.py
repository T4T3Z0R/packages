"""Regression coverage for checkout credential persistence."""

from pathlib import Path
import unittest

import yaml


WORKFLOWS = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "workflows"
)


def checkout_violations(document):
    violations = []

    for job_name, job in document["jobs"].items():
        for index, step in enumerate(
            job.get("steps", []), start=1
        ):
            action = step.get("uses", "")

            if not action.lower().startswith(
                "actions/checkout@"
            ):
                continue

            inputs = step.get("with", {})

            if not isinstance(inputs, dict):
                violations.append((job_name, index))
                continue

            if inputs.get("persist-credentials") is not False:
                violations.append((job_name, index))

    return violations


class WorkflowCredentialTests(unittest.TestCase):
    def test_all_workflows_disable_checkout_persistence(self):
        paths = sorted(
            path
            for path in WORKFLOWS.iterdir()
            if path.suffix in {".yml", ".yaml"}
        )

        self.assertTrue(paths)

        checkout_count = 0

        for path in paths:
            with self.subTest(workflow=path.name):
                document = yaml.safe_load(path.read_text())

                self.assertIsInstance(document, dict)
                self.assertIsInstance(document["jobs"], dict)

                self.assertEqual(
                    checkout_violations(document),
                    [],
                )

                for job in document["jobs"].values():
                    for step in job.get("steps", []):
                        if step.get("uses", "").lower().startswith(
                            "actions/checkout@"
                        ):
                            checkout_count += 1

        self.assertGreater(checkout_count, 0)

    @staticmethod
    def fixture(*steps):
        return {
            "jobs": {
                "validate": {
                    "steps": list(steps),
                },
            },
        }

    def test_explicit_false_is_accepted(self):
        document = self.fixture({
            "uses": "actions/checkout@v6",
            "with": {"persist-credentials": False},
        })

        self.assertEqual(checkout_violations(document), [])

    def test_missing_inputs_are_rejected(self):
        document = self.fixture({
            "uses": "actions/checkout@v6",
        })

        self.assertEqual(
            checkout_violations(document),
            [("validate", 1)],
        )

    def test_missing_persistence_setting_is_rejected(self):
        document = self.fixture({
            "uses": "actions/checkout@v6",
            "with": {"fetch-depth": 0},
        })

        self.assertEqual(
            checkout_violations(document),
            [("validate", 1)],
        )

    def test_unsafe_persistence_values_are_rejected(self):
        for value in (
            True,
            "true",
            "false",
            None,
            0,
            "${{ inputs.persist_credentials }}",
        ):
            with self.subTest(value=value):
                document = self.fixture({
                    "uses": "actions/checkout@v6",
                    "with": {"persist-credentials": value},
                })

                self.assertEqual(
                    checkout_violations(document),
                    [("validate", 1)],
                )

    def test_malformed_inputs_are_rejected(self):
        for value in (None, [], "false"):
            with self.subTest(value=value):
                document = self.fixture({
                    "uses": "actions/checkout@v6",
                    "with": value,
                })

                self.assertEqual(
                    checkout_violations(document),
                    [("validate", 1)],
                )

    def test_pinned_checkout_is_covered(self):
        document = self.fixture({
            "uses": "actions/checkout@" + "a" * 40,
        })

        self.assertEqual(
            checkout_violations(document),
            [("validate", 1)],
        )

    def test_action_name_case_does_not_bypass_policy(self):
        document = self.fixture({
            "uses": "Actions/Checkout@v6",
        })

        self.assertEqual(
            checkout_violations(document),
            [("validate", 1)],
        )

    def test_every_checkout_is_checked(self):
        document = self.fixture(
            {
                "uses": "actions/checkout@v6",
                "with": {"persist-credentials": False},
            },
            {
                "uses": "actions/checkout@v6",
            },
        )

        document["jobs"]["publish"] = {
            "steps": [
                {"uses": "actions/checkout@v6"},
            ],
        }

        self.assertEqual(
            checkout_violations(document),
            [
                ("validate", 2),
                ("publish", 1),
            ],
        )

    def test_unrelated_actions_are_ignored(self):
        document = self.fixture(
            {"uses": "actions/upload-artifact@v8"},
            {"run": "echo validation"},
        )

        self.assertEqual(checkout_violations(document), [])


if __name__ == "__main__":
    unittest.main()
