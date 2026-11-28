"""Regression coverage for checkout credential persistence."""

from pathlib import Path
import copy
import re
import unittest

import yaml


WORKFLOWS = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "workflows"
)



class WorkflowLoader(yaml.SafeLoader):
    """Reject ambiguous Boolean aliases and duplicate mapping keys."""

    def construct_mapping(self, node, deep=False):
        keys = set()

        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=False)

            if key in keys:
                raise ValueError(f"Duplicate YAML mapping key: {key}")

            keys.add(key)

        return super().construct_mapping(node, deep=deep)


WorkflowLoader.yaml_implicit_resolvers = copy.deepcopy(
    yaml.SafeLoader.yaml_implicit_resolvers
)

for character, resolvers in list(
    WorkflowLoader.yaml_implicit_resolvers.items()
):
    WorkflowLoader.yaml_implicit_resolvers[character] = [
        (tag, pattern)
        for tag, pattern in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]

WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$"),
    list("tf"),
)


def load_workflow(source):
    return yaml.load(source, Loader=WorkflowLoader)


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
                document = load_workflow(path.read_text())

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



PRODUCTION_GUARD = (
    "github.repository == 'T4T3Z0R/packages' && "
    "github.ref == 'refs/heads/main'"
)

PUBLISHERS = {
    "publish-broot.yml",
    "publish-engrampa.yml",
    "publish-gameshell.yml",
    "publish-ghostty.yml",
    "publish-keepassxc.yml",
    "publish-moonlight-qt.yml",
    "publish-mousepad.yml",
    "publish-noctalia-custom.yml",
    "publish-noctalia-greeter.yml",
    "publish-syncthing.yml",
    "publish-thunar.yml",
    "publish-wezterm.yml",
    "publish-yazi.yml",
}

READ_ONLY = {"contents": "read"}

WRITERS = {
    (name, "publish"): {"contents": "write"}
    for name in PUBLISHERS
}

WRITERS.update({
    ("check-package-upstream.yml", "write-reviews"): {
        "contents": "read",
        "issues": "write",
    },
    ("create-package-candidate-review.yml", "create-review"): {
        "contents": "read",
        "issues": "write",
    },
    ("maintain-package-history.yml", "recover"): {
        "contents": "write",
    },
    ("package-validation-controller.yml", "dispatch-release-approval"): {
        "actions": "write",
        "contents": "read",
        "issues": "read",
        "pull-requests": "read",
    },
    ("reconcile-package-candidates.yml", "reconcile"): {
        "actions": "read",
        "contents": "read",
        "issues": "write",
        "pull-requests": "read",
    },
    ("review-package-candidate-approval.yml", "create-selection-pr"): {
        "contents": "write",
        "issues": "read",
        "pull-requests": "write",
    },
    ("review-package-candidate-approval.yml", "dispatch-selection-ci"): {
        "actions": "write",
        "contents": "read",
        "issues": "read",
        "pull-requests": "read",
    },
})

PROTECTED_JOBS = {
    (name, "publish") for name in PUBLISHERS
} | {
    ("maintain-package-history.yml", "recover"),
}

GUARDED_JOBS = set(WRITERS) | {
    (name, "approval-ready") for name in PUBLISHERS
}


def normalized_guard(condition):
    if not isinstance(condition, str):
        return ""

    condition = condition.strip()

    if condition.startswith("${{") and condition.endswith("}}"):
        condition = condition[3:-2].strip()

    return condition


def expected_guard(identity):
    workflow, job = identity

    if workflow in PUBLISHERS:
        if workflow == "publish-gameshell.yml":
            condition = (
                "needs.detect.outputs.update == 'true' && "
                "github.event_name == 'workflow_dispatch' && "
                "inputs.publish == true"
            )
        elif workflow in {
            "publish-noctalia-custom.yml",
            "publish-noctalia-greeter.yml",
        }:
            condition = "inputs.publish == true"
        else:
            condition = (
                "github.event_name == 'workflow_dispatch' && "
                "inputs.publish == true"
            )
    else:
        conditions = {
            ("check-package-upstream.yml", "write-reviews"):
                "github.event_name == 'schedule'",
            ("create-package-candidate-review.yml", "create-review"):
                None,
            ("maintain-package-history.yml", "recover"):
                "inputs.mode == 'recover' && "
                "github.ref == 'refs/heads/main'",
            ("package-validation-controller.yml", "dispatch-release-approval"):
                "github.event_name == 'push' && "
                "github.ref == 'refs/heads/main' && "
                "github.actor == 'T4T3Z0R' && "
                "needs.verify-merged-selection.outputs.decision == 'review_validation'",
            ("reconcile-package-candidates.yml", "reconcile"):
                "github.event_name != 'workflow_run' || "
                "github.event.workflow_run.conclusion == 'success'",
            ("review-package-candidate-approval.yml", "create-selection-pr"):
                "github.event_name == 'issues' && "
                "github.actor == 'T4T3Z0R' && "
                "(needs.evaluate.outputs.status == 'template_pr_ready' || "
                "needs.evaluate.outputs.status == 'fixed_pr_ready')",
            ("review-package-candidate-approval.yml", "dispatch-selection-ci"):
                "github.event_name == 'issues' && "
                "github.actor == 'T4T3Z0R' && "
                "needs.create-selection-pr.result == 'success'",
        }

        condition = conditions[identity]

    if condition is None:
        return PRODUCTION_GUARD

    return f"{PRODUCTION_GUARD} && ({condition})"


def permission_violations(filename, document):
    violations = []

    workflow_permissions = document.get("permissions")

    if not isinstance(workflow_permissions, dict):
        return ["Missing or non-explicit workflow permissions"]

    if any(value != "read" for value in workflow_permissions.values()):
        violations.append("Unexpected workflow-level authority")

    for name, job in document["jobs"].items():
        identity = (filename, name)

        permissions = job.get(
            "permissions",
            workflow_permissions,
        )

        if not isinstance(permissions, dict):
            violations.append(f"{name}: invalid permissions")
            continue

        expected = WRITERS.get(identity)

        if expected is not None:
            if job.get("permissions") != expected:
                violations.append(
                    f"{name}: incorrect explicit writer permissions"
                )
        elif any(value != "read" for value in permissions.values()):
            violations.append(
                f"{name}: unauthorized token permissions"
            )

        if identity in GUARDED_JOBS:
            if normalized_guard(job.get("if")) != expected_guard(identity):
                violations.append(f"{name}: incorrect production guard")

        if identity in PROTECTED_JOBS:
            if job.get("environment") != {"name": "arch-repo-publish"}:
                violations.append(f"{name}: incorrect publication environment")

    return violations


class WorkflowPermissionTests(unittest.TestCase):
    def test_workflow_permissions(self):
        paths = sorted(
            path for path in WORKFLOWS.iterdir()
            if path.suffix in {".yml", ".yaml"}
        )

        self.assertTrue(paths)

        observed_writers = set()
        observed_guards = set()
        observed_publishers = set()

        for path in paths:
            document = load_workflow(path.read_text())

            with self.subTest(workflow=path.name):
                self.assertEqual(
                    permission_violations(path.name, document),
                    [],
                )

                if path.name in PUBLISHERS:
                    observed_publishers.add(path.name)
                    self.assertEqual(document["permissions"], READ_ONLY)

                for name in document["jobs"]:
                    identity = (path.name, name)

                    if identity in WRITERS:
                        observed_writers.add(identity)

                    if identity in GUARDED_JOBS:
                        observed_guards.add(identity)

        self.assertEqual(observed_publishers, PUBLISHERS)
        self.assertEqual(observed_writers, set(WRITERS))
        self.assertEqual(observed_guards, GUARDED_JOBS)

    def test_implicit_or_broad_workflow_permissions_rejected(self):
        for permissions in (None, "write-all", "read-all",
                            {"contents": "write"}):
            with self.subTest(permissions=permissions):
                document = {
                    "permissions": permissions,
                    "jobs": {},
                }

                self.assertTrue(
                    permission_violations("example.yml", document)
                )

    def test_unapproved_writer_rejected(self):
        document = {
            "permissions": READ_ONLY,
            "jobs": {
                "validate": {
                    "permissions": {"contents": "write"},
                },
            },
        }

        self.assertTrue(
            permission_violations("example.yml", document)
        )

    def test_publication_boundary(self):
        filename = "publish-broot.yml"

        document = {
            "permissions": READ_ONLY,
            "jobs": {
                "publish": {
                    "permissions": {"contents": "write"},
                    "environment": {"name": "arch-repo-publish"},
                    "if": expected_guard((filename, "publish")),
                },
            },
        }

        self.assertEqual(
            permission_violations(filename, document),
            [],
        )

        mutations = (
            ("permissions", {"contents": "write", "actions": "write"}),
            ("permissions", {"contents": "read"}),
            ("environment", None),
            ("environment", {"name": "unprotected"}),
            ("if", None),
            ("if", PRODUCTION_GUARD),
            ("if", expected_guard((filename, "publish")) + " || true"),
            ("if", "inputs.publish == true"),
        )

        for key, value in mutations:
            with self.subTest(key=key, value=value):
                modified = copy.deepcopy(document)
                modified["jobs"]["publish"][key] = value

                self.assertTrue(
                    permission_violations(filename, modified)
                )

    def test_ambiguous_checkout_booleans_rejected(self):
        for value in ("off", "no", "False", "'false'", "0", "null"):
            with self.subTest(value=value):
                document = load_workflow(
                    "jobs:\n"
                    "  validate:\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v6\n"
                    "        with:\n"
                    f"          persist-credentials: {value}\n"
                )

                self.assertTrue(checkout_violations(document))

    def test_duplicate_mapping_keys_rejected(self):
        with self.assertRaises(ValueError):
            load_workflow(
                "permissions:\n"
                "  contents: write\n"
                "  contents: read\n"
            )


if __name__ == "__main__":
    unittest.main()
