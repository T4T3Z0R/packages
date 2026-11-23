import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from candidate_approval_event import approval_plan


def fixture(package="ghostty", selected="v1.4.0", candidate="v1.4.1"):
    manifest = {
        "packages": {
            package: {
                "status": "approved",
                "source_ref": selected,
                "auto_publish": False,
            }
        }
    }

    body = "\n".join((
        "## Upstream package candidate",
        "",
        "<!-- t4t3z0r:candidate-alert:v1 -->",
        "",
        f"- Package: `{package}`",
        f"- Selected: `{selected}`",
        f"- Candidate: `{candidate}`",
    ))

    event = {
        "action": "labeled",
        "repository": {"full_name": "T4T3Z0R/packages"},
        "sender": {"login": "T4T3Z0R"},
        "label": {"name": "candidate:approved"},
        "issue": {
            "number": 42,
            "state": "open",
            "title": f"Package candidate: {package} @ {candidate}",
            "body": body,
            "user": {"login": "github-actions[bot]"},
            "labels": [{"name": "candidate:approved"}],
        },
    }

    return event, manifest


class ApprovalEventTests(unittest.TestCase):
    def test_authorized_approval_is_read_only(self):
        event, manifest = fixture()
        result = approval_plan(event, manifest)

        self.assertTrue(result["authorized"])
        self.assertEqual(result["issue_number"], 42)
        self.assertEqual(
            result["next_action"],
            "source_selection_review_required",
        )
        self.assertFalse(result["validation_dispatched"])
        self.assertFalse(result["publication_authorized"])

    def test_all_seven_packages_are_supported(self):
        manifest = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )

        for package, config in manifest["packages"].items():
            if config["status"] != "approved":
                continue

            with self.subTest(package=package):
                event, _ = fixture(
                    package,
                    config["source_ref"],
                    "candidate-test",
                )
                result = approval_plan(event, manifest)
                self.assertEqual(result["package"], package)

    def test_untrusted_events_are_rejected(self):
        cases = (
            lambda e, m: e["sender"].update(login="someone-else"),
            lambda e, m: e["repository"].update(full_name="other/repo"),
            lambda e, m: e.update(action="edited"),
            lambda e, m: e["label"].update(name="candidate:denied"),
            lambda e, m: e["issue"].update(state="closed"),
            lambda e, m: e["issue"].update(pull_request={}),
            lambda e, m: e["issue"]["user"].update(login="stranger"),
            lambda e, m: e["issue"].update(title="Unrelated issue"),
            lambda e, m: e["issue"].update(body="Arbitrary text"),
            lambda e, m: e["issue"].update(labels=[]),
            lambda e, m: e["issue"]["labels"].append(
                {"name": "candidate:denied"}
            ),
            lambda e, m: m["packages"]["ghostty"].update(
                status="candidate"
            ),
            lambda e, m: m["packages"]["ghostty"].update(
                auto_publish=True
            ),
            lambda e, m: m["packages"]["ghostty"].update(
                source_ref="v1.4.2"
            ),
            lambda e, m: m["packages"]["ghostty"].update(
                source_ref="v1.4.1"
            ),
        )

        for index, change in enumerate(cases):
            with self.subTest(case=index):
                event, manifest = fixture()
                change(event, manifest)

                with self.assertRaises(ValueError):
                    approval_plan(event, manifest)

    def test_duplicate_issue_evidence_rejected(self):
        event, manifest = fixture()
        event["issue"]["body"] += "\n- Candidate: `v1.4.1`"

        with self.assertRaises(ValueError):
            approval_plan(event, manifest)

    def test_workflow_has_read_only_permissions(self):
        workflow = (
            ROOT / ".github/workflows"
            / "review-package-candidate-approval.yml"
        ).read_text()
        evaluate = workflow.split("\n  create-selection-pr:", 1)[0]

        self.assertIn("types: [labeled]", workflow)
        self.assertIn("issues: read", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("GITHUB_RUN_ATTEMPT", workflow)
        self.assertIn("GITHUB_SHA", workflow)
        self.assertNotIn("issues: write", workflow)
        self.assertNotIn("contents: write", evaluate)
        self.assertNotIn("gh workflow run", workflow)
        self.assertNotIn("gh pr create", evaluate)


if __name__ == "__main__":
    unittest.main()
