import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from candidate_selection_handoff import plan, pull_history

def fixture(package="ghostty", selected="v1.4.0", candidate="v1.4.1"):
    body = "\n".join((
        "## Upstream package candidate",
        "",
        "<!-- t4t3z0r:candidate-alert:v1 -->",
        "",
        f"- Package: `{package}`",
        f"- Selected: `{selected}`",
        f"- Candidate: `{candidate}`",
    ))
    issue = {
        "number": 42,
        "id": 424242,
        "state": "open",
        "title": f"Package candidate: {package} @ {candidate}",
        "body": body,
        "user": {"login": "github-actions[bot]"},
        "labels": [{"name": "candidate:approved"}],
    }
    event = {
        "action": "labeled",
        "repository": {"full_name": "T4T3Z0R/packages"},
        "sender": {"login": "T4T3Z0R"},
        "label": {"name": "candidate:approved"},
        "issue": copy.deepcopy(issue),
    }
    manifest = {"packages": {
        package: {
            "status": "approved",
            "auto_publish": False,
            "source_ref": selected,
        },
    }}
    upstream = [{
        "package": package,
        "status": "update",
        "selected": selected,
        "candidate": candidate,
    }]
    return event, issue, upstream, manifest


class HandoffTests(unittest.TestCase):
    def test_all_fixed_recipes_are_eligible(self):
        for package, selected, candidate in (
            ("ghostty", "v1.4.0", "v1.4.1"),
            ("keepassxc", "2.8.0", "2.8.1"),
            ("syncthing", "v2.1.7", "v2.1.8"),
            ("moonlight-qt", "v6.2.0", "v9.9.9"),
            ("wezterm", "a" * 40, "b" * 40),
        ):
            with self.subTest(package=package):
                e, issue, upstream, m = fixture(
                    package, selected, candidate
                )
                result = plan(e, issue, upstream, [], m)
                self.assertEqual(result["status"], "fixed_pr_ready")
                self.assertFalse(result["pr_created"])
                self.assertFalse(result["validation_dispatched"])
                self.assertFalse(result["publication_authorized"])
                self.assertEqual(
                    result["branch"],
                    f"source-selection/issue-42-{package}",
                )

    def test_three_generated_recipes_are_eligible(self):
        for package, selected, candidate in (
            ("gameshell", "a" * 40, "b" * 40),
            ("noctalia-custom", "a" * 40, "b" * 40),
            ("noctalia-greeter-t4t3z0r", "v1.7.1", "v1.7.2"),
        ):
            with self.subTest(package=package):
                e, issue, upstream, m = fixture(
                    package, selected, candidate
                )
                result = plan(e, issue, upstream, [], m)
                self.assertEqual(result["status"], "template_pr_ready")
                self.assertFalse(result["pr_created"])

    def test_already_selected_legacy_approval_is_noop(self):
        e, issue, upstream, m = fixture(
            "wezterm", "a" * 40, "b" * 40
        )
        m["packages"]["wezterm"]["source_ref"] = "b" * 40
        issue["body"] = "Legacy approval; no v1 marker"
        e["issue"]["body"] = issue["body"]
        result = plan(e, issue, upstream, [], m)
        self.assertEqual(result["status"], "already_selected")

    def test_existing_selection_pr_blocks_recreation(self):
        e, issue, upstream, m = fixture()
        pr = {
            "id": 99,
            "number": 18,
            "state": "closed",
            "merged_at": "2026-11-23T00:00:00Z",
            "base": {"ref": "main"},
            "body": "Review issue: #42\n",
        }
        result = plan(e, issue, upstream, [pr], m)
        self.assertEqual(result["status"], "existing_selection_pr")
        self.assertTrue(result["pr_merged"])

    def test_stale_or_changed_inputs_fail_closed(self):
        changes = (
            lambda e, i, u, m: e["sender"].update(login="stranger"),
            lambda e, i, u, m: i.update(id=999),
            lambda e, i, u, m: i.update(body="edited"),
            lambda e, i, u, m: i.update(labels=[]),
            lambda e, i, u, m: i["labels"].append(
                {"name": "candidate:denied"}
            ),
            lambda e, i, u, m: u[0].update(candidate="v9.9.9"),
            lambda e, i, u, m: u[0].update(status="blocked"),
            lambda e, i, u, m: m["packages"]["ghostty"].update(
                auto_publish=True
            ),
        )
        for index, modify in enumerate(changes):
            with self.subTest(index=index):
                e, issue, upstream, m = fixture()
                modify(e, issue, upstream, m)
                with self.assertRaises(ValueError):
                    plan(e, issue, upstream, [], m)

    def test_duplicate_prs_fail_closed(self):
        e, issue, upstream, m = fixture()
        pr = {
            "id": 91,
            "number": 21,
            "state": "open",
            "base": {"ref": "main"},
            "body": "Review issue: #42",
        }
        other = dict(pr, id=92, number=22)
        with self.assertRaises(ValueError):
            plan(e, issue, upstream, [pr, other], m)

    def test_paginated_pr_history(self):
        calls = []
        def api(endpoint):
            calls.append(endpoint)
            return [] if "page=2" in endpoint else [
                {"id": n} for n in range(1, 101)
            ]
        items = pull_history(api)
        self.assertEqual(len(items), 100)
        self.assertEqual(len(calls), 2)

    def test_workflow_stays_read_only(self):
        workflow = (
            ROOT / ".github/workflows"
            / "review-package-candidate-approval.yml"
        ).read_text()
        evaluate = workflow.split("\n  create-selection-pr:", 1)[0]
        self.assertIn("issues: read", workflow)
        self.assertIn("pull-requests: read", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("GITHUB_RUN_ATTEMPT", workflow)
        self.assertNotIn("contents: write", evaluate)
        self.assertNotIn("gh pr create", evaluate)
        self.assertNotIn("gh workflow run", workflow)


if __name__ == "__main__":
    unittest.main()
