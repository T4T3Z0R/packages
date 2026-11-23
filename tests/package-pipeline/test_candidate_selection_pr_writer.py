import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from candidate_selection_pr_writer import render

MANIFEST = json.loads(
    (ROOT / "arch/packages/manifest.json").read_text()
)
ORIGINAL = json.dumps(MANIFEST, indent=2) + "\n"


def fixture(package, candidate):
    selected = MANIFEST["packages"][package]["source_ref"]
    number = 42
    return {
        "status": "template_pr_ready",
        "package": package,
        "selected": selected,
        "candidate": candidate,
        "issue_number": number,
        "branch": f"source-selection/issue-{number}-{package}",
        "pr_marker": (
            f"<!-- t4t3z0r:source-selection:v1 issue={number}"
            f" package={package} candidate={candidate} -->"
        ),
        "pr_title": f"Select {package} candidate {candidate}",
        "pr_created": False,
        "validation_dispatched": False,
        "publication_authorized": False,
    }


class SourceSelectionWriterTests(unittest.TestCase):
    def test_three_generated_recipe_packages(self):
        candidates = {
            "gameshell": "b" * 40,
            "noctalia-custom": "c" * 40,
            "noctalia-greeter-t4t3z0r": "v9.9.9",
        }

        for package, candidate in candidates.items():
            with self.subTest(package=package):
                plan = fixture(package, candidate)
                updated, body = render(ORIGINAL, plan)

                expected = copy.deepcopy(MANIFEST)
                expected["packages"][package]["source_ref"] = candidate

                self.assertEqual(json.loads(updated), expected)
                self.assertIn(plan["pr_marker"], body)
                self.assertIn("Requires human PR review", body)
                self.assertIn("No signing or publication", body)

    def test_fixed_recipe_packages_rejected(self):
        for package in ("ghostty", "keepassxc", "syncthing", "wezterm"):
            with self.subTest(package=package):
                plan = fixture(package, "d" * 40)
                with self.assertRaises(ValueError):
                    render(ORIGINAL, plan)

    def test_stale_manifest_rejected(self):
        plan = fixture("gameshell", "e" * 40)
        plan["selected"] = "f" * 40
        with self.assertRaises(ValueError):
            render(ORIGINAL, plan)

    def test_unapproved_manifest_rejected(self):
        altered = copy.deepcopy(MANIFEST)
        altered["packages"]["gameshell"]["status"] = "candidate"
        plan = fixture("gameshell", "e" * 40)

        with self.assertRaises(ValueError):
            render(json.dumps(altered, indent=2) + "\n", plan)

    def test_malformed_or_untrusted_plan_rejected(self):
        cases = (
            lambda p: p.update(status="existing_selection_pr"),
            lambda p: p.update(pr_created=True),
            lambda p: p.update(validation_dispatched=True),
            lambda p: p.update(publication_authorized=True),
            lambda p: p.update(issue_number=0),
            lambda p: p.update(branch="some-other-branch"),
            lambda p: p.update(pr_marker="incorrect"),
            lambda p: p.update(pr_title="incorrect"),
            lambda p: p.update(candidate="not-a-commit"),
        )
        for i, change in enumerate(cases):
            with self.subTest(case=i):
                plan = fixture("gameshell", "e" * 40)
                change(plan)
                with self.assertRaises(ValueError):
                    render(ORIGINAL, plan)

    def test_writer_permissions_are_isolated(self):
        source = (
            ROOT / ".github/workflows"
            / "review-package-candidate-approval.yml"
        ).read_text()

        evaluate, writer = source.split(
            "\n  create-selection-pr:", 1
        )
        self.assertNotIn("contents: write", evaluate)
        self.assertNotIn("pull-requests: write", evaluate)
        self.assertIn("contents: write", writer)
        self.assertIn("pull-requests: write", writer)
        self.assertIn(
            "needs.evaluate.outputs.status == 'template_pr_ready'",
            writer,
        )
        self.assertIn("--draft", writer)
        self.assertIn("GITHUB_RUN_ATTEMPT", writer)
        self.assertNotIn("gh workflow run", writer)
        self.assertNotIn("publish=true", writer)


if __name__ == "__main__":
    unittest.main()
