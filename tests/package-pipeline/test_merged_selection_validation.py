import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from merged_selection_validation import changed_source, collection, plan

BEFORE = "a" * 40
AFTER = "b" * 40
WHEN = "2026-11-23T13:00:00Z"


def fixture(package="noctalia-custom", old="c" * 40, new="d" * 40):
    old_config = {"status": "approved", "auto_publish": False,
                  "source_ref": old, "release_policy": "reviewed-commit"}
    if package == "gameshell":
        old_config.update(release_policy="development-commit",
                          tracking_ref="refs/tags/latest")
    elif package == "noctalia-greeter-t4t3z0r":
        old_config["release_policy"] = "stable-git-tag"
    elif package in ("ghostty", "keepassxc", "syncthing"):
        old_config["release_policy"] = "stable-tag"
    elif package == "wezterm":
        old_config["release_policy"] = "development-commit"
    old_manifest = {"schema_version": 1, "packages": {package: old_config}}
    new_manifest = copy.deepcopy(old_manifest)
    new_manifest["packages"][package]["source_ref"] = new

    issue_number = 42
    marker = (f"<!-- t4t3z0r:source-selection:v1 issue={issue_number} "
              f"package={package} candidate={new} -->")
    review_line = f"Review issue: #{issue_number}"
    is_template = package in ("gameshell", "noctalia-custom",
                              "noctalia-greeter-t4t3z0r")
    branch = (f"source-selection/issue-{issue_number}-{package}"
              if is_template else "manual-source-selection")
    pr = {"id": 22, "number": 123, "merged_at": WHEN,
          "merged_by": {"login": "T4T3Z0R"}, "merge_commit_sha": AFTER,
          "base": {"ref": "main"}, "head": {"ref": branch},
          "body": f"{marker}\n{review_line}" if is_template else review_line}
    issue = {"number": issue_number, "state": "open",
             "title": f"Package candidate: {package} @ {new}",
             "user": {"login": "github-actions[bot]"},
             "labels": [{"name": "candidate:approved"}],
             "body": f"- Package: `{package}`\n- Selected: `{old}`\n"
                     f"- Candidate: `{new}`"}
    history = [{"id": 30, "event": "labeled", "created_at":
                "2026-11-23T12:00:00Z", "actor": {"login": "T4T3Z0R"},
                "label": {"name": "candidate:approved"}}]
    event = {"ref": "refs/heads/main", "before": BEFORE, "after": AFTER,
             "forced": False, "deleted": False,
             "repository": {"full_name": "T4T3Z0R/packages"},
             "sender": {"login": "T4T3Z0R"}}
    return [event, old_manifest, new_manifest, [pr], issue, history]


class MergedSelectionTests(unittest.TestCase):
    def test_seven_packages_use_only_unsigned_dispatch_inputs(self):
        for package, old, new, expected_workflow, inputs in (
            ("gameshell", "c"*40, "d"*40, "publish-gameshell.yml",
             {"publish": False, "source_ref": "latest"}),
            ("noctalia-custom", "c"*40, "d"*40,
             "publish-noctalia-custom.yml", {"publish": False, "source_ref": "d"*40}),
            ("noctalia-greeter-t4t3z0r", "v1.7.1", "v1.7.2",
             "publish-noctalia-greeter.yml", {"publish": False, "source_tag": "v1.7.2"}),
            ("ghostty", "v1.4.0", "v1.4.1", "publish-ghostty.yml", {"publish": False}),
            ("keepassxc", "2.8.0", "2.8.1", "publish-keepassxc.yml", {"publish": False}),
            ("syncthing", "v2.1.7", "v2.1.8", "publish-syncthing.yml", {"publish": False}),
            ("wezterm", "c"*40, "d"*40, "publish-wezterm.yml", {"publish": False}),
        ):
            with self.subTest(package=package):
                result = plan(*fixture(package, old, new))
                self.assertEqual(result["decision"], "review_validation")
                self.assertEqual(result["workflow"], expected_workflow)
                self.assertEqual(result["inputs"], inputs)
                self.assertFalse(result["validation_dispatched"])
                self.assertFalse(result["publication_authorized"])

    def test_exact_bootstrap_does_not_dispatch(self):
        after = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )
        before = copy.deepcopy(after)
        for name in (
            "noctalia-custom",
            "noctalia-greeter-t4t3z0r",
            "gameshell",
        ):
            before["packages"].pop(name)

        event = fixture()[0]
        result = plan(event, before, after, [])

        self.assertEqual(
            result["decision"], "bootstrap_registry_expansion"
        )
        self.assertFalse(result["validation_dispatched"])
        self.assertFalse(result["publication_authorized"])

    def test_bootstrap_changes_fail_closed(self):
        after = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )
        before = copy.deepcopy(after)
        for name in (
            "noctalia-custom",
            "noctalia-greeter-t4t3z0r",
            "gameshell",
        ):
            before["packages"].pop(name)

        changes = (
            lambda m: m["packages"]["gameshell"].update(
                source_ref="f" * 40
            ),
            lambda m: m["packages"]["gameshell"].update(
                auto_publish=True
            ),
            lambda m: m["packages"]["ghostty"].update(
                source_ref="v0.0.0"
            ),
            lambda m: m["packages"].pop("noctalia-custom"),
            lambda m: m["packages"].update(
                unexpected={"status": "approved"}
            ),
        )

        for index, change in enumerate(changes):
            with self.subTest(case=index):
                modified = copy.deepcopy(after)
                change(modified)
                with self.assertRaises(ValueError):
                    changed_source(before, modified)

        incomplete = copy.deepcopy(before)
        incomplete["packages"].pop("wezterm")
        with self.assertRaises(ValueError):
            changed_source(incomplete, after)

    def test_no_source_change_is_noop(self):
        args = fixture()
        args[2] = copy.deepcopy(args[1])
        self.assertEqual(plan(*args)["decision"], "no_source_change")

    def test_multiple_changes_fail_closed(self):
        args = fixture()
        args[1]["packages"]["ghostty"] = {"status": "approved", "auto_publish": False,
                                            "source_ref": "v1.4.0"}
        args[2]["packages"]["ghostty"] = {"status": "approved", "auto_publish": False,
                                            "source_ref": "v1.4.1"}
        with self.assertRaisesRegex(ValueError, "Multiple"):
            plan(*args)

    def test_other_manifest_field_modification_rejected(self):
        args = fixture()
        args[2]["packages"]["noctalia-custom"]["auto_publish"] = True
        with self.assertRaises(ValueError):
            plan(*args)

    def test_invalid_event_and_untrusted_pr_rejected(self):
        for mutate in (
            lambda a: a[0]["sender"].update(login="stranger"),
            lambda a: a[0].update(ref="refs/heads/feature"),
            lambda a: a[0].update(forced=True),
            lambda a: a[3][0].update(merge_commit_sha="c"*40),
            lambda a: a[3][0]["merged_by"].update(login="stranger"),
            lambda a: a[3][0]["base"].update(ref="development"),
            lambda a: a[3][0].update(body="no review issue"),
            lambda a: a[3][0]["head"].update(ref="unexpected"),
        ):
            with self.subTest(mutate=repr(mutate)):
                args = fixture()
                mutate(args)
                with self.assertRaises(ValueError):
                    plan(*args)

    def test_untrusted_or_revoked_issue_rejected(self):
        for mutate in (
            lambda a: a[4].update(state="closed", labels=[]),
            lambda a: a[4]["user"].update(login="stranger"),
            lambda a: a[4]["labels"].append({"name":"candidate:denied"}),
            lambda a: a[4].update(title="wrong title"),
            lambda a: a[4].update(body="malformed"),
            lambda a: a[5][0]["actor"].update(login="stranger"),
            lambda a: a[5][0].update(event="unlabeled"),
            lambda a: a[5][0].update(created_at="2026-11-23T14:00:00Z"),
        ):
            with self.subTest(mutate=repr(mutate)):
                args = fixture()
                mutate(args)
                with self.assertRaises(ValueError):
                    plan(*args)

    def test_owner_unlabels_after_approval_is_rejected(self):
        args = fixture()
        args[5].append({"id": 31, "event": "unlabeled",
                        "label": {"name": "candidate:approved"},
                        "created_at": "2026-11-23T12:01:00Z",
                        "actor": {"login": "T4T3Z0R"}})
        with self.assertRaises(ValueError):
            plan(*args)

    def test_legacy_wezterm_approval_accepted(self):
        args = fixture("wezterm", "c"*40, "d"*40)
        self.assertEqual(plan(*args)["decision"], "review_validation")

    def test_pagination_and_duplicates(self):
        calls = []
        def api(endpoint):
            calls.append(endpoint)
            if "page=2" in endpoint:
                return []
            return [{"id": n} for n in range(1, 101)]
        self.assertEqual(len(collection(api, "repos/T4T3Z0R/packages/issues/1/events")), 100)
        self.assertEqual(len(calls), 2)
        with self.assertRaises(ValueError):
            collection(lambda url: [{"id": 1}, {"id": 1}], "x")

    def test_controller_is_read_only_for_push(self):
        s = (ROOT / ".github/workflows/package-validation-controller.yml").read_text()
        self.assertIn("branches: [main]", s)
        self.assertIn("if: github.event_name == 'workflow_dispatch'", s)
        self.assertIn("name: Verify merged source selection", s)
        self.assertIn("pull-requests: read", s)
        self.assertIn("issues: read", s)
        reader = s.split("\n  dispatch-unsigned-validation:", 1)[0]
        self.assertNotIn("actions: write", reader)
        self.assertNotIn("contents: write", s)
        self.assertNotIn("gh workflow run", s)
        self.assertNotIn("--field publish=true", s)


if __name__ == "__main__":
    unittest.main()
