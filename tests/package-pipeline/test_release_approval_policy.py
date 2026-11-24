import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))
from release_approval_policy import verify

ENV = {
    "name": "arch-repo-publish",
    "can_admins_bypass": False,
    "deployment_branch_policy": {
        "protected_branches": False,
        "custom_branch_policies": True,
    },
    "protection_rules": [
        {"type": "required_reviewers", "prevent_self_review": False,
         "reviewers": [{"type": "User",
                        "reviewer": {"login": "T4T3Z0R"}}]},
        {"type": "branch_policy"},
    ],
}
BRANCHES = {
    "total_count": 1,
    "branch_policies": [{"name": "main", "type": "branch"}],
}


def api(environment=None, branches=None):
    env = copy.deepcopy(
        ENV if environment is None else environment
    )
    allowed = copy.deepcopy(
        BRANCHES if branches is None else branches
    )

    def fetch(endpoint):
        if endpoint.endswith("/arch-repo-publish"):
            return env
        if endpoint.endswith(
            "/deployment-branch-policies?per_page=100"
        ):
            return allowed
        raise AssertionError(f"Unexpected endpoint: {endpoint}")

    return fetch


class ApprovalPolicyTests(unittest.TestCase):
    def test_verified_production_policy(self):
        self.assertEqual(
            verify(api())["reviewer"], "T4T3Z0R"
        )

    def test_rejects_changed_environment_protection(self):
        mutations = (
            lambda e: e.update(can_admins_bypass=True),
            lambda e: e.update(protection_rules=[]),
            lambda e: e["protection_rules"][0].update(
                prevent_self_review=True
            ),
            lambda e: e["protection_rules"][0]["reviewers"][0][
                "reviewer"].update(login="other"),
            lambda e: e["protection_rules"][0]["reviewers"].append(
                {"type": "User", "reviewer": {"login": "other"}}
            ),
            lambda e: e.update(deployment_branch_policy=None),
            lambda e: e["protection_rules"].append(
                {"type": "wait_timer"}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=str(mutate)):
                env = copy.deepcopy(ENV)
                mutate(env)
                with self.assertRaises(ValueError):
                    verify(api(environment=env))

    def test_rejects_ambiguous_branch_policy(self):
        for branches in (
            {"total_count": 0, "branch_policies": []},
            {"total_count": 2, "branch_policies": [
                {"name": "main", "type": "branch"}, {"name": "develop", "type": "branch"}]},
            {"total_count": 1, "branch_policies": [
                {"name": "release", "type": "branch"}]},
            {"total_count": 2, "branch_policies": [
                {"name": "main", "type": "branch"}]},
        ):
            with self.subTest(branches=branches):
                with self.assertRaises(ValueError):
                    verify(api(branches=branches))

    def test_rejects_tag_or_missing_branch_type(self):
        for kind in ("tag", None, "branch-or-tag", ""):
            with self.subTest(kind=kind):
                config = copy.deepcopy(BRANCHES)

                if kind is None:
                    del config["branch_policies"][0]["type"]
                else:
                    config["branch_policies"][0]["type"] = kind

                with self.assertRaises(ValueError):
                    verify(api(branches=config))

    def test_api_failure_blocks(self):
        def unavailable(_endpoint):
            raise RuntimeError("GitHub unavailable")

        with self.assertRaises(RuntimeError):
            verify(unavailable)


if __name__ == "__main__":
    unittest.main()
