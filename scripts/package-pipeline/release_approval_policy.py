"""Read-only fail-closed verification of the signing environment."""

REPOSITORY = "T4T3Z0R/packages"
ENVIRONMENT = "arch-repo-publish"
OWNER = "T4T3Z0R"


def require(ok, explanation):
    if not ok:
        raise ValueError(explanation)


def verify(api):
    base = f"repos/{REPOSITORY}/environments/{ENVIRONMENT}"
    env = api(base)
    require(isinstance(env, dict) and env.get("name") == ENVIRONMENT,
            "Missing or unexpected signing environment")
    require(env.get("can_admins_bypass") is False,
            "Administrator environment bypass must be disabled")

    policy = env.get("deployment_branch_policy")
    require(isinstance(policy, dict) and
            policy.get("protected_branches") is False and
            policy.get("custom_branch_policies") is True,
            "Signing environment must use main-only branch policy")

    rules = env.get("protection_rules")
    require(isinstance(rules, list) and len(rules) == 2 and
            {r.get("type") for r in rules if isinstance(r, dict)} ==
            {"required_reviewers", "branch_policy"},
            "Unexpected signing environment protection rules")

    review = next(
        r for r in rules if r["type"] == "required_reviewers"
    )
    require(review.get("prevent_self_review") is False,
            "Self-review must remain allowed for release owner")

    reviewers = review.get("reviewers")
    require(isinstance(reviewers, list) and len(reviewers) == 1 and
            isinstance(reviewers[0], dict) and
            reviewers[0].get("type") == "User" and
            isinstance(reviewers[0].get("reviewer"), dict) and
            reviewers[0]["reviewer"].get("login") == OWNER,
            "Signing reviewer must be exactly the repository owner")

    branches = api(f"{base}/deployment-branch-policies?per_page=100")
    require(isinstance(branches, dict) and
            type(branches.get("total_count")) is int and
            branches["total_count"] == 1 and
            isinstance(branches.get("branch_policies"), list) and
            len(branches["branch_policies"]) == 1 and
            isinstance(branches["branch_policies"][0], dict) and
            branches["branch_policies"][0].get("name") == "main" and
            branches["branch_policies"][0].get("type") == "branch",
            "Signing environment must allow exactly main")

    return {
        "environment": ENVIRONMENT,
        "reviewer": OWNER,
        "branch": "main",
        "admin_bypass": False,
    }
