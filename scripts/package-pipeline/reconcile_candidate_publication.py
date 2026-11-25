#!/usr/bin/env python3
"""Reconcile approved candidate issues with protected publication evidence."""

import argparse
import json
import re
import subprocess
from pathlib import Path

from candidate_issue_state import classify as classify_issue
from github_candidate_issues import issue_history
from github_validation_history import (
    github_api,
    validation_runs,
    run_attempt_evidence,
    run_artifacts,
)
from merged_selection_validation import (
    collection,
    plan,
    TITLE,
    REVIEW,
)
from package_fingerprint import fingerprint
from package_release_contract import SUPPORTED
from validation_ledger import classify as classify_run

REPO = "T4T3Z0R/packages"
OWNER = "T4T3Z0R"
SHA = re.compile(r"[0-9a-f]{40}\Z")
MANIFEST = "arch/packages/manifest.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args],
        text=True,
        stderr=subprocess.PIPE,
    ).strip()


def ancestor(root, older, newer):
    for revision in (older, newer):
        require(
            isinstance(revision, str)
            and SHA.fullmatch(revision),
            "Invalid commit identity",
        )

        git(root, "cat-file", "-e", f"{revision}^{{commit}}")

    result = subprocess.run(
        [
            "git", "-C", str(root),
            "merge-base", "--is-ancestor",
            older, newer,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode not in (0, 1):
        result.check_returncode()

    return result.returncode == 0


def manifest(root, revision):
    return json.loads(
        git(root, "show", f"{revision}:{MANIFEST}")
    )


def approved_candidate(issue):
    if "pull_request" in issue:
        return None

    if issue.get("state") != "open":
        return None

    title = issue.get("title")

    match = TITLE.fullmatch(title) if isinstance(
        title, str
    ) else None

    if match is None:
        return None

    package, candidate = match.groups()

    if package not in SUPPORTED:
        return None

    result = classify_issue({"title": title}, [issue])

    if result["action"] != "approved":
        return None

    require(
        issue.get("user", {}).get("login")
        in (OWNER, "github-actions[bot]"),
        "Untrusted candidate issue author",
    )

    require(
        isinstance(issue.get("body"), str)
        and "<!-- t4t3z0r:candidate-alert:v1 -->"
        in issue["body"].splitlines(),
        "Missing candidate issue marker",
    )

    return package, candidate


def publication_evidence(
    root, api, package, candidate, selection, current
):
    """Find successful publication descended from the approved merge."""

    matches = []

    for run in validation_runs(api, REPO, package):
        if (
            run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run.get("event") != "workflow_dispatch"
            or run.get("head_branch") != "main"
        ):
            continue

        require(
            run.get("head_repository", {}).get("full_name") == REPO,
            "Unexpected publisher repository",
        )

        revision = run.get("head_sha")

        if not ancestor(root, selection, revision):
            continue

        require(
            ancestor(root, revision, current),
            "Publication revision outside production history",
        )

        config = manifest(root, revision)["packages"].get(package)

        if not isinstance(config, dict):
            continue

        if (
            config.get("status") != "approved"
            or config.get("source_ref") != candidate
            or config.get("auto_publish") is not False
        ):
            continue

        run_id = run.get("id")
        attempt = run.get("run_attempt")

        require(
            type(run_id) is int and run_id > 0
            and type(attempt) is int and attempt > 0,
            "Invalid publisher execution identity",
        )

        exact, jobs = run_attempt_evidence(
            api, REPO, run_id, attempt
        )

        for field in (
            "id", "head_sha", "event",
            "status", "conclusion", "run_attempt",
        ):
            require(
                exact.get(field) == run.get(field),
                f"Publisher attempt metadata changed: {field}",
            )

        target = fingerprint(root, revision, package)

        outcome = classify_run(
            exact,
            jobs,
            run_artifacts(api, REPO, run_id),
            package=package,
            target=target,
            fingerprint=lambda sha, name: fingerprint(
                root, sha, name
            ),
        )

        if outcome == "published":
            matches.append({
                "run_id": run_id,
                "attempt": attempt,
                "revision": revision,
                "fingerprint": target,
            })

    if not matches:
        return None

    return max(matches, key=lambda item: item["run_id"])


def reconcile(root, api, current):
    require(
        git(root, "rev-parse", "HEAD") == current,
        "Checkout does not match reconciliation revision",
    )

    issues = issue_history(api, REPO)

    approved = [
        (issue, result)
        for issue in issues
        if (result := approved_candidate(issue)) is not None
    ]

    if not approved:
        return []

    pulls = collection(
        api, f"repos/{REPO}/pulls?state=closed"
    )

    results = []

    for issue, (package, candidate) in approved:
        number = issue["number"]

        matches = [
            pr for pr in pulls
            if pr.get("merged_at") is not None
            and REVIEW.findall(pr.get("body") or "")
            == [str(number)]
        ]

        result = {
            "issue_number": number,
            "package": package,
            "candidate": candidate,
        }

        if not matches:
            results.append({
                **result,
                "decision": "awaiting_selection",
            })
            continue

        require(
            len(matches) == 1,
            "Ambiguous merged candidate selection",
        )

        pr = api(
            f"repos/{REPO}/pulls/{matches[0]['number']}"
        )

        require(
            pr.get("id") == matches[0].get("id"),
            "Selection PR identity mismatch",
        )

        selection = pr.get("merge_commit_sha")

        require(
            ancestor(root, selection, current),
            "Selection is not in production history",
        )

        parents = git(
            root, "show", "-s", "--format=%P", selection
        ).split()

        require(
            len(parents) == 2,
            "Expected a two-parent selection merge",
        )

        previous = parents[0]

        # Reconstruct the original merged-selection evidence.
        # This is a read-only plan, not a workflow authorization.
        event = {
            "ref": "refs/heads/main",
            "repository": {"full_name": REPO},
            "sender": {
                "login": pr.get("merged_by", {}).get("login")
            },
            "forced": False,
            "deleted": False,
            "before": previous,
            "after": selection,
        }

        verified = plan(
            event,
            manifest(root, previous),
            manifest(root, selection),
            [pr],
            issue,
            collection(
                api, f"repos/{REPO}/issues/{number}/events"
            ),
        )

        require(
            verified.get("decision") == "review_validation"
            and verified.get("package") == package
            and verified.get("selected") == candidate
            and verified.get("issue_number") == number,
            "Original selection verification failed",
        )

        evidence = publication_evidence(
            root, api, package, candidate,
            selection, current,
        )

        results.append({
            **result,
            "selection_pr": pr["number"],
            "selection_revision": selection,
            "decision": (
                "close_published"
                if evidence else "awaiting_publication"
            ),
            "publication": evidence,
        })

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]

    require(
        github_api(
            f"repos/{REPO}/branches/main"
        )["commit"]["sha"] == args.revision,
        "Production main moved",
    )

    print(json.dumps(
        reconcile(root, github_api, args.revision),
        indent=2,
        sort_keys=True,
    ))


if __name__ == "__main__":
    main()
