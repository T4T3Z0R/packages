#!/usr/bin/env python3
"""Fresh, read-only source-selection handoff. Never write GitHub state."""

import argparse
import json
import re
from pathlib import Path

from candidate_approval_event import (
    OWNER, REPOSITORY, TITLE, approval_plan,
)
from candidate_issue_state import classify
from discover_upstream import DEFAULT_MANIFEST
from github_validation_history import github_api
from report_upstream import report
from select_package_validation import TEMPLATE_PACKAGES
from fixed_recipe_selection import FIXED_PACKAGES

MAX_PAGES = 100
PER_PAGE = 100


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pull_history(api):
    """Read open, closed, and merged PRs; reject incomplete history."""
    results = []
    identities = set()
    for page in range(1, MAX_PAGES + 1):
        endpoint = (
            f"repos/{REPOSITORY}/pulls?state=all"
            f"&sort=created&direction=asc"
            f"&per_page={PER_PAGE}&page={page}"
        )
        batch = api(endpoint)
        require(isinstance(batch, list), "Invalid PR history page")
        require(len(batch) <= PER_PAGE, "Oversized PR history page")

        for item in batch:
            require(isinstance(item, dict), "Malformed PR")
            identity = item.get("id")
            require(
                type(identity) is int and identity > 0,
                "Invalid PR identity",
            )
            require(identity not in identities, "Overlapping PR history")
            identities.add(identity)
            results.append(item)

        if len(batch) < PER_PAGE:
            return results

    raise ValueError("PR history exceeds pagination limit")


def plan(event, live_issue, upstream, pulls, manifest):
    """Return a decision requiring no GitHub writes."""
    require(isinstance(event, dict), "Malformed event")
    require(event.get("action") == "labeled", "Unexpected event")
    require(
        isinstance(event.get("repository"), dict)
        and event["repository"].get("full_name") == REPOSITORY,
        "Unexpected repository",
    )
    require(
        isinstance(event.get("sender"), dict)
        and event["sender"].get("login") == OWNER,
        "Unauthorized actor",
    )
    require(
        isinstance(event.get("label"), dict)
        and event["label"].get("name") == "candidate:approved",
        "Unexpected label",
    )

    original = event.get("issue")
    require(isinstance(original, dict), "Missing event issue")
    require(isinstance(live_issue, dict), "Missing live issue")

    number = original.get("number")
    identity = original.get("id")
    require(type(number) is int and number > 0, "Invalid issue number")
    require(type(identity) is int and identity > 0, "Invalid issue ID")

    for key in ("number", "id", "title", "body"):
        require(
            original.get(key) == live_issue.get(key),
            f"Issue changed since approval event: {key}",
        )

    original_author = original.get("user")
    live_author = live_issue.get("user")
    require(
        isinstance(original_author, dict)
        and isinstance(live_author, dict)
        and original_author.get("login") == live_author.get("login")
        and live_author.get("login") in (OWNER, "github-actions[bot]"),
        "Untrusted issue creator",
    )
    require(live_issue.get("state") == "open", "Review no longer open")

    title = live_issue.get("title")
    require(isinstance(title, str), "Missing title")
    match = TITLE.fullmatch(title)
    require(match is not None, "Invalid candidate title")
    package, candidate = match.groups()

    decision = classify({"title": title}, [live_issue])
    require(decision["action"] == "approved", "Approval no longer valid")

    require(
        isinstance(manifest, dict)
        and isinstance(manifest.get("packages"), dict),
        "Malformed manifest",
    )
    config = manifest["packages"].get(package)
    require(isinstance(config, dict), "Unknown package")
    require(config.get("status") == "approved", "Unapproved package")
    require(config.get("auto_publish") is False, "Auto-publication forbidden")

    selected = config.get("source_ref")
    require(isinstance(selected, str), "Invalid selected reference")

    result = {
        "issue_number": number,
        "package": package,
        "selected": selected,
        "candidate": candidate,
        "validation_dispatched": False,
        "pr_created": False,
        "publication_authorized": False,
    }

    # This also handles approved legacy issues whose source was selected
    # before the v1 issue marker was introduced, including issue #16.
    if selected == candidate:
        return {**result, "status": "already_selected"}

    fresh_event = dict(event)
    fresh_event["issue"] = live_issue
    authorized = approval_plan(fresh_event, manifest)
    require(authorized["issue_number"] == number, "Approval mismatch")

    require(isinstance(upstream, list), "Invalid upstream report")
    rows = [
        row for row in upstream
        if isinstance(row, dict) and row.get("package") == package
    ]
    require(len(rows) == 1, "Ambiguous upstream candidate")
    row = rows[0]
    require(
        row.get("status") == "update"
        and row.get("selected") == selected
        and row.get("candidate") == candidate,
        "Candidate is no longer the verified upstream update",
    )

    require(isinstance(pulls, list), "Invalid PR history")
    seen_ids = set()
    matches = []

    source_marker = re.compile(
        r"<!-- t4t3z0r:source-selection:v1 issue=[1-9][0-9]*"
        r" package=" + re.escape(package)
        + r" candidate=" + re.escape(candidate) + r" -->"
    )
    issue_marker = (
        f"<!-- t4t3z0r:source-selection:v1 issue={number}"
        f" package={package} candidate={candidate} -->"
    )
    legacy_marker = re.compile(
        rf"(?m)^Review issue: #{number}[ \t]*$"
    )
    branch = f"source-selection/issue-{number}-{package}"

    for pr in pulls:
        require(isinstance(pr, dict), "Malformed PR history")
        pr_id = pr.get("id")
        require(
            type(pr_id) is int and pr_id > 0,
            "Invalid historical PR ID",
        )
        require(pr_id not in seen_ids, "Duplicate historical PR")
        seen_ids.add(pr_id)

        base = pr.get("base")
        if not isinstance(base, dict) or base.get("ref") != "main":
            continue

        body = pr.get("body") or ""
        require(isinstance(body, str), "Invalid PR body")
        head = pr.get("head") or {}
        head_ref = head.get("ref") if isinstance(head, dict) else None

        if (
            issue_marker in body
            or source_marker.search(body) is not None
            or legacy_marker.search(body) is not None
            or head_ref == branch
        ):
            matches.append(pr)

    require(len(matches) <= 1, "Ambiguous existing source-selection PRs")

    if matches:
        prior = matches[0]
        pr_number = prior.get("number")
        require(
            type(pr_number) is int and pr_number > 0,
            "Invalid existing PR number",
        )
        return {
            **result,
            "status": "existing_selection_pr",
            "pr_number": pr_number,
            "pr_state": prior.get("state"),
            "pr_merged": prior.get("merged_at") is not None,
        }

    if package in TEMPLATE_PACKAGES:
        status = "template_pr_ready"
    elif package in FIXED_PACKAGES:
        status = "fixed_pr_ready"
    else:
        raise ValueError("Unsupported source-selection recipe")

    return {
        **result,
        "status": status,
        "branch": branch,
        "pr_title": f"Select {package} candidate {candidate}",
        "pr_marker": issue_marker,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("event", type=Path)
    parser.add_argument("--manifest", type=Path,
                        default=DEFAULT_MANIFEST)
    args = parser.parse_args()

    event = json.loads(args.event.read_text())
    issue = event.get("issue")
    if not isinstance(issue, dict):
        raise ValueError("Missing issue payload")
    number = issue.get("number")
    if type(number) is not int or number <= 0:
        raise ValueError("Invalid issue number")

    manifest = json.loads(args.manifest.read_text())

    current = github_api(f"repos/{REPOSITORY}/issues/{number}")
    pulls = pull_history(github_api)

    # Fresh upstream discovery, including policy and ancestry checks.
    upstream = report(manifest)

    print(json.dumps(
        plan(event, current, upstream, pulls, manifest),
        indent=2,
        sort_keys=True,
    ))


if __name__ == "__main__":
    main()
