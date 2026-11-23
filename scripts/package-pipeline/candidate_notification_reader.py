#!/usr/bin/env python3
"""Read-only inventory of candidate notification outbox issues.

No issue/comment writes, Pushover requests, workflow dispatch, or publishing.
"""

import argparse
import json
from pathlib import Path

from candidate_notification_state import (
    ISSUE_MARKER,
    TITLE,
    TRUSTED_AUTHOR,
    classify,
)
from github_candidate_issues import REPOSITORY, issue_history
from github_validation_history import github_api

PER_PAGE = 100
MAX_COMMENTS = 10000


def issue_comments(api, issue_number, declared_count, repo=REPOSITORY):
    """Read a complete comment snapshot or fail on inconsistent pagination."""
    if repo != REPOSITORY:
        raise ValueError("Unexpected repository")
    if type(issue_number) is not int or issue_number < 1:
        raise ValueError("Invalid issue number")
    if (
        type(declared_count) is not int
        or not 0 <= declared_count <= MAX_COMMENTS
    ):
        raise ValueError("Invalid issue comment count")

    comments = []
    pages = max(1, (declared_count + PER_PAGE - 1) // PER_PAGE)

    for page in range(1, pages + 1):
        endpoint = (
            f"repos/{repo}/issues/{issue_number}/comments"
            f"?per_page={PER_PAGE}&page={page}"
        )
        batch = api(endpoint)
        if not isinstance(batch, list):
            raise ValueError("Invalid issue comments response")

        remaining = declared_count - len(comments)
        required = min(PER_PAGE, remaining)
        if len(batch) != required:
            raise ValueError("Incomplete or changed issue comment history")
        comments.extend(batch)

    # A full final page can conceal newly appended comments
    # after the issue's reported comment count was retrieved.
    # Check the next page rather than accepting a truncated view.
    if declared_count > 0 and declared_count % PER_PAGE == 0:
        endpoint = (
            f"repos/{repo}/issues/{issue_number}/comments"
            f"?per_page={PER_PAGE}&page={pages + 1}"
        )
        overflow = api(endpoint)
        if not isinstance(overflow, list) or overflow:
            raise ValueError(
                "Incomplete or changed issue comment history"
            )

    return comments


def inspect_outbox(manifest, api, repo=REPOSITORY):
    """Inventory marked issues and identify eligible unsent notifications."""
    if repo != REPOSITORY:
        raise ValueError("Unexpected repository")
    if not isinstance(manifest, dict) or not isinstance(
        manifest.get("packages"), dict
    ):
        raise ValueError("Invalid package manifest")
    if not callable(api):
        raise ValueError("Missing GitHub reader")

    registry = manifest["packages"]
    seen = set()
    results = []

    for issue in issue_history(api, repo):
        body = issue.get("body")
        if not isinstance(body, str) or ISSUE_MARKER not in body:
            continue

        if "pull_request" in issue:
            raise ValueError("Notification marker belongs to a PR")
        author = issue.get("user")
        if (
            not isinstance(author, dict)
            or author.get("login") != TRUSTED_AUTHOR
        ):
            raise ValueError("Untrusted outbox issue author")

        title = issue.get("title")
        match = TITLE.fullmatch(title) if isinstance(title, str) else None
        if match is None:
            raise ValueError("Invalid outbox issue title")
        package, candidate = match.group("package", "candidate")
        config = registry.get(package)
        if (
            not isinstance(config, dict)
            or config.get("status") != "approved"
            or config.get("auto_publish") is not False
        ):
            raise ValueError("Outbox package is not approved")

        if title in seen:
            raise ValueError("Duplicate outbox candidate identity")
        seen.add(title)

        comments = issue_comments(
            api, issue.get("number"), issue.get("comments"), repo
        )
        outcome = classify(issue, comments)
        if outcome["state"] == "legacy":
            raise ValueError("Marked issue classified as legacy")

        labels = issue.get("labels")
        if not isinstance(labels, list):
            raise ValueError("Missing outbox issue labels")
        names = set()
        for label in labels:
            name = label if isinstance(label, str) else (
                label.get("name") if isinstance(label, dict) else None
            )
            if not isinstance(name, str):
                raise ValueError("Invalid outbox issue label")
            names.add(name)

        decisions = sorted(n for n in names if n.startswith("candidate:"))
        if len(decisions) > 1:
            raise ValueError("Conflicting candidate decisions")

        row = {
            "issue_number": outcome["issue_number"],
            "package": package,
            "candidate": candidate,
            "state": outcome["state"],
            "decision": decisions[0] if decisions else None,
            "deliverable": outcome["state"] == "unclaimed" and not decisions,
            "run_id": outcome.get("run_id"),
        }

        if "pushover_request" in outcome:
            row["pushover_request"] = outcome["pushover_request"]

        results.append(row)

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest", type=Path,
        default=Path("arch/packages/manifest.json"),
    )
    args = parser.parse_args()
    records = inspect_outbox(
        json.loads(args.manifest.read_text()), github_api
    )
    print(json.dumps(records, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
