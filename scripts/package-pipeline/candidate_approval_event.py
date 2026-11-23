#!/usr/bin/env python3
"""Authorize a candidate approval event without performing writes."""

import argparse
import json
import re
from pathlib import Path

from candidate_issue_state import classify
from discover_upstream import DEFAULT_MANIFEST
from select_package_validation import SUPPORTED

REPOSITORY = "T4T3Z0R/packages"
OWNER = "T4T3Z0R"

TITLE = re.compile(
    r"Package candidate: ([a-z0-9-]+) @ ([A-Za-z0-9._+-]{1,100})\Z"
)

MARKER = "<!-- t4t3z0r:candidate-alert:v1 -->"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def approval_plan(event, manifest):
    """Validate event identity and issue state; return a read-only plan."""
    require(isinstance(event, dict), "Malformed event")
    require(event.get("action") == "labeled", "Unexpected event action")

    repository = event.get("repository")
    require(
        isinstance(repository, dict)
        and repository.get("full_name") == REPOSITORY,
        "Unexpected repository",
    )

    sender = event.get("sender")
    require(
        isinstance(sender, dict)
        and sender.get("login") == OWNER,
        "Approval must originate from repository owner",
    )

    label = event.get("label")
    require(
        isinstance(label, dict)
        and label.get("name") == "candidate:approved",
        "Unexpected approval label",
    )

    issue = event.get("issue")
    require(isinstance(issue, dict), "Malformed issue")
    require("pull_request" not in issue, "Pull request is not a candidate issue")
    require(issue.get("state") == "open", "Candidate issue is not open")

    author = issue.get("user")
    require(
        isinstance(author, dict)
        and author.get("login") in (OWNER, "github-actions[bot]"),
        "Untrusted candidate issue creator",
    )

    title = issue.get("title")
    require(isinstance(title, str), "Missing candidate title")

    match = TITLE.fullmatch(title)
    require(match is not None, "Invalid candidate issue title")
    package, candidate = match.groups()

    require(package in SUPPORTED, "Unsupported package")

    require(
        isinstance(manifest, dict)
        and isinstance(manifest.get("packages"), dict),
        "Malformed manifest",
    )

    config = manifest["packages"].get(package)
    require(isinstance(config, dict), "Missing package configuration")
    require(config.get("status") == "approved", "Package not approved")
    require(
        config.get("auto_publish") is False,
        "Automatic publication is forbidden",
    )

    selected = config.get("source_ref")
    require(isinstance(selected, str), "Invalid selected source")
    require(candidate != selected, "Candidate is already selected")

    body = issue.get("body")
    require(isinstance(body, str), "Missing candidate issue body")

    expected = (
        MARKER,
        f"- Package: `{package}`",
        f"- Selected: `{selected}`",
        f"- Candidate: `{candidate}`",
    )

    for line in expected:
        require(
            body.splitlines().count(line) == 1,
            f"Missing or duplicated issue evidence: {line}",
        )

    decision = classify({"title": title}, [issue])
    require(
        decision["action"] == "approved",
        "Issue has no unambiguous approval decision",
    )

    return {
        "authorized": True,
        "issue_number": decision["issue_number"],
        "package": package,
        "selected": selected,
        "candidate": candidate,
        "next_action": "source_selection_review_required",
        "validation_dispatched": False,
        "publication_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("event", type=Path)
    args = parser.parse_args()

    event = json.loads(args.event.read_text())
    manifest = json.loads(DEFAULT_MANIFEST.read_text())

    print(json.dumps(
        approval_plan(event, manifest),
        indent=2,
        sort_keys=True,
    ))


if __name__ == "__main__":
    main()
