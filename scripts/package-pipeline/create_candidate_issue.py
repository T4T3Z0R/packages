#!/usr/bin/env python3
"""Guard candidate issue creation against existing reviews.

The caller supplies the GitHub API reader and issue creator.
This module makes no network requests or notifications itself.
"""

from candidate_issue_state import classify
from github_candidate_issues import issue_history

TITLE_PREFIX = "Package candidate: "


def create_if_missing(proposal, api, create):
    """Check live history, then create only an absent candidate."""
    if not isinstance(proposal, dict):
        raise ValueError("Invalid proposal")

    package = proposal.get("package")
    candidate = proposal.get("candidate")
    title = proposal.get("title")
    body = proposal.get("body")

    if not all(
        isinstance(value, str) and value
        for value in (package, candidate, title, body)
    ):
        raise ValueError("Incomplete candidate proposal")

    if title != f"{TITLE_PREFIX}{package} @ {candidate}":
        raise ValueError("Inconsistent candidate identity")

    if not callable(api) or not callable(create):
        raise ValueError("Missing GitHub operations")

    # Read current history immediately before the proposed write.
    history = issue_history(api)
    existing = classify(proposal, history)

    if existing["action"] != "create":
        return {
            "action": "existing",
            "decision": existing["action"],
            "issue_number": existing["issue_number"],
        }

    result = create(title, body)

    if not isinstance(result, dict):
        raise ValueError("Invalid created issue response")

    number = result.get("number")

    if (
        type(number) is not int
        or number <= 0
        or result.get("title") != title
        or result.get("state") != "open"
        or "pull_request" in result
    ):
        raise ValueError("Created issue identity mismatch")

    return {
        "action": "created",
        "decision": "pending",
        "issue_number": number,
    }
