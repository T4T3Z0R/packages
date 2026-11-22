#!/usr/bin/env python3
"""Read-only classification of existing GitHub candidate issues."""

DECISIONS = {
    "candidate:approved": "approved",
    "candidate:denied": "denied",
    "candidate:postponed": "postponed",
    "candidate:pinned": "pinned",
}


def classify(proposal, issues):
    """Resolve an existing candidate review or request creation.

    `issues` must contain both open and closed historical issues.
    This function does not fetch or mutate GitHub data.
    """
    if not isinstance(proposal, dict):
        raise ValueError("Invalid proposal")

    title = proposal.get("title")

    if not isinstance(title, str) or not title.startswith(
        "Package candidate: "
    ):
        raise ValueError("Invalid candidate title")

    if not isinstance(issues, list):
        raise ValueError("Incomplete issue collection")

    matches = []

    for issue in issues:
        if not isinstance(issue, dict):
            raise ValueError("Malformed issue")

        if issue.get("title") != title:
            continue

        if "pull_request" in issue:
            raise ValueError("Candidate title belongs to a PR")

        matches.append(issue)

    if not matches:
        return {
            "action": "create",
            "issue_number": None,
        }

    if len(matches) != 1:
        raise ValueError("Duplicate candidate issues")

    issue = matches[0]
    number = issue.get("number")
    state = issue.get("state")
    labels = issue.get("labels")

    if type(number) is not int or number <= 0:
        raise ValueError("Invalid issue number")

    if state not in ("open", "closed"):
        raise ValueError("Unknown issue state")

    if not isinstance(labels, list):
        raise ValueError("Missing issue labels")

    names = set()

    for label in labels:
        if isinstance(label, str):
            name = label
        elif isinstance(label, dict):
            name = label.get("name")
        else:
            raise ValueError("Malformed issue label")

        if not isinstance(name, str):
            raise ValueError("Invalid issue label name")

        names.add(name)

    decisions = names.intersection(DECISIONS)

    if len(decisions) > 1:
        raise ValueError("Conflicting candidate decisions")

    if not decisions:
        if state != "open":
            raise ValueError("Closed review has no decision")
        action = "pending"
    else:
        action = DECISIONS[next(iter(decisions))]

    return {
        "action": action,
        "issue_number": number,
    }
