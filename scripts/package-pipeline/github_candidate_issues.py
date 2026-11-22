#!/usr/bin/env python3
"""Read all GitHub candidate issues, including closed history.

No mutations, notifications, builds, signing, or publication.
"""

from candidate_issue_state import classify
from github_validation_history import github_api

PER_PAGE = 100
MAX_PAGES = 100
REPOSITORY = "T4T3Z0R/packages"


def issue_history(api, repo=REPOSITORY):
    """Read complete issue history, including GitHub PR records."""
    if repo != REPOSITORY:
        raise ValueError("Unexpected repository")

    issues = []
    identities = set()

    for page in range(1, MAX_PAGES + 1):
        endpoint = (
            f"repos/{repo}/issues"
            "?state=all"
            "&sort=created"
            "&direction=asc"
            f"&per_page={PER_PAGE}"
            f"&page={page}"
        )

        batch = api(endpoint)

        if not isinstance(batch, list):
            raise ValueError("Invalid GitHub issue response")

        if len(batch) > PER_PAGE:
            raise ValueError("Oversized GitHub issue page")

        for issue in batch:
            if not isinstance(issue, dict):
                raise ValueError("Malformed GitHub issue")

            identity = issue.get("id")
            number = issue.get("number")

            if type(identity) is not int or identity <= 0:
                raise ValueError("Invalid GitHub issue identity")

            if type(number) is not int or number <= 0:
                raise ValueError("Invalid GitHub issue number")

            if identity in identities:
                raise ValueError(
                    "Overlapping GitHub issue pagination"
                )

            identities.add(identity)
            issues.append(issue)

        if len(batch) < PER_PAGE:
            return issues

    raise ValueError("GitHub issue history exceeds page limit")


def evaluate_proposals(api, proposals, repo=REPOSITORY):
    """Classify proposals against one complete issue snapshot."""
    if not isinstance(proposals, list):
        raise ValueError("Invalid proposal collection")

    issues = issue_history(api, repo)
    results = []
    seen = set()

    for proposal in proposals:
        if not isinstance(proposal, dict):
            raise ValueError("Malformed proposal")

        title = proposal.get("title")

        if title in seen:
            raise ValueError("Duplicate candidate proposal")

        seen.add(title)

        decision = classify(proposal, issues)

        results.append({
            "package": proposal.get("package"),
            "candidate": proposal.get("candidate"),
            **decision,
        })

    return results


def main():
    import json
    import sys
    from pathlib import Path

    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: github_candidate_issues.py proposals.json"
        )

    proposals = json.loads(Path(sys.argv[1]).read_text())

    print(json.dumps(
        evaluate_proposals(github_api, proposals),
        indent=2,
        sort_keys=True,
    ))


if __name__ == "__main__":
    main()
