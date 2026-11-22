#!/usr/bin/env python3
"""Evaluate upstream candidates; writes require explicit opt-in."""

import argparse
import json
import os
from pathlib import Path

from candidate_review import plan
from create_candidate_issue import create_if_missing
from github_candidate_issues import evaluate_proposals
from github_candidate_writer import create_issue
from github_validation_history import github_api


def run(report, api, *, creator=None, allow_create=False):
    """Evaluate candidates, optionally creating missing reviews."""
    proposals = plan(report)

    if not allow_create:
        return evaluate_proposals(api, proposals)

    if not callable(creator):
        raise ValueError("Issue creator required")

    results = []

    for proposal in proposals:
        # Each write gets a fresh history check.
        result = create_if_missing(
            proposal, api, creator
        )
        results.append({
            "package": proposal["package"],
            "candidate": proposal["candidate"],
            **result,
        })

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument(
        "--create",
        action="store_true",
        help="Create missing GitHub review issues",
    )
    args = parser.parse_args()

    if args.create and os.environ.get(
        "CANDIDATE_ISSUE_WRITE_ENABLED"
    ) != "1":
        parser.error(
            "--create requires "
            "CANDIDATE_ISSUE_WRITE_ENABLED=1"
        )

    report = json.loads(args.report.read_text())

    results = run(
        report,
        github_api,
        creator=create_issue if args.create else None,
        allow_create=args.create,
    )

    print(json.dumps(
        results, indent=2, sort_keys=True
    ))


if __name__ == "__main__":
    main()
