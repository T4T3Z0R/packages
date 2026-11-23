#!/usr/bin/env python3
"""Evaluate upstream release candidates without changing repository state."""

import argparse
import json
import re
import subprocess
from pathlib import Path

STABLE_TAG = re.compile(
    r"(?:v)?[0-9]+(?:[.][0-9]+){2}(?:[.][0-9]+)?\Z"
)
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")

STABLE_POLICIES = {"stable-tag", "stable-git-tag", "pinned-tag"}
COMMIT_POLICIES = {"development-commit", "pinned-commit", "reviewed-commit"}


def compare_versions(current, candidate):
    """Return Arch vercmp's comparison result."""
    result = subprocess.run(
        ["vercmp", current.removeprefix("v"),
         candidate.removeprefix("v")],
        check=True,
        capture_output=True,
        text=True,
    )
    value = int(result.stdout.strip())
    if value not in (-1, 0, 1):
        raise ValueError("Unexpected vercmp result")
    return value


def descendant_of(current, candidate, repo):
    """Check whether candidate descends from current."""
    for ref in (current, candidate):
        verified = subprocess.run(
            ["git", "-C", str(repo), "cat-file",
             "-e", f"{ref}^{{commit}}"],
            capture_output=True,
            text=True,
        )
        if verified.returncode != 0:
            raise RuntimeError(
                f"Missing or invalid Git commit: {ref}"
            )

    result = subprocess.run(
        ["git", "-C", str(repo), "merge-base",
         "--is-ancestor", current, candidate],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise RuntimeError(
        result.stderr.strip() or "Git ancestry check failed"
    )


def decide(policy, selected, candidate, *,
           compare=compare_versions, ancestry=None):
    """Return a decision dictionary; never mutate selected state."""
    if policy in STABLE_POLICIES:
        pattern = STABLE_TAG
    elif policy in COMMIT_POLICIES:
        pattern = COMMIT_SHA
    else:
        raise ValueError("Unsupported release policy")

    if not pattern.fullmatch(selected):
        raise ValueError("Invalid selected source ref")
    if not pattern.fullmatch(candidate):
        raise ValueError("Invalid candidate source ref")

    if selected == candidate:
        status, reason = "unchanged", "same-source"
    elif policy.startswith("pinned-"):
        status, reason = "blocked", "pinned"
    elif policy in ("stable-tag", "stable-git-tag"):
        comparison = compare(selected, candidate)
        if comparison < 0:
            status, reason = "update", "newer-version"
        elif comparison == 0:
            status, reason = "unchanged", "equal-version"
        else:
            status, reason = "blocked", "older-version"
    elif policy == "reviewed-commit":
        status, reason = "update", "changed-commit-requires-review"
    else:
        if ancestry is None:
            raise ValueError("Development policy requires Git ancestry")
        if ancestry(selected, candidate):
            status, reason = "update", "descendant-commit"
        else:
            status, reason = "blocked", "divergent-history"

    return {
        "policy": policy,
        "selected": selected,
        "candidate": candidate,
        "status": status,
        "reason": reason,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--selected-ref", required=True)
    parser.add_argument("--candidate-ref", required=True)
    parser.add_argument("--repo-path", type=Path)
    args = parser.parse_args()

    ancestry = None
    if args.policy == "development-commit":
        if args.repo_path is None:
            parser.error("--repo-path required for development commits")
        ancestry = lambda old, new: descendant_of(
            old, new, args.repo_path
        )

    result = decide(
        args.policy,
        args.selected_ref,
        args.candidate_ref,
        ancestry=ancestry,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
