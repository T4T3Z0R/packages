#!/usr/bin/env python3
"""Read-only evaluation of package validation history."""

import argparse
import json
import re
import subprocess
from pathlib import Path

from github_validation_history import (
    github_api,
    run_artifacts,
    run_attempt_evidence,
    validation_runs,
)
from package_fingerprint import fingerprint
from select_package_validation import SUPPORTED
from validation_ledger import classify

SHA = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = "T4T3Z0R/packages"

# First introduction of the shared package manifest.
# Only verified ancestors of this immutable commit can
# be treated as manifest-less legacy history.
MANIFEST_INTRODUCTION = (
    "c9d29099f560c002daf0db7a80ef090cf1cfe66c"
)
MANIFEST_PATH = "arch/packages/manifest.json"


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args],
        stderr=subprocess.PIPE,
        text=True,
    ).strip()


def historical_identity(root, sha, package):
    """Return fingerprint or None for verified legacy history.

    Missing commits, unexpected manifest absence, and malformed
    evidence raise an exception.
    """
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError("Invalid historical Git commit")

    git(root, "cat-file", "-e", f"{sha}^{{commit}}")

    entry = git(
        root, "ls-tree", sha, "--", MANIFEST_PATH
    )

    if not entry:
        # A successful tree lookup establishes actual absence,
        # rather than an unreadable commit or failed Git operation.
        git(
            root, "cat-file", "-e",
            f"{MANIFEST_INTRODUCTION}^{{commit}}"
        )

        git(
            root, "cat-file", "-e",
            f"{MANIFEST_INTRODUCTION}:{MANIFEST_PATH}"
        )

        git(
            root, "merge-base", "--is-ancestor",
            MANIFEST_INTRODUCTION, "HEAD"
        )

        if sha == MANIFEST_INTRODUCTION:
            raise ValueError(
                "Manifest missing at registry introduction"
            )

        ancestry = subprocess.run(
            [
                "git", "-C", str(root),
                "merge-base", "--is-ancestor",
                sha, MANIFEST_INTRODUCTION,
            ],
            capture_output=True,
            text=True,
        )

        if ancestry.returncode == 0:
            return None

        if ancestry.returncode == 1:
            raise ValueError(
                f"Unexpected missing historical manifest: {sha}"
            )

        ancestry.check_returncode()

    raw = git(
        root, "show",
        f"{sha}:{MANIFEST_PATH}"
    )
    manifest = json.loads(raw)

    if not isinstance(manifest, dict):
        raise ValueError("Malformed historical manifest")

    packages = manifest.get("packages")

    if not isinstance(packages, dict):
        raise ValueError("Malformed historical packages mapping")

    if package not in packages:
        return None

    config = packages[package]

    if not isinstance(config, dict):
        raise ValueError("Malformed historical package entry")

    if config.get("status") != "approved":
        return None

    return fingerprint(root, sha, package)


def evaluate(api, repo, package, target, historical):
    """Inspect complete history and return a safe validation decision."""
    if repo != REPOSITORY:
        raise ValueError("Unexpected repository")

    if package not in SUPPORTED:
        raise ValueError("Unsupported package")

    if not re.fullmatch(r"[0-9a-f]{64}", target):
        raise ValueError("Invalid target fingerprint")

    runs = validation_runs(api, repo, package)
    seen = set()
    active = []
    validated = []
    published = []
    manual_review = []

    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("Malformed workflow run")

        run_id = run.get("id")
        if type(run_id) is not int or run_id <= 0:
            raise ValueError("Invalid workflow run ID")
        if run_id in seen:
            raise ValueError("Duplicate workflow run in history")
        seen.add(run_id)

        if run.get("event") != "workflow_dispatch":
            raise ValueError("Unexpected workflow event")

        status = run.get("status")
        if status not in (
            "queued", "pending", "in_progress",
            "waiting", "requested", "completed",
        ):
            raise ValueError("Unknown workflow run status")

        sha = run.get("head_sha")
        old = historical(sha, package)

        if old is None:
            # Legacy runs have no comparable fingerprint.
            # Never overlap an active legacy publication.
            if status != "completed":
                active.append(run_id)
            continue

        if old != target:
            continue

        if status != "completed":
            active.append(run_id)
            continue

        attempt = run.get("run_attempt")
        if type(attempt) is not int or attempt < 1:
            raise ValueError("Invalid workflow run attempt")

        artifacts = run_artifacts(api, repo, run_id)
        outcomes = set()

        for number in range(1, attempt + 1):
            attempt_run, jobs = run_attempt_evidence(
                api, repo, run_id, number
            )

            if (
                attempt_run.get("head_sha") != sha
                or attempt_run.get("event") != run.get("event")
            ):
                raise ValueError(
                    "Workflow attempt source or event mismatch"
                )

            if number == attempt:
                if (
                    attempt_run.get("status") != status
                    or attempt_run.get("conclusion")
                    != run.get("conclusion")
                ):
                    raise ValueError(
                        "Workflow attempt metadata changed during evaluation"
                    )
            elif attempt_run.get("status") != "completed":
                raise ValueError(
                    "Earlier workflow attempt was not completed"
                )

            outcome = classify(
                attempt_run,
                jobs,
                artifacts,
                package=package,
                target=target,
                fingerprint=lambda revision, name: historical(
                    revision, name
                ),
            )
            outcomes.add(outcome)

        unexpected = outcomes - {
            "retry", "validated", "published", "manual_review"
        }
        if unexpected:
            raise ValueError(
                "Unexpected workflow attempt classification"
            )

        # Record each run once per category, not once per attempt.
        if "validated" in outcomes:
            validated.append(run_id)
        if "published" in outcomes:
            published.append(run_id)
        if "manual_review" in outcomes:
            manual_review.append(run_id)

    if active:
        decision = "in_flight"
    elif manual_review:
        decision = "manual_review"
    elif published:
        decision = "published"
    elif validated:
        decision = "validated"
    else:
        decision = "needs_validation"

    return {
        "package": package,
        "decision": decision,
        "validated_runs": validated,
        "published_runs": published,
        "manual_review_runs": manual_review,
        "active_runs": active,
        "history_count": len(runs),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--package",
        choices=SUPPORTED,
        required=True,
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    args = parser.parse_args()

    root = args.repo.resolve()
    current = git(root, "rev-parse", "HEAD")
    target = fingerprint(root, current, args.package)

    result = evaluate(
        github_api,
        REPOSITORY,
        args.package,
        target,
        lambda sha, name: historical_identity(
            root, sha, name
        ),
    )

    result["fingerprint"] = target
    result["revision"] = current

    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
