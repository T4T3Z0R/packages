#!/usr/bin/env python3
"""Read complete GitHub Actions validation evidence.

No workflow dispatch, mutation, signing, or publishing.
"""

import json
import subprocess

from select_package_validation import SUPPORTED, workflow_file

PER_PAGE = 100
MAX_PAGES = 100


def github_api(endpoint):
    """Fetch one GitHub REST API response using gh authentication."""
    result = subprocess.run(
        ["gh", "api", "--method", "GET", endpoint],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def fetch_pages(api, endpoint, collection):
    """Retrieve a complete GitHub collection, rejecting partial data."""
    items = []
    seen_ids = set()
    expected_count = None

    for page in range(1, MAX_PAGES + 1):
        separator = "&" if "?" in endpoint else "?"
        url = (
            f"{endpoint}{separator}"
            f"per_page={PER_PAGE}&page={page}"
        )

        response = api(url)

        if not isinstance(response, dict):
            raise ValueError("Invalid GitHub API response")

        count = response.get("total_count")
        batch = response.get(collection)

        if type(count) is not int or count < 0:
            raise ValueError("Invalid GitHub collection count")
        if not isinstance(batch, list):
            raise ValueError("Invalid GitHub collection data")

        if expected_count is None:
            expected_count = count
        elif count != expected_count:
            raise ValueError(
                "GitHub collection changed during pagination"
            )

        if len(batch) > PER_PAGE:
            raise ValueError("Oversized GitHub API page")

        # GitHub pages are not an atomic snapshot. Detect
        # overlapping records even when total_count is unchanged.
        for item in batch:
            if not isinstance(item, dict):
                raise ValueError("Malformed GitHub collection item")

            identity = item.get("id")
            if type(identity) is not int or identity <= 0:
                raise ValueError("Missing GitHub item identity")

            if identity in seen_ids:
                raise ValueError(
                    "Overlapping GitHub pagination records"
                )

            seen_ids.add(identity)

        items.extend(batch)

        if len(items) > expected_count:
            raise ValueError(
                "GitHub collection exceeds reported count"
            )

        if len(items) == expected_count:
            return items

        if len(batch) != PER_PAGE:
            raise ValueError(
                "Incomplete GitHub API page"
            )

    raise ValueError("GitHub history exceeds pagination limit")


def validation_runs(api, repo, package):
    if package not in SUPPORTED:
        raise ValueError("Unsupported package")

    workflow = workflow_file(package)

    return fetch_pages(
        api,
        f"repos/{repo}/actions/workflows/{workflow}/runs"
        "?event=workflow_dispatch",
        "workflow_runs",
    )


def run_evidence(api, repo, run_id):
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("Invalid workflow run ID")

    base = f"repos/{repo}/actions/runs/{run_id}"

    jobs = fetch_pages(api, f"{base}/jobs", "jobs")
    artifacts = fetch_pages(
        api, f"{base}/artifacts", "artifacts"
    )

    return jobs, artifacts


def run_attempt_evidence(api, repo, run_id, attempt_number):
    """Read one exact workflow attempt and its complete job collection."""
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("Invalid workflow run ID")
    if type(attempt_number) is not int or attempt_number <= 0:
        raise ValueError("Invalid workflow attempt number")

    base = (
        f"repos/{repo}/actions/runs/{run_id}"
        f"/attempts/{attempt_number}"
    )

    run = api(base)

    if (
        not isinstance(run, dict)
        or type(run.get("id")) is not int
        or run["id"] != run_id
        or type(run.get("run_attempt")) is not int
        or run["run_attempt"] != attempt_number
    ):
        raise ValueError("Workflow attempt identity mismatch")

    jobs = fetch_pages(api, f"{base}/jobs", "jobs")

    for job in jobs:
        if job.get("run_id") != run_id:
            raise ValueError("Job belongs to another workflow run")

        if (
            "run_attempt" in job
            and job["run_attempt"] != attempt_number
        ):
            raise ValueError("Job belongs to another workflow attempt")

    return run, jobs


def run_artifacts(api, repo, run_id):
    """Read all artifacts for a workflow run, across attempts."""
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("Invalid workflow run ID")

    return fetch_pages(
        api,
        f"repos/{repo}/actions/runs/{run_id}/artifacts",
        "artifacts",
    )
