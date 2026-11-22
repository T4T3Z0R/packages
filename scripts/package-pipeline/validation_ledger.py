#!/usr/bin/env python3
"""Classify GitHub Actions validation evidence without mutating state."""

import re

from select_package_validation import SUPPORTED

SHA = re.compile(r"[0-9a-f]{40}\Z")
FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")

VALIDATION_JOBS = {
    "ghostty": "Build and validate unsigned Ghostty split packages",
    "keepassxc": "Build and validate unsigned KeePassXC",
    "syncthing": "Build and validate unsigned Syncthing",
    "wezterm": "Build and validate unsigned WezTerm pair",
}

PROTECTED_JOB_PREFIXES = (
    "Sign and publish",
    "Notify signing approval ready",
)


def classify(run, jobs, artifacts, *, package, target, fingerprint):
    """Return validated, in_flight, retry or unrelated.

    fingerprint(commit_sha, package) must independently verify the
    historical Git tree and return its package fingerprint.
    """
    if package not in SUPPORTED:
        raise ValueError("Unsupported package")
    if not FINGERPRINT.fullmatch(target):
        raise ValueError("Invalid target fingerprint")

    if run.get("event") != "workflow_dispatch":
        return "unrelated"

    sha = run.get("head_sha")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError("Missing verified run commit")

    historical = fingerprint(sha, package)
    if not FINGERPRINT.fullmatch(historical):
        raise ValueError("Invalid historical fingerprint")

    if historical != target:
        return "unrelated"

    status = run.get("status")
    if status in ("queued", "pending", "in_progress", "waiting", "requested"):
        return "in_flight"

    if status != "completed":
        raise ValueError("Unrecognized workflow status")

    if run.get("conclusion") != "success":
        return "retry"

    matches = [
        job for job in jobs
        if job.get("name") == VALIDATION_JOBS[package]
    ]
    if len(matches) != 1:
        return "retry"

    validation = matches[0]
    if validation.get("conclusion") != "success":
        return "retry"

    steps = validation.get("steps", [])
    uploads = [
        step for step in steps
        if step.get("name") == "Upload unsigned candidate and evidence"
    ]

    if len(uploads) != 1 or uploads[0].get("conclusion") != "success":
        return "retry"

    protected = [
        job for job in jobs
        if any(
            job.get("name", "").startswith(prefix)
            for prefix in PROTECTED_JOB_PREFIXES
        )
    ]
    if len(protected) != 2:
        return "retry"

    if any(job.get("conclusion") != "skipped" for job in protected):
        return "retry"

    run_id = run.get("id")
    attempt = run.get("run_attempt")
    if type(run_id) is not int or run_id <= 0:
        return "retry"
    if type(attempt) is not int or attempt <= 0:
        return "retry"

    expected = f"{package}-{run_id}-{attempt}-candidate"

    matching_artifacts = [
        artifact for artifact in artifacts
        if artifact.get("name") == expected
        and artifact.get("expired") is False
        and isinstance(artifact.get("size_in_bytes"), int)
        and artifact["size_in_bytes"] > 0
    ]

    if len(matching_artifacts) != 1:
        return "retry"

    return "validated"
