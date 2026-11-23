#!/usr/bin/env python3
"""Authenticated GitHub candidate issue creation.

No retries. Call only after guarded duplicate checking
inside a serialized workflow.
"""

import json
import re
import subprocess

REPOSITORY = "T4T3Z0R/packages"

TITLE = re.compile(
    r"Package candidate: "
    r"[a-z0-9-]+ @ [A-Za-z0-9._+-]{1,100}\Z"
)


def create_issue(title, body, *, runner=subprocess.run):
    """Submit one GitHub issue creation request.

    Ambiguous failures propagate to the caller. Never retry
    automatically because the server may have committed a write.
    """
    if not isinstance(title, str) or not TITLE.fullmatch(title):
        raise ValueError("Invalid candidate issue title")

    if not isinstance(body, str) or not body.strip():
        raise ValueError("Invalid candidate issue body")

    command = [
        "gh", "api",
        "--method", "POST",
        f"repos/{REPOSITORY}/issues",
        "--raw-field", f"title={title}",
        "--raw-field", f"body={body}",
    ]

    result = runner(
        command,
        check=True,
        capture_output=True,
        text=True,
    )

    response = json.loads(result.stdout)

    if not isinstance(response, dict):
        raise ValueError("Invalid GitHub creation response")

    return response
