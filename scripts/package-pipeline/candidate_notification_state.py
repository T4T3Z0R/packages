#!/usr/bin/env python3
"""Pure candidate notification state classification.

No GitHub writes, HTTP requests, notifications, builds, or publishing.
"""

import json
import re

ISSUE_MARKER = "<!-- t4t3z0r:candidate-alert:v1 -->"
COMMENT_MARKER = "<!-- t4t3z0r:candidate-alert-state:v1 -->"
TRUSTED_AUTHOR = "github-actions[bot]"

TITLE = re.compile(
    r"Package candidate: "
    r"(?P<package>[a-z0-9-]+) @ "
    r"(?P<candidate>[A-Za-z0-9._+-]{1,100})\Z"
)


def record_body(state, issue_number, package, candidate, run_id, *, pushover_request=None):
    """Create an auditable comment body, without posting it."""
    if state not in ("claimed", "accepted"):
        raise ValueError("Unknown notification state")
    if type(issue_number) is not int or issue_number < 1:
        raise ValueError("Invalid issue number")
    if type(run_id) is not int or run_id < 1:
        raise ValueError("Invalid workflow run")
    if not isinstance(package, str) or not isinstance(candidate, str):
        raise ValueError("Invalid candidate identity")

    if not TITLE.fullmatch(
        f"Package candidate: {package} @ {candidate}"
    ):
        raise ValueError("Unsafe candidate identity")

    entry = {
        "state": state,
        "issue_number": issue_number,
        "package": package,
        "candidate": candidate,
        "run_id": run_id,
    }

    if pushover_request is not None:
        if (
            state != "accepted"
            or not isinstance(pushover_request, str)
            or re.fullmatch(
                r"[A-Za-z0-9-]{1,100}", pushover_request
            ) is None
        ):
            raise ValueError("Invalid Pushover request receipt")

        entry["pushover_request"] = pushover_request

    return COMMENT_MARKER + "\n" + json.dumps(
        entry, sort_keys=True, separators=(",", ":")
    )


def classify(issue, comments):
    """Classify issue state using complete GitHub comment history.

    A claimed notification must never be retried automatically.
    """
    if not isinstance(issue, dict):
        raise ValueError("Invalid candidate issue")

    number = issue.get("number")
    if type(number) is not int or number < 1:
        raise ValueError("Invalid issue number")

    title = issue.get("title")
    match = (
        TITLE.fullmatch(title)
        if isinstance(title, str) else None
    )

    if match is None or "pull_request" in issue:
        raise ValueError("Invalid candidate identity")

    body = issue.get("body")
    if not isinstance(body, str):
        raise ValueError("Missing issue body")

    if ISSUE_MARKER not in body:
        return {"state": "legacy", "issue_number": number}

    if body.count(ISSUE_MARKER) != 1:
        raise ValueError("Duplicate issue notification marker")

    if issue.get("state") not in ("open", "closed"):
        raise ValueError("Invalid issue state")

    if not isinstance(comments, list):
        raise ValueError("Incomplete notification history")

    package, candidate = match.group("package", "candidate")
    records = {}
    comment_ids = set()

    for comment in comments:
        if not isinstance(comment, dict):
            raise ValueError("Invalid comment")

        comment_id = comment.get("id")
        if (
            type(comment_id) is not int
            or comment_id < 1
            or comment_id in comment_ids
        ):
            raise ValueError(
                "Invalid or duplicate comment identity"
            )

        comment_ids.add(comment_id)
        text = comment.get("body")

        if not isinstance(text, str):
            raise ValueError("Invalid comment body")
        if COMMENT_MARKER not in text:
            continue

        if (
            not text.startswith(COMMENT_MARKER + "\n")
            or text.count(COMMENT_MARKER) != 1
        ):
            raise ValueError(
                "Malformed notification comment marker"
            )

        author = comment.get("user")
        if (
            not isinstance(author, dict)
            or author.get("login") != TRUSTED_AUTHOR
        ):
            raise ValueError("Untrusted notification comment")

        try:
            entry = json.loads(
                text[len(COMMENT_MARKER) + 1:]
            )
        except json.JSONDecodeError as exc:
            raise ValueError(
                "Malformed notification record"
            ) from exc

        expected_fields = {
            "state", "issue_number", "package",
            "candidate", "run_id",
        }

        if isinstance(entry, dict) and "pushover_request" in entry:
            expected_fields.add("pushover_request")

            if (
                entry.get("state") != "accepted"
                or not isinstance(entry["pushover_request"], str)
                or re.fullmatch(
                    r"[A-Za-z0-9-]{1,100}",
                    entry["pushover_request"],
                ) is None
            ):
                raise ValueError("Invalid Pushover request receipt")

        if (
            not isinstance(entry, dict)
            or set(entry) != expected_fields
        ):
            raise ValueError(
                "Invalid notification record fields"
            )

        state = entry["state"]

        if state not in ("claimed", "accepted") or state in records:
            raise ValueError(
                "Unknown or duplicate notification state"
            )

        if (
            entry["issue_number"] != number
            or entry["package"] != package
            or entry["candidate"] != candidate
        ):
            raise ValueError(
                "Notification identity mismatch"
            )

        if (
            type(entry["run_id"]) is not int
            or entry["run_id"] < 1
        ):
            raise ValueError(
                "Invalid notification workflow run"
            )

        records[state] = (entry, comment_id)

    if "accepted" in records and "claimed" not in records:
        raise ValueError(
            "Notification acceptance without claim"
        )

    if "accepted" in records:
        claim, claim_id = records["claimed"]
        accepted, accepted_id = records["accepted"]

        if (
            accepted["run_id"] != claim["run_id"]
            or accepted_id <= claim_id
        ):
            raise ValueError(
                "Inconsistent notification acknowledgment"
            )

        result = {
            "state": "accepted",
            "issue_number": number,
            "run_id": claim["run_id"],
        }

        if "pushover_request" in accepted:
            result["pushover_request"] = accepted["pushover_request"]

        return result

    if "claimed" in records:
        claim, _ = records["claimed"]
        return {
            "state": "claimed",
            "issue_number": number,
            "run_id": claim["run_id"],
        }

    return {
        "state": (
            "unclaimed"
            if issue["state"] == "open"
            else "closed-unclaimed"
        ),
        "issue_number": number,
    }
