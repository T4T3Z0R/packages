#!/usr/bin/env python3
"""One candidate notification transaction, with injected I/O.

No API calls or retries occur in this module. Workflow authorization,
GitHub issue/comment reads and writes, and Pushover HTTP delivery are
provided separately by a guarded caller.
"""

import re

TITLE = re.compile(
    r"Package candidate: [a-z0-9-]+ @ [A-Za-z0-9._+-]{1,100}\Z"
)
RECEIPT = re.compile(r"[A-Za-z0-9-]{1,100}\Z")


def dispatch_one(target, run_id, *, read, claim, send, acknowledge):
    """Attempt delivery at most once, requiring evidence before sending.

    read(issue_number) returns a fresh, complete, authenticated outbox
    row produced by candidate_notification_reader.inspect_outbox().

    Callers must serialize the entire transaction with GitHub's
    package-candidate-issue-writes concurrency lock.
    """
    if not isinstance(target, dict):
        raise ValueError("Invalid notification target")

    number = target.get("issue_number")
    package = target.get("package")
    candidate = target.get("candidate")

    if type(number) is not int or number < 1:
        raise ValueError("Invalid issue number")

    if not isinstance(package, str) or not isinstance(candidate, str):
        raise ValueError("Invalid candidate identity")

    if not TITLE.fullmatch(
        f"Package candidate: {package} @ {candidate}"
    ):
        raise ValueError("Unsafe candidate identity")

    if type(run_id) is not int or run_id < 1:
        raise ValueError("Invalid workflow run")

    if not all(
        callable(op)
        for op in (read, claim, send, acknowledge)
    ):
        raise ValueError("Missing notification operation")

    def verified(state, expected_run=None, expected_receipt=None):
        row = read(number)

        if not isinstance(row, dict):
            raise ValueError("Invalid outbox read")

        for key, value in (
            ("issue_number", number),
            ("package", package),
            ("candidate", candidate),
        ):
            if row.get(key) != value:
                raise ValueError(
                    "Notification issue identity changed"
                )

        if row.get("state") != state:
            raise ValueError(
                "Notification outbox state changed"
            )

        if (
            row.get("decision") is not None
            or row.get("deliverable") is not (
                state == "unclaimed"
            )
        ):
            raise ValueError(
                "Notification no longer eligible"
            )

        if state in ("claimed", "accepted"):
            if row.get("run_id") != expected_run:
                raise ValueError(
                    "Notification claim run changed"
                )
        elif row.get("run_id") is not None:
            raise ValueError(
                "Unexpected notification claim"
            )

        if (
            state == "accepted"
            and row.get("pushover_request") != expected_receipt
        ):
            raise ValueError("Notification receipt changed")

        return row

    # Reject previously claimed, accepted, or reviewed issues.
    verified("unclaimed")

    # Never retry an ambiguous GitHub comment write.
    claim(number, package, candidate, run_id)

    # Do not send until the claim is visible and belongs to this run.
    verified("claimed", run_id)

    # One attempt only. Errors after a claim require reconciliation.
    response = send(number, package, candidate)

    if not isinstance(response, dict):
        raise ValueError(
            "Invalid Pushover response; "
            "manual reconciliation required"
        )

    receipt = response.get("request")

    if (
        type(response.get("http_status")) is not int
        or response["http_status"] != 200
        or type(response.get("status")) is not int
        or response["status"] != 1
        or not isinstance(receipt, str)
        or not RECEIPT.fullmatch(receipt)
    ):
        raise ValueError(
            "Unconfirmed Pushover acceptance; "
            "manual reconciliation required"
        )

    # Persist acknowledgment before reporting success.
    acknowledge(number, package, candidate, run_id, receipt)
    verified("accepted", run_id, receipt)

    return {
        "issue_number": number,
        "package": package,
        "candidate": candidate,
        "run_id": run_id,
        "pushover_request": receipt,
        "state": "accepted",
    }
