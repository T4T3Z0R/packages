#!/usr/bin/env python3
"""Verify one candidate review with bounded read-only history checks."""

import argparse
import json
import sys
import time
from pathlib import Path

from github_validation_history import github_api
from run_candidate_reviews import run

MAX_READS = 5
RETRY_DELAY_SECONDS = 2


def single(value, label):
    if (
        not isinstance(value, list)
        or len(value) != 1
        or not isinstance(value[0], dict)
    ):
        raise ValueError(f"Expected exactly one {label}")
    return value[0]


def verify(before, write, read, *, pause=time.sleep, record=None):
    """Retry only when a newly created issue is absent from history."""
    if not isinstance(before, dict) or not isinstance(write, dict):
        raise ValueError("Invalid candidate review evidence")
    if not callable(read) or not callable(pause):
        raise ValueError("Missing read-only verifier operations")

    for key in ("package", "candidate"):
        if not isinstance(write.get(key), str) or not write[key]:
            raise ValueError(f"Invalid {key} identity")
        if before.get(key) != write[key]:
            raise ValueError(f"Prewrite {key} mismatch")

    action = write.get("action")
    number = write.get("issue_number")
    decision = write.get("decision")

    if action not in ("created", "existing"):
        raise ValueError("Unexpected write action")
    if type(number) is not int or number <= 0:
        raise ValueError("Invalid write issue number")
    if decision not in (
        "pending", "approved", "denied", "postponed", "pinned"
    ):
        raise ValueError("Unexpected write decision")

    if action == "created":
        if (
            before.get("action") != "create"
            or before.get("issue_number") is not None
            or decision != "pending"
        ):
            raise ValueError("Inconsistent issue creation evidence")
    elif (
        before.get("action") != "create"
        and before.get("issue_number") != number
    ):
        raise ValueError("Prewrite issue identity mismatch")

    for attempt in range(1, MAX_READS + 1):
        observed = read()

        if record is not None:
            record(observed)

        after = single(observed, "postwrite result")

        if any(
            after.get(key) != write[key]
            for key in ("package", "candidate")
        ):
            raise ValueError("Postwrite candidate identity mismatch")

        if after.get("issue_number") == number:
            if after.get("action") != decision:
                raise ValueError("Postwrite candidate decision mismatch")
            return after

        stale_create = (
            action == "created"
            and after.get("action") == "create"
            and after.get("issue_number") is None
        )

        if not stale_create:
            raise ValueError("Postwrite issue identity mismatch")

        if attempt == MAX_READS:
            raise RuntimeError(
                f"Created issue #{number} absent after "
                f"{MAX_READS} read-only history checks"
            )

        print(
            f"Read-only history lag for issue #{number}; "
            f"retrying ({attempt}/{MAX_READS - 1})",
            file=sys.stderr,
            flush=True,
        )
        pause(RETRY_DELAY_SECONDS)

    raise AssertionError("Unreachable retry limit")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("prewrite", type=Path)
    parser.add_argument("write", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    report = json.loads(args.report.read_text())
    before = single(
        json.loads(args.prewrite.read_text()), "prewrite result"
    )
    write = single(
        json.loads(args.write.read_text()), "write result"
    )

    def record(observed):
        args.output.write_text(
            json.dumps(observed, indent=2, sort_keys=True) + "\n"
        )

    after = verify(
        before,
        write,
        lambda: run(report, github_api),
        record=record,
    )

    print(json.dumps([after], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
