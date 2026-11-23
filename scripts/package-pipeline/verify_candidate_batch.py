#!/usr/bin/env python3
"""Verify candidate issue writes and identify newly created reviews.

No GitHub writes, notifications, builds, signing, or publication.
Reuses the existing bounded single-candidate consistency verifier.
"""

import argparse
import json
import time
from pathlib import Path

from candidate_review import plan
from github_validation_history import github_api
from run_candidate_reviews import run
from verify_candidate_write import verify


def indexed(records, expected, label):
    if not isinstance(records, list):
        raise ValueError(f"Invalid {label} collection")

    result = {}

    for record in records:
        if not isinstance(record, dict):
            raise ValueError(f"Malformed {label} record")

        package = record.get("package")
        candidate = record.get("candidate")

        if (
            not isinstance(package, str)
            or not isinstance(candidate, str)
        ):
            raise ValueError(f"Invalid {label} identity")

        key = (package, candidate)

        if key in result:
            raise ValueError(f"Duplicate {label} identity")

        result[key] = record

    if set(result) != expected:
        raise ValueError(f"Incomplete or unexpected {label} history")

    return result


def verify_batch(report, before, writes, reader, *,
                 pause=time.sleep):
    """Return notification identities only for verified new issues.

    reader(report_item) returns one read-only candidate evaluation.
    No notification or write is performed here.
    """
    if not callable(reader):
        raise ValueError("Missing read-only reader")

    proposals = plan(report)

    expected = {
        (p["package"], p["candidate"])
        for p in proposals
    }

    if len(expected) != len(proposals):
        raise ValueError("Duplicate proposal identity")

    previous = indexed(before, expected, "prewrite")
    written = indexed(writes, expected, "write")

    reports = {
        (item["package"], item["candidate"]): item
        for item in report
        if item["status"] == "update"
    }

    created = []

    for proposal in proposals:
        key = (proposal["package"], proposal["candidate"])
        old = previous[key]
        write = written[key]
        item = reports[key]

        def read(item=item):
            return reader(item)

        observed = verify(
            old, write, read,
            pause=pause,
        )

        if write["action"] == "created":
            created.append({
                "package": key[0],
                "candidate": key[1],
                "issue_number": observed["issue_number"],
            })

    return created


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("prewrite", type=Path)
    parser.add_argument("writes", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    report = json.loads(args.report.read_text())
    before = json.loads(args.prewrite.read_text())
    writes = json.loads(args.writes.read_text())

    created = verify_batch(
        report,
        before,
        writes,
        lambda item: run([item], github_api),
    )

    args.output.write_text(
        json.dumps(created, indent=2, sort_keys=True) + "\n"
    )

    print(json.dumps(
        {"verified_new_issues": len(created)},
        sort_keys=True,
    ))


if __name__ == "__main__":
    main()
