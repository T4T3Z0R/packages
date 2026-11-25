#!/usr/bin/env python3
"""Close candidate issues only after verified protected publication."""

import argparse
import json
import os
import subprocess
from pathlib import Path

from github_validation_history import github_api
from merged_selection_validation import collection
from reconcile_candidate_publication import (
    REPO,
    approved_candidate,
    reconcile,
    require,
)


def write_api(endpoint, method, payload):
    result = subprocess.run(
        [
            "gh", "api", "--method", method,
            endpoint, "--input", "-",
        ],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def verify_main(api, revision):
    require(
        api(f"repos/{REPO}/branches/main")
        ["commit"]["sha"] == revision,
        "Production main moved during reconciliation",
    )


def receipt(record):
    evidence = record["publication"]

    marker = (
        "<!-- t4t3z0r:publication-receipt:v1 "
        f"issue={record['issue_number']} "
        f"run={evidence['run_id']} "
        f"attempt={evidence['attempt']} -->"
    )

    body = (
        f"{marker}\n\n"
        "## Candidate successfully published\n\n"
        f"- Package: `{record['package']}`\n"
        f"- Published candidate: `{record['candidate']}`\n"
        f"- Source selection: #{record['selection_pr']}\n"
        f"- Infrastructure: `{evidence['revision']}`\n"
        f"- Publication attempt: {evidence['attempt']}\n"
        f"- [Successful publisher run]"
        f"(https://github.com/{REPO}/actions/runs/"
        f"{evidence['run_id']})\n\n"
        "Unsigned validation and protected signing and "
        "publication completed successfully.\n\n"
        "Closing this completed candidate review."
    )

    return marker, body


def apply(root, api, mutate, revision, *, planner=reconcile):
    verify_main(api, revision)
    initial = planner(root, api, revision)
    results = []

    for record in initial:
        if record["decision"] != "close_published":
            continue

        number = record["issue_number"]
        endpoint = f"repos/{REPO}/issues/{number}"

        def recheck():
            verify_main(api, revision)

            current = api(endpoint)

            require(
                current.get("number") == number
                and approved_candidate(current) == (
                    record["package"],
                    record["candidate"],
                ),
                "Candidate issue changed before closure",
            )

            fresh = [
                item for item in planner(root, api, revision)
                if item["issue_number"] == number
            ]

            require(
                fresh == [record],
                "Publication evidence changed before closure",
            )

            return current

        recheck()

        marker, body = receipt(record)

        comments = collection(
            api, f"{endpoint}/comments"
        )

        existing = [
            item for item in comments
            if marker in (item.get("body") or "").splitlines()
        ]

        require(
            len(existing) <= 1,
            "Duplicate publication receipts",
        )

        if existing:
            require(
                existing[0].get("user", {}).get("login")
                == "github-actions[bot]"
                and existing[0].get("body") == body,
                "Untrusted or modified publication receipt",
            )
        else:
            verify_main(api, revision)

            created = mutate(
                f"{endpoint}/comments",
                "POST",
                {"body": body},
            )

            require(
                created.get("body") == body
                and created.get("user", {}).get("login")
                == "github-actions[bot]",
                "Publication receipt could not be verified",
            )

        # Repeat the real evidence checks before closing.
        recheck()
        verify_main(api, revision)

        current = api(endpoint)
        require(
            current.get("number") == number
            and approved_candidate(current) == (
                record["package"], record["candidate"]
            ),
            "Candidate changed immediately before closure",
        )

        closed = mutate(
            endpoint,
            "PATCH",
            {
                "state": "closed",
                "state_reason": "completed",
            },
        )

        require(
            closed.get("number") == number
            and closed.get("state") == "closed"
            and closed.get("state_reason") == "completed",
            "Issue closure could not be verified",
        )

        final = api(endpoint)

        require(
            final.get("number") == number
            and final.get("state") == "closed"
            and final.get("state_reason") == "completed"
            and final.get("title")
            == f"Package candidate: {record['package']} @ "
               f"{record['candidate']}"
            and [
                label["name"]
                for label in final.get("labels", [])
                if label["name"].startswith("candidate:")
            ] == ["candidate:approved"],
            "Final candidate issue verification failed",
        )

        results.append({
            "issue_number": number,
            "package": record["package"],
            "candidate": record["candidate"],
            "publication_run": record["publication"]["run_id"],
            "decision": "closed_published",
        })

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()

    require(
        os.environ.get("CANDIDATE_CLOSURE_ENABLED") == "1"
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REPOSITORY") == REPO
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_SHA") == args.revision,
        "Issue writes require guarded production workflow",
    )

    root = Path(__file__).resolve().parents[2]

    result = apply(
        root, github_api, write_api, args.revision
    )

    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
