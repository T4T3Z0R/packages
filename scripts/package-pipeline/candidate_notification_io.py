#!/usr/bin/env python3
"""Guarded, single-attempt candidate alert GitHub/Pushover adapter.

The calling workflow MUST hold package-candidate-issue-writes throughout.
The dispatcher and history reader provide the transaction invariants.
"""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from candidate_notification_dispatch import dispatch_one
from candidate_notification_reader import inspect_outbox
from candidate_notification_state import TITLE, TRUSTED_AUTHOR, record_body
from github_candidate_issues import REPOSITORY
from github_validation_history import github_api

PUSHOVER_URL = "https://api.pushover.net/1/messages.json"
SHA = re.compile(r"[0-9a-f]{40}\Z")


def validate_targets(targets):
    """Validate the entire verified-new-issues file before any I/O."""
    if not isinstance(targets, list):
        raise ValueError("Invalid candidate alert batch")

    identities = set()
    numbers = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {
            "package", "candidate", "issue_number"
        }:
            raise ValueError("Invalid candidate alert target")

        number = target["issue_number"]
        package = target["package"]
        candidate = target["candidate"]
        if type(number) is not int or number < 1:
            raise ValueError("Invalid alert issue number")
        if not isinstance(package, str) or not isinstance(candidate, str):
            raise ValueError("Invalid alert candidate identity")
        if TITLE.fullmatch(
            f"Package candidate: {package} @ {candidate}"
        ) is None:
            raise ValueError("Unsafe alert candidate identity")
        key = (package, candidate)
        if key in identities or number in numbers:
            raise ValueError("Duplicate alert target")
        identities.add(key)
        numbers.add(number)
    return targets


def authorize(env, local_head, remote_head):
    """Fail closed unless this is the authorized first scheduled run."""
    required = {
        "CANDIDATE_NOTIFICATION_WRITE_ENABLED": "1",
        "GITHUB_EVENT_NAME": "schedule",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ATTEMPT": "1",
    }
    for key, expected in required.items():
        if env.get(key) != expected:
            raise ValueError(f"Unauthorized notification context: {key}")

    run = env.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[1-9][0-9]*", run):
        raise ValueError("Invalid workflow run identity")

    sha = env.get("GITHUB_SHA", "")
    if not SHA.fullmatch(sha) or local_head != sha or remote_head != sha:
        raise ValueError("Notification production revision changed")

    for key in ("GH_TOKEN", "PUSHOVER_APP_TOKEN", "PUSHOVER_USER_KEY"):
        if not env.get(key):
            raise ValueError(f"Missing notification credential: {key}")

    return int(run)


def post_comment(state, number, package, candidate, run_id,
                 receipt=None, *, runner=subprocess.run):
    """Write one authenticated comment; never retry ambiguous errors."""
    if state == "accepted" and receipt is None:
        raise ValueError("Pushover receipt required for acknowledgment")
    body = record_body(
        state, number, package, candidate, run_id,
        pushover_request=receipt,
    )
    response = runner(
        ["gh", "api", "--method", "POST",
         f"repos/{REPOSITORY}/issues/{number}/comments",
         "--raw-field", f"body={body}"],
        check=True, capture_output=True, text=True,
    )
    posted = json.loads(response.stdout)
    if (
        not isinstance(posted, dict)
        or type(posted.get("id")) is not int
        or posted["id"] < 1
        or posted.get("body") != body
        or not isinstance(posted.get("user"), dict)
        or posted["user"].get("login") != TRUSTED_AUTHOR
    ):
        raise ValueError("Unconfirmed GitHub comment; reconcile manually")
    return posted


def send_pushover(number, package, candidate, *, app_token, user_key,
                  opener=urlopen):
    """One POST, without retries or logging credentials."""
    if type(number) is not int or number < 1:
        raise ValueError("Invalid alert issue number")
    if not isinstance(package, str) or not isinstance(candidate, str):
        raise ValueError("Invalid alert candidate identity")
    if TITLE.fullmatch(
        f"Package candidate: {package} @ {candidate}"
    ) is None:
        raise ValueError("Unsafe alert candidate identity")
    if not all(isinstance(x, str) and x for x in (app_token, user_key)):
        raise ValueError("Missing Pushover credentials")

    form = urlencode({
        "token": app_token,
        "user": user_key,
        "title": "Package candidate review required",
        "message": (
            f"{package} candidate {candidate} needs manual review. "
            "No build or publication authorized."
        ),
        "url": f"https://github.com/{REPOSITORY}/issues/{number}",
        "url_title": "Open candidate review",
    }).encode("utf-8")
    request = Request(
        PUSHOVER_URL, data=form, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with opener(request, timeout=15) as response:
        http_status = response.status
        data = response.read(65537)
    if len(data) > 65536:
        raise ValueError("Oversized Pushover response; reconcile manually")
    payload = json.loads(data)
    if not isinstance(payload, dict):
        raise ValueError("Invalid Pushover response; reconcile manually")
    return {
        "http_status": http_status,
        "status": payload.get("status"),
        "request": payload.get("request"),
    }


def deliver_batch(targets, run_id, *, inspect, post, send):
    """Preflight whole batch; independently reread after each action."""
    validate_targets(targets)
    if type(run_id) is not int or run_id < 1:
        raise ValueError("Invalid notification workflow run")
    if not all(callable(x) for x in (inspect, post, send)):
        raise ValueError("Missing alert operations")
    if not targets:
        return []

    rows = inspect()
    if not isinstance(rows, list):
        raise ValueError("Incomplete notification outbox")
    by_number = {}
    for row in rows:
        if not isinstance(row, dict) or type(row.get("issue_number")) is not int:
            raise ValueError("Invalid notification outbox row")
        number = row["issue_number"]
        if number in by_number:
            raise ValueError("Duplicate notification issue number")
        by_number[number] = row

    for target in targets:
        row = by_number.get(target["issue_number"])
        if row is None or any(
            row.get(key) != target[key]
            for key in ("package", "candidate", "issue_number")
        ) or (
            row.get("state") != "unclaimed"
            or row.get("decision") is not None
            or row.get("deliverable") is not True
            or row.get("run_id") is not None
        ):
            raise ValueError("Batch contains ineligible notification")

    def read(number):
        fresh = inspect()
        if not isinstance(fresh, list):
            raise ValueError("Incomplete notification outbox")
        matches = [
            row for row in fresh
            if isinstance(row, dict) and row.get("issue_number") == number
        ]
        if len(matches) != 1:
            raise ValueError("Missing or duplicated notification issue")
        return matches[0]

    accepted = []
    for target in targets:
        accepted.append(dispatch_one(
            target, run_id,
            read=read,
            claim=lambda n, p, c, r: post("claimed", n, p, c, r),
            send=send,
            acknowledge=lambda n, p, c, r, receipt: post(
                "accepted", n, p, c, r, receipt
            ),
        ))
    return accepted


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", type=Path)
    parser.add_argument(
        "--manifest", type=Path,
        default=Path("arch/packages/manifest.json"),
    )
    args = parser.parse_args()
    targets = validate_targets(json.loads(args.targets.read_text()))
    if not targets:
        print('{"accepted_notifications": 0}')
        return

    env = os.environ
    # Basic gates precede all network reads. Full authorization also
    # confirms local and remote production SHAs before any mutation.
    for key, value in {
        "CANDIDATE_NOTIFICATION_WRITE_ENABLED": "1",
        "GITHUB_EVENT_NAME": "schedule",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ATTEMPT": "1",
    }.items():
        if env.get(key) != value:
            raise ValueError(f"Unauthorized notification context: {key}")

    local_head = subprocess.run(
        ["git", "-c",
         f"safe.directory={env.get('GITHUB_WORKSPACE', '')}",
         "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    remote = github_api(f"repos/{REPOSITORY}/branches/main")
    remote_head = remote.get("commit", {}).get("sha") if isinstance(remote, dict) else None
    run_id = authorize(env, local_head, remote_head)

    manifest = json.loads(args.manifest.read_text())
    results = deliver_batch(
        targets, run_id,
        inspect=lambda: inspect_outbox(manifest, github_api),
        post=post_comment,
        send=lambda n, p, c: send_pushover(
            n, p, c,
            app_token=env["PUSHOVER_APP_TOKEN"],
            user_key=env["PUSHOVER_USER_KEY"],
        ),
    )
    print(json.dumps({"accepted_notifications": len(results)}, sort_keys=True))


if __name__ == "__main__":
    main()
