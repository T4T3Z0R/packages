#!/usr/bin/env python3
"""Read-only verification of a merged package source selection.

A verified plan is not permission to sign or publish.
"""

import argparse
import json
import re
import subprocess
from pathlib import Path

from candidate_issue_state import classify
from select_package_validation import SUPPORTED, TEMPLATE_PACKAGES, workflow_file

REPO = "T4T3Z0R/packages"
OWNER = "T4T3Z0R"
SHA = re.compile(r"[0-9a-f]{40}\Z")
TITLE = re.compile(r"Package candidate: ([a-z0-9-]+) @ ([A-Za-z0-9._+-]{1,100})\Z")
REVIEW = re.compile(r"(?m)^Review issue: #([1-9][0-9]*)[ \t]*$")
MARKER = re.compile(
    r"<!-- t4t3z0r:source-selection:v1 issue=([1-9][0-9]*)"
    r" package=([a-z0-9-]+) candidate=([A-Za-z0-9._+-]{1,100}) -->"
)
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
PER_PAGE = 100
MAX_PAGES = 100


BOOTSTRAP_BASE = frozenset(('ghostty', 'keepassxc', 'syncthing', 'wezterm', 'yazi'))
BOOTSTRAP_PACKAGES = {'noctalia-custom': {'upstream': 'T4T3Z0R/noctalia', 'source_ref': '0a0dd757fe685b0ec7aa56943e3a9bd15a1d2df2', 'release_policy': 'reviewed-commit', 'tracking_ref': 'refs/heads/custom', 'license': 'MIT AND Apache-2.0', 'recipe': 'arch/noctalia-custom/PKGBUILD.in', 'status': 'approved', 'auto_publish': False}, 'noctalia-greeter-t4t3z0r': {'upstream': 'noctalia-dev/noctalia-greeter', 'source_ref': 'v1.7.1', 'release_policy': 'stable-git-tag', 'license': 'MIT', 'recipe': 'arch/noctalia-greeter-t4t3z0r/PKGBUILD.in', 'status': 'approved', 'auto_publish': False}, 'gameshell': {'upstream': 'phyver/GameShell', 'source_ref': '63ae30982cf28ec7de1a4de23b85d15eccc031d8', 'release_policy': 'development-commit', 'tracking_ref': 'refs/tags/latest', 'license': 'GPL-3.0-only', 'recipe': 'arch/gameshell/PKGBUILD.in', 'status': 'approved', 'auto_publish': False}}


MOONLIGHT_BOOTSTRAP_BASE = (
    BOOTSTRAP_BASE | set(BOOTSTRAP_PACKAGES)
)

MOONLIGHT_BOOTSTRAP_CONFIG = {
    "upstream": "moonlight-stream/moonlight-qt",
    "source_ref": "v6.2.0",
    "release_policy": "stable-tag",
    "license": "GPL-3.0-or-later",
    "recipe": "arch/moonlight-qt/PKGBUILD",
    "status": "approved",
    "auto_publish": False,
}


YAZI_BOOTSTRAP_ORIGINAL = {'upstream': 'sxyazi/yazi', 'source_ref': 'v26.9.1', 'release_policy': 'stable-tag', 'license': 'MIT', 'recipe': 'arch/packages/yazi/PKGBUILD.in', 'status': 'candidate', 'auto_publish': False}

YAZI_BOOTSTRAP_APPROVED = {'upstream': 'sxyazi/yazi', 'source_ref': 'v26.9.1', 'release_policy': 'stable-tag', 'license': 'MIT', 'recipe': 'arch/yazi/PKGBUILD', 'status': 'approved', 'auto_publish': False}

BROOT_BOOTSTRAP_BASE = (
    MOONLIGHT_BOOTSTRAP_BASE | {"moonlight-qt"}
)

BROOT_BOOTSTRAP_CONFIG = {
    "upstream": "Canop/broot",
    "source_ref": "v1.62.0",
    "release_policy": "stable-git-tag",
    "license": "MIT",
    "recipe": "arch/broot/PKGBUILD",
    "status": "approved",
    "auto_publish": False,
}


THUNAR_BOOTSTRAP_BASE = (
    BROOT_BOOTSTRAP_BASE | {"broot"}
)

THUNAR_BOOTSTRAP_CONFIG = {
    "upstream": "https://gitlab.xfce.org/xfce/thunar.git",
    "source_ref": "thunar-4.20.10",
    "release_policy": "stable-xfce-git-tag",
    "license": "GPL-2.0-or-later AND LGPL-2.1-only",
    "recipe": "arch/thunar/PKGBUILD",
    "status": "approved",
    "auto_publish": False
}


MOUSEPAD_BOOTSTRAP_BASE = (
    THUNAR_BOOTSTRAP_BASE | {"thunar"}
)


MOUSEPAD_BOOTSTRAP_CONFIG = {
    "upstream": "https://gitlab.xfce.org/apps/mousepad.git",
    "source_ref": "mousepad-0.7.0",
    "release_policy": "stable-xfce-git-tag",
    "license": "GPL-2.0-or-later",
    "recipe": "arch/mousepad/PKGBUILD",
    "status": "approved",
    "auto_publish": False,
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def collection(api, endpoint):
    """Read a complete GitHub REST array; reject malformed pagination."""
    items, ids = [], set()
    for page in range(1, MAX_PAGES + 1):
        batch = api(f"{endpoint}{'&' if '?' in endpoint else '?'}"
                    f"per_page={PER_PAGE}&page={page}")
        require(isinstance(batch, list) and len(batch) <= PER_PAGE,
                "Invalid GitHub collection page")
        for item in batch:
            require(isinstance(item, dict), "Malformed GitHub record")
            key = item.get("id")
            require(type(key) is int and key > 0 and key not in ids,
                    "Duplicate or invalid GitHub record identity")
            ids.add(key)
        items.extend(batch)
        if len(batch) < PER_PAGE:
            return items
    raise ValueError("GitHub collection exceeds pagination limit")


def changed_source(before, after):
    """Return the only changed approved source or None; fail on ambiguity."""
    require(isinstance(before, dict) and isinstance(after, dict),
            "Invalid manifest data")
    require(before.get("schema_version") == after.get("schema_version") == 1,
            "Unexpected manifest schema")
    old, new = before.get("packages"), after.get("packages")
    require(isinstance(old, dict) and isinstance(new, dict),
            "Missing package mapping")
    if set(old) != set(new):
        # Initial Mousepad registration is not a source approval.
        if set(old) == MOUSEPAD_BOOTSTRAP_BASE:
            require(
                set(new) == MOUSEPAD_BOOTSTRAP_BASE | {"mousepad"},
                "Unexpected Mousepad registry expansion",
            )
            require(
                all(old[name] == new[name] for name in old),
                "Existing package modified during Mousepad bootstrap",
            )
            require(
                new["mousepad"] == MOUSEPAD_BOOTSTRAP_CONFIG,
                "Mousepad bootstrap configuration changed",
            )
            return None

        # Initial Thunar registration is not a source approval.
        if set(old) == THUNAR_BOOTSTRAP_BASE:
            require(
                set(new) == THUNAR_BOOTSTRAP_BASE | {"thunar"},
                "Unexpected Thunar registry expansion",
            )
            require(
                all(old[name] == new[name] for name in old),
                "Existing package modified during Thunar bootstrap",
            )
            require(
                new["thunar"] == THUNAR_BOOTSTRAP_CONFIG,
                "Thunar bootstrap configuration changed",
            )
            return None

        # Initial Broot registration is not a source approval.
        if set(old) == BROOT_BOOTSTRAP_BASE:
            require(
                set(new) == BROOT_BOOTSTRAP_BASE | {"broot"},
                "Unexpected Broot registry expansion",
            )
            require(
                all(old[name] == new[name] for name in old),
                "Existing package modified during Broot bootstrap",
            )
            require(
                new["broot"] == BROOT_BOOTSTRAP_CONFIG,
                "Broot bootstrap configuration changed",
            )
            return None

        # Initial Moonlight registration is not a source approval.
        if set(old) == MOONLIGHT_BOOTSTRAP_BASE:
            require(
                set(new) == MOONLIGHT_BOOTSTRAP_BASE | {"moonlight-qt"},
                "Unexpected Moonlight registry expansion",
            )
            require(
                all(old[name] == new[name] for name in old),
                "Existing package modified during Moonlight bootstrap",
            )
            require(
                new["moonlight-qt"] == MOONLIGHT_BOOTSTRAP_CONFIG,
                "Moonlight bootstrap configuration changed",
            )
            return None

        # This is the one-time seven-package migration, not a
        # reviewed source selection. Never dispatch a build here.
        require(set(old) == BOOTSTRAP_BASE,
                "Unexpected bootstrap baseline")
        require(set(new) == BOOTSTRAP_BASE | set(BOOTSTRAP_PACKAGES),
                "Unexpected package registry expansion")
        require(all(old[name] == new[name] for name in old),
                "Existing package modified during bootstrap")
        require(all(new[name] == config for name, config
                    in BOOTSTRAP_PACKAGES.items()),
                "Bootstrap package configuration changed")
        return None
    # Initial Yazi registration approval is not a source update.
    # Only the exact original registration may be promoted.
    if (
        old.get("yazi") == YAZI_BOOTSTRAP_ORIGINAL
        and new.get("yazi") == YAZI_BOOTSTRAP_APPROVED
    ):
        require(
            all(old[name] == new[name]
                for name in old if name != "yazi"),
            "Existing package modified during Yazi bootstrap",
        )
        return None

    differences = []
    for package in new:
        a, b = old[package], new[package]
        require(isinstance(a, dict) and isinstance(b, dict),
                "Malformed package configuration")
        if a == b:
            continue
        require(package in SUPPORTED, "Unsupported package modified")
        require(a.get("status") == b.get("status") == "approved",
                "Package approval changed")
        require(a.get("auto_publish") is False
                and b.get("auto_publish") is False,
                "Automatic publishing must remain disabled")
        require(isinstance(a.get("source_ref"), str)
                and isinstance(b.get("source_ref"), str)
                and a["source_ref"] != b["source_ref"],
                "Invalid source selection")
        require({k: v for k, v in a.items() if k != "source_ref"} ==
                {k: v for k, v in b.items() if k != "source_ref"},
                "Other manifest fields changed")
        differences.append((package, a["source_ref"], b["source_ref"], b))
    require(len(differences) <= 1, "Multiple source changes in one push")
    return differences[0] if differences else None


def owner_approved(events, issue, merged_at):
    require(isinstance(events, list) and isinstance(issue, dict),
            "Missing approval history")
    actions = []
    identities = set()
    for event in events:
        require(isinstance(event, dict), "Malformed issue history event")
        key = event.get("id")
        require(type(key) is int and key > 0 and key not in identities,
                "Duplicate issue history event")
        identities.add(key)
        kind = event.get("event")
        label = event.get("label")
        if kind in ("labeled", "unlabeled") and isinstance(label, dict) \
                and label.get("name") == "candidate:approved":
            timestamp = event.get("created_at")
            require(isinstance(timestamp, str) and STAMP.fullmatch(timestamp),
                    "Invalid approval timestamp")
            actor = event.get("actor")
            require(isinstance(actor, dict), "Missing approval actor")
            actions.append((timestamp, key, kind, actor.get("login")))
    require(actions, "No approval label history")
    actions.sort()
    timestamp, _, kind, actor = actions[-1]
    require(kind == "labeled" and actor == OWNER,
            "Latest approval was not applied by owner")
    require(isinstance(merged_at, str) and STAMP.fullmatch(merged_at),
            "Invalid PR merge timestamp")
    require(timestamp <= merged_at,
            "Approval was applied after the PR was merged")


def plan(event, before, after, pulls, issue=None, history=None):
    require(isinstance(event, dict), "Invalid push event")
    require(event.get("ref") == "refs/heads/main"
            and isinstance(event.get("repository"), dict)
            and event["repository"].get("full_name") == REPO,
            "Unexpected push destination")
    require(event.get("forced") is False and event.get("deleted") is False,
            "Nonstandard push")
    require(isinstance(event.get("sender"), dict)
            and event["sender"].get("login") == OWNER,
            "Push must originate from repository owner")
    revision = event.get("after")
    predecessor = event.get("before")
    require(isinstance(revision, str) and SHA.fullmatch(revision),
            "Invalid after revision")
    require(isinstance(predecessor, str) and SHA.fullmatch(predecessor)
            and predecessor != "0" * 40,
            "Invalid before revision")

    change = changed_source(before, after)
    if change is None:
        decision = (
            "bootstrap_registry_expansion"
            if set(before["packages"]) != set(after["packages"])
            else "no_source_change"
        )
        return {"decision": decision, "revision": revision,
                "validation_dispatched": False, "publication_authorized": False}
    package, old_ref, new_ref, config = change

    require(isinstance(pulls, list), "Missing associated PR history")
    matches = []
    ids = set()
    for pr in pulls:
        require(isinstance(pr, dict), "Malformed associated PR")
        key = pr.get("id")
        require(type(key) is int and key > 0 and key not in ids,
                "Duplicate associated PR")
        ids.add(key)
        if (pr.get("merged_at") is not None
            and pr.get("merge_commit_sha") == revision
            and isinstance(pr.get("base"), dict)
            and pr["base"].get("ref") == "main"):
            matches.append(pr)
    require(len(matches) == 1, "Exactly one merged PR must match push")
    pr = matches[0]
    require(type(pr.get("number")) is int and pr["number"] > 0,
            "Invalid merged PR number")
    merged_by = pr.get("merged_by")
    require(isinstance(merged_by, dict)
            and merged_by.get("login") == OWNER,
            "Source-selection PR must be merged by owner")
    merged_at = pr["merged_at"]
    require(isinstance(merged_at, str), "Missing merge timestamp")

    body = pr.get("body")
    require(isinstance(body, str), "Missing source-selection PR body")
    numbers = REVIEW.findall(body)
    require(len(numbers) == 1, "Expected exactly one review-issue reference")
    issue_number = int(numbers[0])
    markers = MARKER.findall(body)
    if package in TEMPLATE_PACKAGES:
        require(markers == [(str(issue_number), package, new_ref)],
                "Generated-recipe PR missing exact selection marker")
        head = pr.get("head")
        require(isinstance(head, dict) and head.get("ref") ==
                f"source-selection/issue-{issue_number}-{package}",
                "Unexpected generated-selection PR branch")
    else:
        require(not markers or markers == [(str(issue_number), package, new_ref)],
                "Mismatched fixed-recipe selection marker")

    require(isinstance(issue, dict)
            and issue.get("number") == issue_number
            and "pull_request" not in issue,
            "Unrelated review issue")
    author = issue.get("user")
    require(isinstance(author, dict)
            and author.get("login") in (OWNER, "github-actions[bot]"),
            "Untrusted review issue author")
    title = issue.get("title")
    match = TITLE.fullmatch(title) if isinstance(title, str) else None
    require(match is not None and match.groups() == (package, new_ref),
            "Review issue describes another candidate")
    issue_body = issue.get("body")
    require(isinstance(issue_body, str), "Missing issue evidence")
    for line in (f"- Package: `{package}`", f"- Selected: `{old_ref}`",
                 f"- Candidate: `{new_ref}`"):
        require(issue_body.splitlines().count(line) == 1,
                "Review issue source evidence mismatch")
    result = classify({"title": title}, [issue])
    require(result.get("action") == "approved"
            and result.get("issue_number") == issue_number,
            "Source-selection issue is not approved")
    owner_approved(history, issue, merged_at)

    inputs = {"publish": False}
    if package == "noctalia-custom":
        inputs["source_ref"] = new_ref
    elif package == "noctalia-greeter-t4t3z0r":
        inputs["source_tag"] = new_ref
    elif package == "gameshell":
        require(config.get("tracking_ref") == "refs/tags/latest",
                "GameShell tracking ref changed")
        inputs["source_ref"] = "latest"

    return {"decision": "review_validation", "revision": revision,
            "package": package, "selected": new_ref,
            "workflow": workflow_file(package), "inputs": inputs,
            "pr_number": pr.get("number"), "issue_number": issue_number,
            "validation_dispatched": False, "publication_authorized": False}


def cli_api(endpoint):
    raw = subprocess.check_output(["gh", "api", "--method", "GET", endpoint],
                                  text=True)
    return json.loads(raw)


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args],
                                   text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("event", type=Path)
    parser.add_argument("--repo", type=Path,
                        default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    event = json.loads(args.event.read_text())
    root = args.repo.resolve()
    after = event.get("after")
    before = event.get("before")
    require(git(root, "rev-parse", "HEAD") == after,
            "Checkout does not match push revision")
    git(root, "merge-base", "--is-ancestor", before, after)
    original = json.loads(git(root, "show", f"{before}:arch/packages/manifest.json"))
    selected = json.loads(git(root, "show", f"{after}:arch/packages/manifest.json"))
    associated = collection(cli_api, f"repos/{REPO}/commits/{after}/pulls")
    candidates = [p for p in associated if p.get("merge_commit_sha") == after
                  and p.get("merged_at") is not None]
    require(len(candidates) <= 1, "Ambiguous associated merged PRs")
    pulls = []
    if candidates:
        number = candidates[0].get("number")
        require(type(number) is int and number > 0, "Invalid associated PR")
        full = cli_api(f"repos/{REPO}/pulls/{number}")
        require(isinstance(full, dict) and full.get("id") == candidates[0].get("id"),
                "Full PR record does not match association")
        pulls = [full]
    issue = history = None
    if changed_source(original, selected):
        require(len(candidates) == 1, "Ambiguous merged source-selection PR")
        body = candidates[0].get("body") or ""
        refs = REVIEW.findall(body)
        require(len(refs) == 1, "Missing unique approval issue reference")
        number = int(refs[0])
        issue = cli_api(f"repos/{REPO}/issues/{number}")
        history = collection(cli_api, f"repos/{REPO}/issues/{number}/events")
    print(json.dumps(plan(event, original, selected, pulls, issue, history),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
