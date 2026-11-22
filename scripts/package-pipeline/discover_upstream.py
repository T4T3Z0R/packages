#!/usr/bin/env python3
"""Read-only GitHub upstream source discovery."""

import argparse
import json
import os
import re
import urllib.request
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "arch/packages/manifest.json"

UPSTREAM = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
STABLE_TAG = re.compile(r"(?:v)?[0-9]+(?:\.[0-9]+){2}(?:\.[0-9]+)?\Z")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


def fetch_json(url):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "t4t3z0r-release-discovery",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def discover(name, config, fetch=fetch_json):
    upstream = config["upstream"]
    policy = config["release_policy"]
    selected = config["source_ref"]

    if not UPSTREAM.fullmatch(upstream):
        raise ValueError(f"{name}: invalid upstream repository")

    base = f"https://api.github.com/repos/{upstream}"

    if policy in ("pinned-tag", "pinned-commit"):
        candidate = selected
        channel = "pinned"
    elif policy == "stable-tag":
        release = fetch(f"{base}/releases/latest")
        if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
            raise ValueError(f"{name}: invalid stable release response")
        candidate = release.get("tag_name")
        if not isinstance(candidate, str) or not STABLE_TAG.fullmatch(candidate):
            raise ValueError(f"{name}: invalid upstream stable tag")
        channel = "stable-release"
    elif policy == "development-commit":
        repository = fetch(base)
        branch = repository.get("default_branch")
        if not isinstance(branch, str) or not branch:
            raise ValueError(f"{name}: missing default branch")
        commit = fetch(f"{base}/commits/{quote(branch, safe='')}")
        candidate = commit.get("sha")
        if not isinstance(candidate, str) or not COMMIT_SHA.fullmatch(candidate):
            raise ValueError(f"{name}: invalid upstream commit SHA")
        channel = "default-branch"
    else:
        raise ValueError(f"{name}: unsupported discovery policy")

    return {
        "package": name,
        "upstream": upstream,
        "policy": policy,
        "selected": selected,
        "candidate": candidate,
        "channel": channel,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--package", required=True)
    args = parser.parse_args()

    data = json.loads(args.manifest.read_text())
    config = data["packages"][args.package]
    print(json.dumps(discover(args.package, config), sort_keys=True))


if __name__ == "__main__":
    main()
