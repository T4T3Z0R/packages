#!/usr/bin/env python3
"""Select affected approved packages from two complete Git trees.

Read-only. Does not dispatch, build, sign, or publish.
"""

import argparse
import json
import re
import subprocess
from pathlib import Path

from package_release_contract import (
    SUPPORTED, TEMPLATE_PACKAGES, workflow_file,
)

SELECTION_FIELDS = (
    "source_ref",
    "release_policy",
    "recipe",
    "status",
)


def eligible(config):
    if not isinstance(config, dict):
        return False
    if config.get("status") != "approved":
        return False
    if config.get("auto_publish") is not False:
        raise ValueError(
            "Approved package enables automatic publication"
        )
    return True


def select(before, after, changed_paths):
    """Return approved packages affected by the tree changes."""
    selected = []

    old = before["packages"]
    new = after["packages"]

    for name in SUPPORTED:
        current = new.get(name)

        if not eligible(current):
            continue

        previous = old.get(name)
        source_changed = (
            not isinstance(previous, dict)
            or any(
                previous.get(key) != current.get(key)
                for key in SELECTION_FIELDS
            )
        )

        recipe_changed = any(
            path.startswith(f"arch/{name}/")
            for path in changed_paths
        )

        workflow_changed = (
            f".github/workflows/{workflow_file(name)}"
            in changed_paths
        )

        if (
            source_changed
            or recipe_changed
            or workflow_changed
        ):
            selected.append(name)

    return selected


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args]
    )


def read_manifest(root, revision):
    raw = git(
        root, "show",
        f"{revision}:arch/packages/manifest.json"
    )
    return json.loads(raw)


def changed_paths(root, before, after):
    raw = git(
        root, "diff", "--name-only",
        "--no-renames", "-z", before, after
    )
    return {
        path.decode("utf-8")
        for path in raw.split(b"\0")
        if path
    }


def select_revisions(root, before, after):
    for revision in (before, after):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("Expected full Git commit SHA")

        git(root, "cat-file", "-e", f"{revision}^{{commit}}")

    old = read_manifest(root, before)
    new = read_manifest(root, after)
    changed = changed_paths(root, before, after)

    return select(old, new, changed)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument(
        "--repo", type=Path,
        default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args()

    root = args.repo.resolve()

    # Source-contract validation later reads files from this
    # checkout. Reject comparisons against a different tree.
    checkout = git(root, "rev-parse", "HEAD").decode().strip()
    if checkout != args.after:
        parser.error("--after must equal checked-out HEAD")

    packages = select_revisions(
        root, args.before, args.after
    )

    print(json.dumps({
        "before": args.before,
        "after": args.after,
        "packages": packages,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
