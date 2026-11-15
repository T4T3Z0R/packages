#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args()

    policy = json.loads(
        Path("arch/packages/retention.json").read_text()
    )
    assert policy["schema_version"] == 1

    retain = policy["previous_versions"].get(
        args.package,
        policy["default_previous_versions"],
    )
    if type(retain) is not int or retain < 0:
        raise ValueError("Invalid retention count")

    names = json.loads(args.inventory.read_text())
    if not isinstance(names, list) or not all(
        isinstance(name, str) for name in names
    ):
        raise ValueError("Inventory must be a JSON list of names")
    if len(names) != len(set(names)):
        raise ValueError("Duplicate release assets")

    pattern = re.compile(
        re.escape(args.package)
        + r"-([^-]+)-([^-]+)-([^-]+)\.pkg\.tar\.zst$"
    )
    if not pattern.fullmatch(args.candidate):
        raise ValueError("Candidate does not match package identity")

    packages = sorted(
        name for name in names if pattern.fullmatch(name)
    )

    if len(packages) > 1:
        raise ValueError("Multiple active versions of selected package")

    for name in packages:
        if name + ".sig" not in names:
            raise ValueError("Existing package lacks signature: " + name)

    current = packages[0] if packages else None
    displaced = (
        current if current != args.candidate else None
    )

    plan = {
        "package": args.package,
        "candidate": args.candidate,
        "current": current,
        "displaced": displaced,
        "history_release": (
            "arch-history-" + args.package if retain else None
        ),
        "previous_versions_to_keep": retain,
        "archive_required": bool(displaced and retain),
        "delete_live_after_publication": bool(displaced),
        "dry_run": True,
    }
    print(json.dumps(plan, indent=2))

if __name__ == "__main__":
    main()
