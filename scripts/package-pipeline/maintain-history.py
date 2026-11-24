#!/usr/bin/env python3
"""Inspect historical releases or recover existing transactions."""

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "arch/packages/retention.json"

SPEC = importlib.util.spec_from_file_location(
    "history_publisher",
    Path(__file__).with_name("publish-history.py"),
)
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


def configured_packages():
    policy = json.loads(POLICY.read_text())

    if (
        type(policy["schema_version"]) is not int
        or policy["schema_version"] != 1
        or type(policy["default_previous_versions"]) is not int
        or policy["default_previous_versions"] != 0
    ):
        raise ValueError("Unsupported retention policy")

    packages = policy["previous_versions"]

    if not isinstance(packages, dict):
        raise ValueError("Invalid retention package mapping")

    for package, count in packages.items():
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]*", package)
            or type(count) is not int
            or count < 1
        ):
            raise ValueError("Invalid historical retention policy")

    return packages


def maintain_package(package, retain, recover=False):
    release = "arch-history-" + package
    snapshot = publisher.history_snapshot(release)
    names = set(snapshot["assets"])

    if publisher.JOURNAL_NAME not in names:
        publisher.validate_history_inventory(
            names, package, None,
            allow_incomplete_current=False,
        )

        publisher.require_unchanged_snapshot(snapshot)

        return {
            "package": package,
            "release": release,
            "state": "clean",
            "archived_versions": len(names) // 2,
            "retention": retain,
            "over_limit": len(names) // 2 > retain,
        }

    existing = publisher.load_pruning_journal(release)

    if existing is None:
        raise ValueError("Pending pruning journal disappeared")

    if existing["journal"]["retain"] != retain:
        raise ValueError("Transaction retention policy changed")

    if existing["journal_asset"] != snapshot["assets"][
        publisher.JOURNAL_NAME
    ]:
        raise ValueError("Pending pruning journal changed")

    publisher.require_unchanged_snapshot(snapshot)

    if not recover:
        return {
            "package": package,
            "release": release,
            "state": "pending",
            "transaction_state": existing["state"]["state"],
            "remaining_assets": len(
                existing["state"]["remaining"]
            ),
        }

    result = publisher.execute_pruning_transaction(
        release, expected=existing
    )

    if result["state"] != "complete":
        raise ValueError("Historical recovery not completed")

    return {
        "package": package,
        "release": release,
        "state": "recovered",
        "deleted_assets": result["deleted"],
    }


def maintain(recover=False):
    packages = configured_packages()
    results = []

    for package, retain in sorted(packages.items()):
        try:
            result = maintain_package(
                package, retain, recover=recover
            )
        except (
            ValueError, KeyError, TypeError,
            OSError, publisher.subprocess.CalledProcessError,
        ) as error:
            result = {
                "package": package,
                "release": "arch-history-" + package,
                "state": "failed",
                "error": str(error),
            }

        results.append(result)

    return {
        "mode": "recover" if recover else "inspect",
        "success": all(
            item["state"] != "failed" for item in results
        ),
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--recover", action="store_true")
    args = parser.parse_args()

    if not os.environ.get("GH_TOKEN") or not os.environ.get("GH_REPO"):
        raise ValueError("GH_TOKEN and GH_REPO are required")

    result = maintain(recover=args.recover)
    print(json.dumps(result, indent=2))

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
