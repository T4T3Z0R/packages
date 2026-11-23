#!/usr/bin/env python3
"""Select one current upstream candidate; perform no GitHub writes."""

import argparse
import json
from pathlib import Path

from candidate_review import REF, plan
from discover_upstream import DEFAULT_MANIFEST


def select(report, package, candidate):
    if not isinstance(package, str):
        raise ValueError("Unsupported requested package")

    registry = json.loads(
        DEFAULT_MANIFEST.read_text()
    )["packages"]

    config = registry.get(package)

    if (
        not isinstance(config, dict)
        or config.get("status") != "approved"
        or config.get("auto_publish") is not False
    ):
        raise ValueError("Unsupported requested package")
    if not isinstance(candidate, str) or not REF.fullmatch(candidate):
        raise ValueError("Invalid requested candidate")

    proposals = plan(report)
    matches = [p for p in proposals if p["package"] == package]
    if len(matches) != 1:
        raise ValueError("Requested package has no actionable update")
    if matches[0]["candidate"] != candidate:
        raise ValueError("Requested candidate is no longer current")

    selected = [item for item in report if item["package"] == package]
    if len(selected) != 1:
        raise ValueError("Ambiguous requested package")
    return selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--package", required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    print(json.dumps(
        select(report, args.package, args.candidate),
        indent=2, sort_keys=True,
    ))


if __name__ == "__main__":
    main()
