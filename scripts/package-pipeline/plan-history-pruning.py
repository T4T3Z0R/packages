#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
from functools import cmp_to_key
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "arch/packages/retention.json"


def compare_versions(left, right):
    result = subprocess.run(
        ["vercmp", left, right],
        check=True, capture_output=True, text=True,
    )
    value = int(result.stdout.strip())
    return (value > 0) - (value < 0)


def build_plan(names, package, retain, compare=compare_versions):
    if type(retain) is not int or retain < 0:
        raise ValueError("Invalid retention count")

    if not isinstance(names, list) or not all(
        isinstance(name, str) for name in names
    ):
        raise ValueError("History inventory must be a list of names")

    if len(names) != len(set(names)):
        raise ValueError("Duplicate history release assets")

    pattern = re.compile(
        re.escape(package)
        + r"-([^-]+)-([^-]+)-([^-]+)[.]pkg[.]tar[.]zst"
    )

    packages = {}
    inventory = set(names)

    for name in names:
        base = name[:-4] if name.endswith(".sig") else name
        match = pattern.fullmatch(base)

        if not match:
            raise ValueError("Unexpected history asset: " + name)

        if base not in inventory or base + ".sig" not in inventory:
            raise ValueError("Incomplete historical pair: " + base)

        version = match.group(1) + "-" + match.group(2)
        packages[base] = version

    ordered = sorted(
        packages,
        key=cmp_to_key(
            lambda a, b: compare(packages[a], packages[b])
        ),
        reverse=True,
    )

    for newer, older in zip(ordered, ordered[1:]):
        if compare(packages[newer], packages[older]) == 0:
            raise ValueError("Duplicate historical package version")

    if retain == 0 and ordered:
        raise ValueError("History exists for zero-retention package")

    keep = ordered[:retain]
    prune = ordered[retain:]

    return {
        "package": package,
        "previous_versions_to_keep": retain,
        "keep": [
            {"package": name, "signature": name + ".sig"}
            for name in keep
        ],
        "prune": [
            {"package": name, "signature": name + ".sig"}
            for name in prune
        ],
        "dry_run": True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--package", required=True)
    args = parser.parse_args()

    policy = json.loads(POLICY.read_text())

    if policy["schema_version"] != 1:
        raise ValueError("Unsupported retention policy")

    retain = policy["previous_versions"].get(
        args.package, policy["default_previous_versions"]
    )

    names = json.loads(args.inventory.read_text())
    plan = build_plan(names, args.package, retain)

    print(json.dumps(plan, indent=2))


if __name__ == "__main__":
    main()
