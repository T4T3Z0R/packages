#!/usr/bin/env python3
"""Plan historical retention without mutating release assets."""

import argparse
import json
import re
import subprocess
from functools import cmp_to_key
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def compare_versions(left, right):
    result = subprocess.run(
        ["vercmp", left, right],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    if result not in ("-1", "0", "1"):
        raise ValueError("Invalid vercmp result")

    return int(result)


def plan_pruning(
    package, names, versions, protected, retain,
    compare=compare_versions,
):
    if not re.fullmatch(r"[a-z][a-z0-9-]*", package):
        raise ValueError("Invalid package identity")

    if type(retain) is not int or retain < 1:
        raise ValueError(
            "Pruning requires positive retention policy"
        )

    if not isinstance(names, list) or not all(
        isinstance(name, str) for name in names
    ):
        raise ValueError("Invalid history inventory")

    if len(names) != len(set(names)):
        raise ValueError("Duplicate history assets")

    if not isinstance(versions, dict):
        raise ValueError("Invalid version metadata")

    pattern = re.compile(
        re.escape(package)
        + r"-([A-Za-z0-9._+]+)-([0-9.]+)"
        + r"-([A-Za-z0-9_]+)[.]pkg[.]tar[.]zst"
    )

    assets = set(names)
    packages = set()

    for name in names:
        base = name[:-4] if name.endswith(".sig") else name

        if not pattern.fullmatch(base):
            raise ValueError(
                "Unexpected history asset: " + name
            )

        packages.add(base)

    for name in packages:
        if name not in assets or name + ".sig" not in assets:
            raise ValueError(
                "Incomplete historical pair: " + name
            )

    if protected not in packages:
        raise ValueError("Protected package is missing")

    if set(versions) != packages:
        raise ValueError(
            "Version metadata does not match inventory"
        )

    architectures = set()

    for name in packages:
        match = pattern.fullmatch(name)
        version, release, arch = match.groups()
        architectures.add(arch)

        full = versions[name]

        if not isinstance(full, str):
            raise ValueError("Invalid full package version")

        if not re.fullmatch(
            r"(?:[0-9]+:)?[A-Za-z0-9._+]+-[0-9.]+",
            full,
        ):
            raise ValueError("Invalid full package version")

        if full.split(":")[-1] != f"{version}-{release}":
            raise ValueError(
                "Metadata version disagrees with filename"
            )

    if len(architectures) != 1:
        raise ValueError("Mixed history architectures")

    def compare_packages(left, right):
        return compare(versions[left], versions[right])

    ordered = sorted(
        packages,
        key=cmp_to_key(compare_packages),
        reverse=True,
    )

    for left, right in zip(ordered, ordered[1:]):
        if compare_packages(left, right) == 0:
            raise ValueError("Ambiguous historical versions")

    keep = {protected}

    for name in ordered:
        if len(keep) >= retain:
            break
        keep.add(name)

    retained = [
        name for name in ordered if name in keep
    ]

    excess = [
        name for name in reversed(ordered)
        if name not in keep
    ]

    def pairs(files):
        return [
            {"package": name, "signature": name + ".sig"}
            for name in files
        ]

    return {
        "package": package,
        "history_release": "arch-history-" + package,
        "previous_versions_to_keep": retain,
        "protected": protected,
        "keep": pairs(retained),
        "prune": pairs(excess),
        "dry_run": True,
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--package", required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--versions", type=Path, required=True)
    parser.add_argument("--protected", required=True)

    args = parser.parse_args()

    policy = json.loads(
        (ROOT / "arch/packages/retention.json").read_text()
    )

    if policy["schema_version"] != 1:
        raise ValueError("Unsupported retention policy")

    retain = policy["previous_versions"].get(
        args.package,
        policy["default_previous_versions"],
    )

    plan = plan_pruning(
        args.package,
        json.loads(args.inventory.read_text()),
        json.loads(args.versions.read_text()),
        args.protected,
        retain,
    )

    print(json.dumps(plan, indent=2))


if __name__ == "__main__":
    main()
