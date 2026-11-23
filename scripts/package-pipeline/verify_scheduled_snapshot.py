#!/usr/bin/env python3
"""Fail closed when scheduled discovery evidence becomes stale.

Read-only. Does not create issues or authorize packaging.
"""

import argparse
import json
from pathlib import Path


def verify(manifest, earlier, fresh):
    if not isinstance(manifest, dict):
        raise ValueError("Invalid manifest")

    packages = manifest.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("Invalid package registry")

    approved = {}

    for name, config in packages.items():
        if not isinstance(config, dict):
            raise ValueError("Malformed package configuration")
        if config.get("status") != "approved":
            continue
        if config.get("auto_publish") is not False:
            raise ValueError("Automatic publication enabled")
        approved[name] = config

    if not approved:
        raise ValueError("No approved packages")

    def index(records, label):
        if not isinstance(records, list):
            raise ValueError(f"Invalid {label} report")

        result = {}

        for item in records:
            if not isinstance(item, dict):
                raise ValueError(f"Malformed {label} entry")

            name = item.get("package")
            if name not in approved:
                raise ValueError(f"Unexpected {label} package")
            if name in result:
                raise ValueError(f"Duplicate {label} package")

            config = approved[name]

            for field, expected in (
                ("selected", config["source_ref"]),
                ("policy", config["release_policy"]),
                ("upstream", config["upstream"]),
            ):
                if item.get(field) != expected:
                    raise ValueError(
                        f"{name}: inconsistent {label} {field}"
                    )

            if item.get("status") not in (
                "update", "unchanged", "blocked"
            ):
                raise ValueError(f"{name}: invalid {label} status")

            if not isinstance(item.get("candidate"), str):
                raise ValueError(f"{name}: invalid candidate")

            result[name] = item

        if set(result) != set(approved):
            raise ValueError(f"Incomplete {label} report")

        return result

    original = index(earlier, "original")
    current = index(fresh, "fresh")

    changed = sorted(
        name for name in approved
        if original[name] != current[name]
    )

    if changed:
        raise ValueError(
            "Upstream changed since discovery: "
            + ", ".join(changed)
        )

    return len(approved)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("earlier", type=Path)
    parser.add_argument("fresh", type=Path)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("arch/packages/manifest.json"),
    )
    args = parser.parse_args()

    count = verify(
        json.loads(args.manifest.read_text()),
        json.loads(args.earlier.read_text()),
        json.loads(args.fresh.read_text()),
    )
    print(f"PASS: {count} upstream snapshots still current")


if __name__ == "__main__":
    main()
