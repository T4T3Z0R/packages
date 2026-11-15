#!/usr/bin/env python3
import argparse
import importlib.util
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLANNER = ROOT / "scripts/package-pipeline/plan-history-pruning.py"

spec = importlib.util.spec_from_file_location(
    "history_pruning_planner", PLANNER
)
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


def remote_inventory(package, repo):
    release = "arch-history-" + package
    result = subprocess.run(
        [
            "gh", "release", "view", release,
            "--json", "assets",
            "--jq", "[.assets[].name]",
            "--repo", repo,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--inventory", type=Path)
    source.add_argument("--remote", action="store_true")

    args = parser.parse_args()

    policy = json.loads(planner.POLICY.read_text())
    if policy.get("schema_version") != 1:
        raise ValueError("Unsupported retention policy")

    retain = policy["previous_versions"].get(
        args.package, policy["default_previous_versions"]
    )

    release = "arch-history-" + args.package

    if args.remote:
        repo = os.environ.get("GH_REPO")
        token = os.environ.get("GH_TOKEN")

        if not repo or not token:
            raise ValueError("GH_REPO and GH_TOKEN are required")

        names = remote_inventory(args.package, repo)
        source_name = "github"
    else:
        names = json.loads(args.inventory.read_text())
        source_name = "local-inventory"

    plan = planner.build_plan(names, args.package, retain)

    plan["history_release"] = release
    plan["inventory_source"] = source_name
    plan["deletion_enabled"] = False

    print(json.dumps(plan, indent=2))


if __name__ == "__main__":
    main()
