#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "scripts/package-pipeline"
POLICY = ROOT / "arch/packages/retention.json"


def invoke(script, package, fingerprint, staging, publish=False):
    args = [
        sys.executable, str(PIPELINE / script),
        "--package", package,
        "--fingerprint", fingerprint,
        "--staging", str(staging),
    ]
    if publish:
        args.append("--publish")

    result = subprocess.run(
        args, check=True, capture_output=True, text=True
    )
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--state", type=Path, default=Path("archive-state.txt")
    )
    parser.add_argument(
        "--staging", type=Path, default=Path("archive-output")
    )
    args = parser.parse_args()

    state = args.state.read_text().splitlines()
    if len(state) != 3:
        raise ValueError("Invalid assembly state")

    package, candidate, displaced = state

    if package != args.package or candidate != args.candidate:
        raise ValueError("Assembly identity mismatch")

    policy = json.loads(POLICY.read_text())
    if policy["schema_version"] != 1:
        raise ValueError("Unsupported retention policy")

    retain = policy["previous_versions"].get(
        package, policy["default_previous_versions"]
    )
    if type(retain) is not int or retain < 0:
        raise ValueError("Invalid retention count")

    staging = args.staging.resolve()
    expected = set()

    if displaced:
        if not re.fullmatch(
            r"[A-Za-z0-9._+-]+\.pkg\.tar\.zst",
            displaced
        ):
            raise ValueError("Invalid displaced package filename")
        if displaced == candidate:
            raise ValueError("Candidate equals displaced package")
        expected = {displaced, displaced + ".sig"}

    actual = (
        {item.name for item in staging.iterdir()}
        if staging.is_dir() else set()
    )
    if actual != expected:
        raise ValueError("Staging does not match assembly state")

    if not displaced:
        print(json.dumps({
            "gate_passed": True,
            "displaced": False,
            "history_verified": False
        }))
        return

    fingerprint = os.environ.get("SIGNING_SUBKEY", "")
    if not re.fullmatch(r"[A-Fa-f0-9]{40}", fingerprint):
        raise ValueError("Full signing fingerprint required")

    if retain:
        result = invoke(
            "publish-history.py",
            package, fingerprint, staging, publish=True
        )
        if (
            result.get("published") is not True
            or result.get("verified") is not True
            or result.get("release") != "arch-history-" + package
            or set(result.get("assets", [])) != expected
        ):
            raise ValueError("Historical publication not verified")
    else:
        result = invoke(
            "archive-repository.py",
            package, fingerprint, staging
        )
        if (
            result.get("verified") is not True
            or result.get("archive_required") is not False
            or result.get("file") != displaced
            or result.get("signature") != displaced + ".sig"
        ):
            raise ValueError("Displaced package preflight failed")

    print(json.dumps({
        "gate_passed": True,
        "displaced": True,
        "history_verified": bool(retain)
    }))


if __name__ == "__main__":
    main()
