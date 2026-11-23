#!/usr/bin/env python3
"""Read-only identity of one approved package's build inputs."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from select_package_validation import SUPPORTED, TEMPLATE_PACKAGES, workflow_file

SHA = re.compile(r"[0-9a-f]{40}\Z")


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args],
        stderr=subprocess.PIPE,
    ).decode().strip()


def fingerprint(root, revision, package):
    if package not in SUPPORTED:
        raise ValueError("Unsupported package")

    if not SHA.fullmatch(revision):
        raise ValueError("Full Git commit SHA required")

    git(root, "cat-file", "-e", f"{revision}^{{commit}}")

    manifest = json.loads(git(
        root, "show",
        f"{revision}:arch/packages/manifest.json"
    ))

    config = manifest["packages"][package]

    if config.get("status") != "approved":
        raise ValueError("Package is not approved")

    if config.get("auto_publish") is not False:
        raise ValueError("Automatic publication is forbidden")

    recipe = (f"arch/{package}/PKGBUILD.in" if package in TEMPLATE_PACKAGES
              else f"arch/{package}/PKGBUILD")
    if config.get("recipe") != recipe:
        raise ValueError("Unexpected recipe path")
    git(root, "cat-file", "-e", f"{revision}:{recipe}")

    recipe_tree = git(
        root, "rev-parse", "--verify",
        f"{revision}:arch/{package}"
    )

    workflow_blob = git(
        root, "rev-parse", "--verify",
        f"{revision}:.github/workflows/{workflow_file(package)}"
    )

    # Canonical serialization makes object order irrelevant.
    inputs = {
        "schema": 1,
        "package": package,
        "manifest": config,
        "recipe_tree": recipe_tree,
        "workflow_blob": workflow_blob,
    }

    encoded = json.dumps(
        inputs, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument(
        "--repo", type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    args = parser.parse_args()

    root = args.repo.resolve()
    head = git(root, "rev-parse", "HEAD")

    if args.revision != head:
        parser.error(
            "--revision must equal the checked-out HEAD"
        )

    print(json.dumps({
        "revision": args.revision,
        "package": args.package,
        "fingerprint": fingerprint(
            root, args.revision, args.package
        ),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
