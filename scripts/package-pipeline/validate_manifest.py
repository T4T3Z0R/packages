#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "arch/packages/manifest.json"

PACKAGE_NAME = re.compile(r"[a-z][a-z0-9-]*", re.ASCII)
UPSTREAM = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
STABLE_TAG = re.compile(r"v[0-9]+(?:[.][0-9]+){2}(?:[.][0-9]+)?", re.ASCII)
COMMIT_SHA = re.compile(r"[0-9a-f]{40}", re.ASCII)

STABLE_POLICIES = {"stable-tag", "pinned-tag"}
COMMIT_POLICIES = {"development-commit", "pinned-commit"}
SUPPORTED_POLICIES = STABLE_POLICIES | COMMIT_POLICIES


REQUIRED_FIELDS = {
    "upstream", "source_ref", "release_policy",
    "license", "recipe", "status", "auto_publish",
}

def validate():
    data = json.loads(MANIFEST.read_text())

    if type(data) is not dict or set(data) != {"schema_version", "packages"}:
        raise ValueError("Invalid manifest structure")

    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported schema version")

    packages = data["packages"]
    if type(packages) is not dict or not packages:
        raise ValueError("Packages must be a nonempty object")

    for name, config in packages.items():
        if not PACKAGE_NAME.fullmatch(name):
            raise ValueError(f"Invalid package name: {name}")

        if type(config) is not dict or set(config) != REQUIRED_FIELDS:
            raise ValueError(f"{name}: unexpected or missing fields")

        for field in ("upstream", "source_ref", "release_policy",
                      "license", "recipe", "status"):
            if type(config[field]) is not str or not config[field]:
                raise ValueError(f"{name}: invalid {field}")

        if not UPSTREAM.fullmatch(config["upstream"]):
            raise ValueError(f"{name}: invalid upstream repository")

        policy = config["release_policy"]
        ref = config["source_ref"]

        if policy not in SUPPORTED_POLICIES:
            raise ValueError(f"{name}: unsupported release policy")

        if policy in STABLE_POLICIES:
            if not STABLE_TAG.fullmatch(ref):
                raise ValueError(f"{name}: invalid stable tag")

        if policy in COMMIT_POLICIES:
            if not COMMIT_SHA.fullmatch(ref):
                raise ValueError(f"{name}: invalid commit SHA")

        expected = f"arch/packages/{name}/PKGBUILD.in"
        if config["recipe"] != expected:
            raise ValueError(f"{name}: recipe path must be {expected}")

        if config["status"] not in ("candidate", "approved"):
            raise ValueError(f"{name}: invalid status")

        if type(config["auto_publish"]) is not bool:
            raise ValueError(f"{name}: auto_publish must be boolean")

        if config["auto_publish"]:
            raise ValueError(f"{name}: automatic publication not enabled")

        print("PASS: {} ({})".format(name, config["source_ref"]))

    print(f"PASS: {len(packages)} package definition(s) validated")

if __name__ == "__main__":
    try:
        validate()
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
