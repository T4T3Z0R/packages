#!/usr/bin/env python3
"""Require unsigned manual validation to build the manifest-selected source."""
import argparse
import json
import re
from discover_upstream import DEFAULT_MANIFEST
from select_package_validation import TEMPLATE_PACKAGES

SHA = re.compile(r"[0-9a-f]{40}\Z")

def verify(manifest, package, source):
    if package not in TEMPLATE_PACKAGES:
        raise ValueError("Unsupported generated-recipe package")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("packages"), dict):
        raise ValueError("Malformed manifest")
    config = manifest["packages"].get(package)
    if not isinstance(config, dict) or config.get("status") != "approved":
        raise ValueError("Package not approved")
    if config.get("auto_publish") is not False:
        raise ValueError("Automatic publication forbidden")
    expected = config.get("source_ref")
    if not isinstance(source, str) or not isinstance(expected, str):
        raise ValueError("Invalid source identity")
    if package != "noctalia-greeter-t4t3z0r" and not SHA.fullmatch(source):
        raise ValueError("Expected exact commit SHA")
    if source != expected:
        raise ValueError(f"{package}: source differs from manifest selection")
    return {"package": package, "source": source, "verified": True}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    manifest = json.loads(DEFAULT_MANIFEST.read_text())
    print(json.dumps(verify(manifest, args.package, args.source), sort_keys=True))

if __name__ == "__main__":
    main()
