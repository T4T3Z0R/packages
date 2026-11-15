#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def command(*args):
    return subprocess.run(
        args, check=True, capture_output=True, text=True
    ).stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument(
        "--staging", type=Path, default=Path("archive-output")
    )
    args = parser.parse_args()

    fingerprint = args.fingerprint.upper()

    if not re.fullmatch("[A-F0-9]{40}", fingerprint):
        raise ValueError("Expected full signing fingerprint")

    policy = json.loads(
        (ROOT / "arch/packages/retention.json").read_text()
    )

    if policy["schema_version"] != 1:
        raise ValueError("Unsupported retention policy")

    count = policy["previous_versions"].get(
        args.package, policy["default_previous_versions"]
    )

    if type(count) is not int or count < 0:
        raise ValueError("Invalid retention count")

    files = (
        sorted(p for p in args.staging.iterdir() if p.is_file())
        if args.staging.is_dir() else []
    )

    if not files:
        print(json.dumps({
            "package": args.package,
            "archive_required": False,
            "reason": "No displaced package",
            "dry_run": True,
        }, indent=2))
        return

    packages = [
        p for p in files if p.name.endswith(".pkg.tar.zst")
    ]

    if len(packages) != 1 or len(files) != 2:
        raise ValueError("Expected exactly one staged package/signature pair")

    package = packages[0]
    signature = Path(str(package) + ".sig")

    if signature not in files:
        raise ValueError("Missing staged package signature")

    metadata = command(
        "bsdtar", "-xOf", str(package), ".PKGINFO"
    )

    identities = [
        line.partition(" = ")[2]
        for line in metadata.splitlines()
        if line.startswith("pkgname = ")
    ]

    if identities != [args.package]:
        raise ValueError("Staged package identity mismatch")

    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ROOT))
    keyfile = (
        workspace / "arch/keys/t4t3z0r-package-signing.asc"
    )

    key_records = command(
        "gpg", "--batch", "--with-colons",
        "--show-keys", str(keyfile)
    )

    key_fingerprints = [
        line.split(":")[9].upper()
        for line in key_records.splitlines()
        if line.startswith("fpr:")
    ]

    if fingerprint not in key_fingerprints:
        raise ValueError("Signing fingerprint not in public key")

    status = command(
        "gpg", "--batch", "--status-fd", "1",
        "--verify", str(signature), str(package)
    )

    signers = [
        parts[2].upper()
        for line in status.splitlines()
        if (parts := line.split())[:2] == [
            "[GNUPG:]", "VALIDSIG"
        ]
    ]

    if signers != [fingerprint]:
        raise ValueError("Unauthorized or ambiguous package signature")

    print(json.dumps({
        "package": args.package,
        "file": package.name,
        "signature": signature.name,
        "history_release": (
            "arch-history-" + args.package if count else None
        ),
        "previous_versions_to_keep": count,
        "archive_required": count > 0,
        "verified": True,
        "dry_run": True,
    }, indent=2))


if __name__ == "__main__":
    main()
