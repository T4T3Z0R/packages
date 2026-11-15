#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "scripts/package-pipeline/archive-repository.py"


def run(*args):
    return subprocess.run(
        args, check=True, capture_output=True, text=True
    ).stdout


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify_downloaded_pair(package, signature, fingerprint):
    status = run(
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

    if signers != [fingerprint.upper()]:
        raise ValueError("Archived signature has unauthorized signer")


def inventory(release):
    names = json.loads(run(
        "gh", "release", "view", release,
        "--json", "assets", "--jq", "[.assets[].name]",
        "--repo", os.environ["GH_REPO"]
    ))
    if not isinstance(names, list) or not all(
        isinstance(name, str) and name and "/" not in name
        for name in names
    ):
        raise ValueError("Invalid history release inventory")
    if len(names) != len(set(names)):
        raise ValueError("Duplicate history release assets")
    return set(names)


def validate_history_inventory(names, package, current_file, allow_incomplete_current=True):
    pattern = re.compile(
        re.escape(package)
        + r"-[^-]+-[^-]+-[^-]+\.pkg\.tar\.zst"
    )

    packages = set()

    for name in names:
        base = name[:-4] if name.endswith(".sig") else name
        if not pattern.fullmatch(base):
            raise ValueError("Unexpected history release asset: " + name)
        packages.add(base)

    for name in packages:
        if name == current_file and allow_incomplete_current:
            continue
        if name not in names or name + ".sig" not in names:
            raise ValueError("Incomplete historical package pair: " + name)


def download(release, name, directory):
    run(
        "gh", "release", "download", release,
        "--pattern", name, "--dir", str(directory),
        "--repo", os.environ["GH_REPO"]
    )
    result = directory / name
    if not result.is_file():
        raise ValueError("Downloaded archive asset missing: " + name)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--staging", type=Path,
                        default=Path("archive-output"))
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()

    verified = json.loads(run(
        sys.executable, str(PREFLIGHT),
        "--package", args.package,
        "--fingerprint", args.fingerprint,
        "--staging", str(args.staging.resolve())
    ))

    if not verified["archive_required"]:
        print(json.dumps({
            "archive_required": False,
            "published": False
        }, indent=2))
        return

    release = verified["history_release"]
    filenames = [verified["file"], verified["signature"]]
    local = {name: args.staging.resolve() / name
             for name in filenames}

    if not args.publish:
        print(json.dumps({
            "archive_required": True,
            "release": release,
            "assets": filenames,
            "published": False,
            "dry_run": True
        }, indent=2))
        return

    if not os.environ.get("GH_TOKEN") or not os.environ.get("GH_REPO"):
        raise ValueError("GH_TOKEN and GH_REPO are required")

    remote = inventory(release)
    validate_history_inventory(remote, args.package, filenames[0])

    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)

        # Existing assets must match byte-for-byte; never clobber.
        for name in filenames:
            if name in remote:
                fetched = download(release, name, directory)
                if digest(fetched) != digest(local[name]):
                    raise ValueError("Conflicting archived asset: " + name)

        # A partially completed upload is safe to resume.
        for name in filenames:
            if name not in remote:
                run(
                    "gh", "release", "upload", release,
                    str(local[name]),
                    "--repo", os.environ["GH_REPO"]
                )

        # Require both assets and verify downloaded bytes.
        final = inventory(release)
        validate_history_inventory(
            final, args.package, filenames[0],
            allow_incomplete_current=False,
        )
        if not set(filenames).issubset(final):
            raise ValueError("Incomplete archived package/signature pair")

        for name in filenames:
            fetched = directory / name
            if fetched.exists():
                fetched.unlink()
            fetched = download(release, name, directory)
            if digest(fetched) != digest(local[name]):
                raise ValueError("Archive verification failed: " + name)

        verify_downloaded_pair(
            directory / filenames[0],
            directory / filenames[1],
            args.fingerprint,
        )

    print(json.dumps({
        "archive_required": True,
        "release": release,
        "assets": filenames,
        "published": True,
        "verified": True
    }, indent=2))


if __name__ == "__main__":
    main()
