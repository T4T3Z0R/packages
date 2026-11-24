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


def history_snapshot(release):
    """Read stable release and asset identities without mutation."""

    repo = os.environ["GH_REPO"]

    if not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo
    ):
        raise ValueError("Invalid repository identity")

    if not re.fullmatch(r"arch-history-[a-z][a-z0-9-]*", release):
        raise ValueError("Invalid historical release tag")

    document = json.loads(run(
        "gh", "api", f"repos/{repo}/releases/tags/{release}"
    ))

    release_id = document.get("id")

    if (
        type(release_id) is not int
        or release_id <= 0
        or document.get("tag_name") != release
        or document.get("draft") is not False
    ):
        raise ValueError("Invalid historical release identity")

    pages = json.loads(run(
        "gh", "api", "--paginate", "--slurp",
        f"repos/{repo}/releases/{release_id}/assets?per_page=100"
    ))

    if not isinstance(pages, list) or not pages:
        raise ValueError("Invalid historical asset inventory")

    assets = {}
    ids = set()

    for page in pages:
        if not isinstance(page, list):
            raise ValueError("Invalid historical asset page")

        for asset in page:
            name = asset.get("name")
            asset_id = asset.get("id")
            size = asset.get("size")
            checksum = asset.get("digest")
            updated = asset.get("updated_at")

            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9._+-]+", name)
                or name in (".", "..")
                or type(asset_id) is not int
                or asset_id <= 0
                or type(size) is not int
                or size <= 0
                or not isinstance(checksum, str)
                or not re.fullmatch(
                    r"sha256:[a-f0-9]{64}", checksum
                )
                or asset.get("state") != "uploaded"
                or not isinstance(updated, str)
                or not updated
            ):
                raise ValueError("Invalid historical asset metadata")

            if name in assets or asset_id in ids:
                raise ValueError("Duplicate historical asset identity")

            ids.add(asset_id)

            assets[name] = {
                "id": asset_id,
                "size": size,
                "sha256": checksum.removeprefix("sha256:"),
                "state": asset["state"],
                "updated_at": updated,
            }

    return {
        "repository": repo,
        "release": release,
        "release_id": release_id,
        "assets": assets,
    }


def verify_snapshot_asset(path, record):
    """Require downloaded bytes to match remote asset metadata."""

    if path.stat().st_size != record["size"]:
        raise ValueError(
            "Historical asset size mismatch: " + path.name
        )

    checksum = digest(path)

    if checksum != record["sha256"]:
        raise ValueError(
            "Historical asset digest mismatch: " + path.name
        )

    return checksum


def require_unchanged_snapshot(expected):
    """Reject changed release or asset identities."""

    actual = history_snapshot(expected["release"])

    if actual != expected:
        raise ValueError("Historical asset snapshot changed")

    return actual


def collect_history_metadata(package, fingerprint, keyfile):
    """Collect verified history metadata without remote mutations."""

    if not re.fullmatch(r"[a-z][a-z0-9-]*", package):
        raise ValueError("Invalid package identity")

    if not re.fullmatch(r"[A-Fa-f0-9]{40}", fingerprint):
        raise ValueError("Invalid signing fingerprint")

    fingerprint = fingerprint.upper()

    records = run(
        "gpg", "--batch", "--with-colons",
        "--show-keys", str(keyfile)
    )

    fingerprints = [
        line.split(":")[9].upper()
        for line in records.splitlines()
        if line.startswith("fpr:")
    ]

    if fingerprint not in fingerprints:
        raise ValueError("Signing fingerprint not in repository key")

    release = "arch-history-" + package
    snapshot = history_snapshot(release)
    names = set(snapshot["assets"])

    validate_history_inventory(
        names, package, None,
        allow_incomplete_current=False,
    )

    pattern = re.compile(
        re.escape(package)
        + r"-([A-Za-z0-9._+]+)-([0-9.]+)"
        + r"-([A-Za-z0-9_]+)[.]pkg[.]tar[.]zst"
    )

    packages = sorted(
        name for name in names
        if not name.endswith(".sig")
    )

    if not all(pattern.fullmatch(name) for name in packages):
        raise ValueError("Invalid historical filename")

    versions = {}
    hashes = {}

    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)

        for name in packages:
            payload = download(release, name, directory)
            signature = download(
                release, name + ".sig", directory
            )

            hashes[name] = verify_snapshot_asset(
                payload, snapshot["assets"][name]
            )
            hashes[name + ".sig"] = verify_snapshot_asset(
                signature, snapshot["assets"][name + ".sig"]
            )

            verify_downloaded_pair(
                payload, signature, fingerprint
            )

            metadata = run(
                "bsdtar", "-xOf", str(payload), ".PKGINFO"
            )

            fields = {}

            for field in ("pkgname", "pkgver", "arch"):
                values = [
                    line.partition(" = ")[2]
                    for line in metadata.splitlines()
                    if line.startswith(field + " = ")
                ]

                if len(values) != 1:
                    raise ValueError(
                        "Invalid historical metadata field: "
                        + field
                    )

                fields[field] = values[0]

            version, rel, arch = (
                pattern.fullmatch(name).groups()
            )
            full = fields["pkgver"]

            if (
                fields["pkgname"] != package
                or fields["arch"] != arch
                or not re.fullmatch(
                    r"(?:[0-9]+:)?[A-Za-z0-9._+]+-[0-9.]+",
                    full,
                )
                or full.split(":")[-1] != f"{version}-{rel}"
            ):
                raise ValueError(
                    "Historical metadata disagrees with filename: "
                    + name
                )

            versions[name] = full

            payload.unlink()
            signature.unlink()

        require_unchanged_snapshot(snapshot)

    return {
        "package": package,
        "release": release,
        "names": sorted(names),
        "versions": versions,
        "sha256": hashes,
        "snapshot": snapshot,
    }


def plan_verified_history(package, fingerprint, protected):
    """Generate a pruning proposal from verified signed history."""
    import runpy

    retain = current_retention_count(package)

    metadata = collect_history_metadata(
        package,
        fingerprint,
        ROOT / "arch/keys/t4t3z0r-package-signing.asc",
    )

    planner = runpy.run_path(str(
        ROOT / "scripts/package-pipeline/plan-history-pruning.py"
    ))

    plan = planner["plan_pruning"](
        package,
        metadata["names"],
        metadata["versions"],
        protected,
        retain,
    )

    plan["verified_metadata"] = metadata
    return plan


def prepare_pruning_transaction(plan):
    """Bind a verified pruning proposal to an exact deletion sequence."""
    import copy

    if plan.get("dry_run") is not True:
        raise ValueError("Expected verified dry-run proposal")

    package = plan["package"]
    release = "arch-history-" + package
    metadata = plan["verified_metadata"]
    snapshot = metadata["snapshot"]
    assets = snapshot["assets"]

    if (
        plan["history_release"] != release
        or metadata["package"] != package
        or metadata["release"] != release
        or snapshot["release"] != release
        or set(metadata["names"]) != set(assets)
        or metadata["sha256"] != {
            name: record["sha256"]
            for name, record in assets.items()
        }
    ):
        raise ValueError("Inconsistent verified pruning proposal")

    validate_history_inventory(
        set(assets), package, None,
        allow_incomplete_current=False,
    )

    def flatten(pairs):
        names = []

        for pair in pairs:
            name = pair["package"]
            signature = pair["signature"]

            if (
                name.endswith(".sig")
                or signature != name + ".sig"
            ):
                raise ValueError("Invalid authorized package pair")

            names.extend((name, signature))

        return names

    keep = flatten(plan["keep"])
    prune = flatten(plan["prune"])
    combined = keep + prune

    if (
        len(combined) != len(set(combined))
        or set(combined) != set(assets)
    ):
        raise ValueError("Invalid retention partition")

    protected = plan["protected"]

    if (
        protected not in keep
        or protected + ".sig" not in keep
    ):
        raise ValueError("Protected pair is not retained")

    retain = plan["previous_versions_to_keep"]

    if (
        type(retain) is not int
        or retain < 1
        or len(keep) != 2 * min(retain, len(assets) // 2)
    ):
        raise ValueError("Invalid retained pair count")

    return {
        "schema_version": 1,
        "package": package,
        "protected": protected,
        "snapshot": copy.deepcopy(snapshot),
        "versions": copy.deepcopy(metadata["versions"]),
        "retain": retain,
        "keep": keep,
        "delete": [
            {"name": name, "id": assets[name]["id"]}
            for name in prune
        ],
    }


def validate_transaction_decision(journal):
    """Reconstruct the original retention decision."""
    import runpy

    planner = runpy.run_path(str(
        ROOT / "scripts/package-pipeline/plan-history-pruning.py"
    ))

    original = journal["snapshot"]

    expected = planner["plan_pruning"](
        journal["package"],
        sorted(original["assets"]),
        journal["versions"],
        journal["protected"],
        journal["retain"],
    )

    def flatten(pairs):
        return [
            name
            for pair in pairs
            for name in (pair["package"], pair["signature"])
        ]

    if (
        flatten(expected["keep"]) != journal["keep"]
        or flatten(expected["prune"]) != [
            target["name"] for target in journal["delete"]
        ]
    ):
        raise ValueError(
            "Transaction retention decision mismatch"
        )


def pruning_transaction_state(journal, actual):
    """Accept only an exact prefix of authorized deletions."""

    if journal.get("schema_version") != 1:
        raise ValueError("Unsupported pruning transaction")

    original = journal["snapshot"]
    original_assets = original["assets"]

    for field in ("repository", "release", "release_id"):
        if actual[field] != original[field]:
            raise ValueError("Transaction release identity changed")

    protected = journal["protected"]
    keep = journal["keep"]
    targets = journal["delete"]
    names = [target["name"] for target in targets]

    if (
        len(keep + names) != len(set(keep + names))
        or set(keep + names) != set(original_assets)
        or protected not in keep
        or protected + ".sig" not in keep
    ):
        raise ValueError("Invalid transaction partition")

    package = journal["package"]

    if (
        not re.fullmatch(r"[a-z][a-z0-9-]*", package)
        or original["release"] != "arch-history-" + package
    ):
        raise ValueError("Invalid transaction package identity")

    validate_history_inventory(
        set(original_assets), package, None,
        allow_incomplete_current=False,
    )

    retain = journal["retain"]

    if (
        type(retain) is not int
        or retain < 1
        or len(keep) != 2 * min(
            retain, len(original_assets) // 2
        )
    ):
        raise ValueError("Invalid transaction retained pair count")

    for group in (keep, names):
        if len(group) % 2:
            raise ValueError("Incomplete transaction pair")

        for index in range(0, len(group), 2):
            name, signature = group[index:index + 2]

            if (
                name.endswith(".sig")
                or signature != name + ".sig"
            ):
                raise ValueError("Invalid transaction pair ordering")

    ids = [
        record["id"]
        for record in original_assets.values()
    ]

    if (
        any(type(value) is not int or value <= 0 for value in ids)
        or len(ids) != len(set(ids))
    ):
        raise ValueError("Invalid original asset identities")

    for target in targets:
        if (
            type(target["id"]) is not int
            or target["id"] != original_assets[target["name"]]["id"]
        ):
            raise ValueError("Invalid transaction asset identity")

    validate_transaction_decision(journal)

    remaining = actual["assets"]

    for name, record in remaining.items():
        if original_assets.get(name) != record:
            raise ValueError("Unexpected transaction asset change")

    missing = set(original_assets) - set(remaining)

    if missing.intersection(keep):
        raise ValueError("Retained transaction asset missing")

    completed = len(missing)

    if missing != set(names[:completed]):
        raise ValueError("Unauthorized deletion sequence")

    if completed == len(targets):
        state = "complete"
    elif completed:
        state = "interrupted"
    else:
        state = "prepared"

    return {
        "state": state,
        "completed": completed,
        "remaining": targets[completed:],
    }


JOURNAL_NAME = "pruning-transaction.json"


def encode_pruning_journal(journal):
    """Produce deterministic journal bytes."""
    payload = json.dumps(
        journal,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")

    return payload + bytes([10])


def decode_pruning_journal(payload):
    """Reject malformed or noncanonical journal content."""

    def unique_fields(pairs):
        result = {}

        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate journal field")
            result[key] = value

        return result

    journal = json.loads(
        payload.decode("ascii"),
        object_pairs_hook=unique_fields,
    )

    if not isinstance(journal, dict):
        raise ValueError("Invalid pruning journal")

    if encode_pruning_journal(journal) != payload:
        raise ValueError("Noncanonical pruning journal")

    required = {
        "schema_version",
        "package",
        "protected",
        "snapshot",
        "versions",
        "retain",
        "keep",
        "delete",
    }

    if set(journal) != required:
        raise ValueError("Invalid pruning journal fields")

    if (
        type(journal["schema_version"]) is not int
        or journal["schema_version"] != 1
    ):
        raise ValueError("Unsupported pruning journal")

    return journal


def load_pruning_journal(release):
    """Load and validate an existing durable transaction."""
    import copy

    snapshot = history_snapshot(release)

    if JOURNAL_NAME not in snapshot["assets"]:
        return None

    record = snapshot["assets"][JOURNAL_NAME]

    with tempfile.TemporaryDirectory() as temp:
        path = download(
            release, JOURNAL_NAME, Path(temp)
        )

        verify_snapshot_asset(path, record)
        journal = decode_pruning_journal(path.read_bytes())

    require_unchanged_snapshot(snapshot)

    package_snapshot = copy.deepcopy(snapshot)
    del package_snapshot["assets"][JOURNAL_NAME]

    state = pruning_transaction_state(
        journal, package_snapshot
    )

    return {
        "journal": journal,
        "journal_asset": record,
        "state": state,
    }


def persist_pruning_journal(journal):
    """Persist authorization before permitting deletion."""

    snapshot = journal["snapshot"]
    release = snapshot["release"]

    if not journal["delete"]:
        raise ValueError("Cannot persist empty pruning transaction")

    require_unchanged_snapshot(snapshot)

    if JOURNAL_NAME in snapshot["assets"]:
        raise ValueError("Existing pruning journal")

    state = pruning_transaction_state(journal, snapshot)

    if state["state"] != "prepared":
        raise ValueError("Transaction is not prepared")

    payload = encode_pruning_journal(journal)

    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / JOURNAL_NAME
        path.write_bytes(payload)

        run(
            "gh", "release", "upload", release,
            str(path),
            "--repo", snapshot["repository"],
        )

    persisted = load_pruning_journal(release)

    if persisted is None:
        raise ValueError("Persisted pruning journal missing")

    if (
        encode_pruning_journal(persisted["journal"]) != payload
        or persisted["state"]["state"] != "prepared"
    ):
        raise ValueError("Persisted pruning journal mismatch")

    return persisted


def current_retention_count(package):
    policy = json.loads(
        (ROOT / "arch/packages/retention.json").read_text()
    )

    if policy["schema_version"] != 1:
        raise ValueError("Unsupported retention policy")

    retain = policy["previous_versions"].get(
        package, policy["default_previous_versions"]
    )

    if type(retain) is not int or retain < 1:
        raise ValueError("Pruning requires positive retention policy")

    return retain


def execute_pruning_transaction(release, expected=None):
    """Resume a persisted transaction without expanding its scope."""

    persisted = load_pruning_journal(release)

    if expected is not None and persisted != expected:
        raise ValueError("Authorized pruning journal changed")

    if persisted is None:
        return {
            "state": "no_transaction",
            "deleted": 0,
        }

    journal = persisted["journal"]
    journal_record = persisted["journal_asset"]
    payload = encode_pruning_journal(journal)
    repo = journal["snapshot"]["repository"]

    def validate_policy():
        if current_retention_count(
            journal["package"]
        ) != journal["retain"]:
            raise ValueError("Transaction retention policy changed")

    def reload_transaction():
        current = load_pruning_journal(release)

        if current is None:
            raise ValueError("Active pruning journal disappeared")

        if (
            current["journal_asset"] != journal_record
            or encode_pruning_journal(
                current["journal"]
            ) != payload
        ):
            raise ValueError("Active pruning journal changed")

        return current

    validate_policy()

    initial_completed = persisted["state"]["completed"]
    state = persisted["state"]

    while state["remaining"]:
        validate_policy()

        current = reload_transaction()

        if current["state"] != state:
            raise ValueError("Unexpected transaction progress")

        target = state["remaining"][0]

        run(
            "gh", "api", "--method", "DELETE",
            f"repos/{repo}/releases/assets/{target['id']}",
        )

        current = reload_transaction()
        next_state = current["state"]

        if (
            next_state["completed"] != state["completed"] + 1
            or next_state["remaining"] != state["remaining"][1:]
        ):
            raise ValueError("Unexpected deletion progress")

        state = next_state

    validate_policy()

    final = reload_transaction()

    if final["state"]["state"] != "complete":
        raise ValueError("Pruning transaction is incomplete")

    run(
        "gh", "api", "--method", "DELETE",
        f"repos/{repo}/releases/assets/{journal_record['id']}",
    )

    snapshot = history_snapshot(release)
    verified = pruning_transaction_state(journal, snapshot)

    if verified["state"] != "complete":
        raise ValueError("Final pruning verification failed")

    return {
        "state": "complete",
        "deleted": verified["completed"] - initial_completed,
        "total_pruned_assets": verified["completed"],
    }


def prune_verified_history(package, fingerprint, protected):
    """Recover an existing transaction or authorize one new transaction."""

    if not re.fullmatch(r"[a-z][a-z0-9-]*", package):
        raise ValueError("Invalid package identity")

    if not re.fullmatch(r"[A-Fa-f0-9]{40}", fingerprint):
        raise ValueError("Invalid signing fingerprint")

    release = "arch-history-" + package

    existing = load_pruning_journal(release)

    if existing is not None:
        result = execute_pruning_transaction(
            release, expected=existing
        )

        if result["state"] != "complete":
            raise ValueError("Existing transaction not completed")

        return {
            **result,
            "recovered": True,
        }

    plan = plan_verified_history(
        package, fingerprint, protected
    )

    journal = prepare_pruning_transaction(plan)

    if current_retention_count(package) != journal["retain"]:
        raise ValueError("Transaction retention policy changed")

    state = pruning_transaction_state(
        journal, journal["snapshot"]
    )

    if not journal["delete"]:
        if state["state"] != "complete":
            raise ValueError("Invalid empty pruning transaction")

        require_unchanged_snapshot(journal["snapshot"])

        return {
            "state": "within_limit",
            "deleted": 0,
            "recovered": False,
        }

    persisted = persist_pruning_journal(journal)

    if (
        persisted["journal"] != journal
        or persisted["state"]["state"] != "prepared"
    ):
        raise ValueError("Transaction persistence not confirmed")

    result = execute_pruning_transaction(
        release, expected=persisted
    )

    if result["state"] != "complete":
        raise ValueError("New transaction not completed")

    return {
        **result,
        "recovered": False,
    }


def recover_before_archive(release):
    """Resolve pending pruning before adding historical assets."""

    remote = inventory(release)

    if JOURNAL_NAME not in remote:
        return remote

    existing = load_pruning_journal(release)

    if existing is None:
        raise ValueError("Pending pruning journal disappeared")

    result = execute_pruning_transaction(
        release, expected=existing
    )

    if result["state"] != "complete":
        raise ValueError("Pending pruning recovery incomplete")

    remote = inventory(release)

    if JOURNAL_NAME in remote:
        raise ValueError("Pending pruning journal remains")

    return remote


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--staging", type=Path,
                        default=Path("archive-output"))
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--publish", action="store_true")
    modes.add_argument("--plan-pruning", action="store_true")
    modes.add_argument("--apply-pruning", action="store_true")
    parser.add_argument("--protected")
    args = parser.parse_args()

    if args.plan_pruning:
        if not args.protected:
            parser.error("--plan-pruning requires --protected")

        print(json.dumps(plan_verified_history(
            args.package,
            args.fingerprint,
            args.protected,
        ), indent=2))
        return

    if args.apply_pruning:
        if not args.protected:
            parser.error("--apply-pruning requires --protected")

        if not os.environ.get("GH_TOKEN") or not os.environ.get("GH_REPO"):
            raise ValueError("GH_TOKEN and GH_REPO are required")

        print(json.dumps(prune_verified_history(
            args.package,
            args.fingerprint,
            args.protected,
        ), indent=2))
        return

    if args.protected:
        parser.error(
            "--protected requires --plan-pruning or --apply-pruning"
        )

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

    remote = recover_before_archive(release)
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
