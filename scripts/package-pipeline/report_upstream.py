#!/usr/bin/env python3
"""Report eligible upstream updates. Never select, build or publish."""

import argparse
import json
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

import check_upstream
import discover_upstream
import resolve_candidate


def git_ancestry(upstream, selected, candidate):
    """Verify ancestry using full Git history without downloading blobs."""
    with tempfile.TemporaryDirectory(prefix="package-upstream-") as tmp:
        repo = Path(tmp) / "upstream"
        repo.mkdir()

        subprocess.run(
            ["git", "-C", str(repo), "init", "-q"],
            check=True,
        )
        subprocess.run(
            [
                "git", "-C", str(repo), "remote", "add",
                "origin", f"https://github.com/{upstream}.git",
            ],
            check=True,
        )
        subprocess.run(
            [
                "git", "-C", str(repo), "fetch", "--quiet",
                "--filter=blob:none", "--no-tags", "origin",
                selected, candidate,
            ],
            check=True,
        )
        return resolve_candidate.descendant_of(
            selected, candidate, repo
        )


def report(manifest, *, fetch=None, ancestry_check=git_ancestry):
    """Evaluate approved entries, leaving all manifest state unchanged."""
    fetcher = (
        discover_upstream.fetch_json
        if fetch is None else fetch
    )
    cached_fetch = lru_cache(maxsize=None)(fetcher)

    results = []

    for name, config in sorted(manifest["packages"].items()):
        if config["status"] != "approved":
            continue

        if config["auto_publish"] is not False:
            raise ValueError(
                f"{name}: automatic publication must remain disabled"
            )

        ancestry = None

        if config["release_policy"] == "development-commit":
            discovery = discover_upstream.discover(
                name, config, fetch=cached_fetch
            )
            candidate = discovery["candidate"]
            ancestry = lambda old, new, c=config: ancestry_check(
                c["upstream"], old, new
            )

            # An unchanged commit needs no Git history download.
            if candidate == config["source_ref"]:
                ancestry = None

        decision = check_upstream.check(
            name,
            config,
            fetch=cached_fetch,
            ancestry=ancestry,
        )
        results.append(decision)

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=discover_upstream.DEFAULT_MANIFEST,
    )
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text())
    results = report(manifest)

    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
