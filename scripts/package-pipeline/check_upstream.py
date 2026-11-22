#!/usr/bin/env python3
"""Read-only discovery and candidate selection."""

import argparse
import json
from pathlib import Path

import discover_upstream
import resolve_candidate


def check(name, config, *, fetch=None, compare=None, ancestry=None):
    """Discover and evaluate one package without modifying state."""
    discovery = discover_upstream.discover(
        name,
        config,
        fetch=fetch if fetch is not None
        else discover_upstream.fetch_json,
    )

    kwargs = {}
    if compare is not None:
        kwargs["compare"] = compare
    if ancestry is not None:
        kwargs["ancestry"] = ancestry

    decision = resolve_candidate.decide(
        config["release_policy"],
        config["source_ref"],
        discovery["candidate"],
        **kwargs,
    )

    return {
        "package": name,
        "upstream": discovery["upstream"],
        "channel": discovery["channel"],
        **decision,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=discover_upstream.DEFAULT_MANIFEST,
    )
    parser.add_argument("--package", required=True)
    parser.add_argument(
        "--repo-path",
        type=Path,
        help="Fetched upstream Git repository for ancestry checks",
    )
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text())
    config = manifest["packages"][args.package]

    ancestry = None
    if config["release_policy"] == "development-commit":
        if args.repo_path is None:
            parser.error(
                "--repo-path required for development-commit"
            )
        ancestry = lambda old, new: resolve_candidate.descendant_of(
            old, new, args.repo_path
        )

    print(json.dumps(
        check(args.package, config, ancestry=ancestry),
        sort_keys=True,
    ))


if __name__ == "__main__":
    main()
