#!/usr/bin/env python3
"""Render exactly one source-selection change; no GitHub writes."""

import argparse
import copy
import json
import re
from pathlib import Path

from resolve_candidate import (
    COMMIT_POLICIES, COMMIT_SHA,
    STABLE_POLICIES, STABLE_TAG,
)
from select_package_validation import TEMPLATE_PACKAGES


def require(condition, message):
    if not condition:
        raise ValueError(message)


def render(manifest_text, decision):
    require(isinstance(decision, dict), "Invalid approval plan")
    require(decision.get("status") == "template_pr_ready",
            "Selection is not eligible for automatic PR preparation")
    require(decision.get("pr_created") is False, "PR already created")
    require(decision.get("validation_dispatched") is False,
            "Unexpected validation dispatch")
    require(decision.get("publication_authorized") is False,
            "Unexpected publication authorization")

    package = decision.get("package")
    selected = decision.get("selected")
    candidate = decision.get("candidate")
    number = decision.get("issue_number")

    require(package in TEMPLATE_PACKAGES, "Unsupported recipe")
    require(type(number) is int and number > 0, "Invalid issue number")
    require(isinstance(selected, str), "Invalid selected ref")
    require(isinstance(candidate, str), "Invalid candidate ref")
    require(selected != candidate, "Candidate already selected")

    branch = f"source-selection/issue-{number}-{package}"
    marker = (
        f"<!-- t4t3z0r:source-selection:v1 issue={number}"
        f" package={package} candidate={candidate} -->"
    )
    title = f"Select {package} candidate {candidate}"

    require(decision.get("branch") == branch, "Branch mismatch")
    require(decision.get("pr_marker") == marker, "PR marker mismatch")
    require(decision.get("pr_title") == title, "PR title mismatch")

    manifest = json.loads(manifest_text)
    require(isinstance(manifest, dict), "Invalid manifest")
    require(isinstance(manifest.get("packages"), dict),
            "Invalid package mapping")

    # Refuse to reformat the whole manifest as collateral damage.
    require(
        manifest_text == json.dumps(manifest, indent=2) + "\n",
        "Unexpected manifest formatting",
    )

    config = manifest["packages"].get(package)
    require(isinstance(config, dict), "Missing package configuration")
    require(config.get("status") == "approved", "Unapproved package")
    require(config.get("auto_publish") is False,
            "Automatic publication forbidden")
    require(config.get("recipe") == f"arch/{package}/PKGBUILD.in",
            "Unexpected recipe path")
    require(config.get("source_ref") == selected,
            "Manifest selected source changed")

    policy = config.get("release_policy")
    if policy in STABLE_POLICIES:
        pattern = STABLE_TAG
    elif policy in COMMIT_POLICIES:
        pattern = COMMIT_SHA
    else:
        raise ValueError("Unsupported release policy")

    require(pattern.fullmatch(candidate) is not None,
            "Candidate does not match source policy")

    changed = copy.deepcopy(manifest)
    changed["packages"][package]["source_ref"] = candidate

    text = json.dumps(changed, indent=2) + "\n"

    body = "\n".join((
        "## Source-selection proposal",
        "",
        marker,
        "",
        f"Review issue: #{number}",
        "",
        f"- Package: `{package}`",
        f"- Previously selected: `{selected}`",
        f"- Proposed source: `{candidate}`",
        "",
        "## Safety",
        "",
        "- Only the manifest source selection changes.",
        "- Requires human PR review and merge.",
        "- No signing or publication is authorized.",
        "- Unsigned validation is a separate subsequent step.",
        "",
    ))

    return text, body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("plan", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--body-file", type=Path, required=True)
    args = parser.parse_args()

    decision = json.loads(args.plan.read_text())
    updated, body = render(args.manifest.read_text(), decision)

    args.manifest.write_text(updated)
    args.body_file.write_text(body)

    print("PASS: Only manifest source selection prepared")


if __name__ == "__main__":
    main()
