#!/usr/bin/env python3
"""Render exactly one source-selection change; no GitHub writes."""

import argparse
import copy
import json
import re
from pathlib import Path

import xfce_source
import mate_source

from resolve_candidate import (
    COMMIT_POLICIES, COMMIT_SHA,
    STABLE_POLICIES, STABLE_TAG,
)
from select_package_validation import TEMPLATE_PACKAGES
from fixed_recipe_selection import FIXED_PACKAGES, render_recipe
from resolve_candidate import compare_versions


def require(condition, message):
    if not condition:
        raise ValueError(message)


def render(
    manifest_text, decision, *,
    recipe_source=None, metadata=None,
    compare=compare_versions,
):
    require(isinstance(decision, dict), "Invalid approval plan")
    require(decision.get("status") in (
        "template_pr_ready", "fixed_pr_ready"
    ), "Selection is not eligible for automatic PR preparation")
    require(decision.get("pr_created") is False, "PR already created")
    require(decision.get("validation_dispatched") is False,
            "Unexpected validation dispatch")
    require(decision.get("publication_authorized") is False,
            "Unexpected publication authorization")

    package = decision.get("package")
    selected = decision.get("selected")
    candidate = decision.get("candidate")
    number = decision.get("issue_number")

    generated = package in TEMPLATE_PACKAGES
    fixed = package in FIXED_PACKAGES

    require(generated or fixed, "Unsupported recipe")
    require(
        decision["status"] == (
            "template_pr_ready" if generated
            else "fixed_pr_ready"
        ),
        "Recipe selection status mismatch",
    )

    if generated:
        require(
            recipe_source is None and metadata is None,
            "Unexpected generated-recipe metadata",
        )
    else:
        require(
            isinstance(recipe_source, str)
            and isinstance(metadata, dict),
            "Fixed recipe requires source and metadata",
        )
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
    recipe_name = "PKGBUILD.in" if generated else "PKGBUILD"
    require(
        config.get("recipe") == f"arch/{package}/{recipe_name}",
        "Unexpected recipe path",
    )
    require(config.get("source_ref") == selected,
            "Manifest selected source changed")

    policy = config.get("release_policy")
    if policy == xfce_source.POLICY:
        xfce_source.validate_source(
            package, config["upstream"], selected
        )
        xfce_source.stable_version(candidate, package)
        pattern = xfce_source.tag_pattern(package)
    elif policy == mate_source.POLICY:
        mate_source.validate_source(
            package, config["upstream"], selected
        )
        mate_source.stable_version(candidate)
        pattern = mate_source.TAG
    elif policy in STABLE_POLICIES:
        pattern = STABLE_TAG
    elif policy in COMMIT_POLICIES:
        pattern = COMMIT_SHA
    else:
        raise ValueError("Unsupported release policy")

    require(pattern.fullmatch(candidate) is not None,
            "Candidate does not match source policy")

    updated_recipe = None

    if fixed:
        updated_recipe = render_recipe(
            package,
            config,
            candidate,
            recipe_source,
            metadata,
            compare=compare,
        )

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
        (
            "- Only the manifest source selection changes."
            if generated else
            "- Coordinated manifest and fixed recipe update."
        ),
        "- Requires human PR review and merge.",
        "- No signing or publication is authorized.",
        "- Unsigned validation is a separate subsequent step.",
        "",
    ))

    if fixed:
        return text, body, updated_recipe

    return text, body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("plan", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--body-file", type=Path, required=True)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--recipe", type=Path)
    args = parser.parse_args()

    decision = json.loads(args.plan.read_text())

    if decision.get("status") == "fixed_pr_ready":
        package = decision.get("package")

        require(package in FIXED_PACKAGES, "Unsupported recipe")
        require(
            args.metadata is not None and args.recipe is not None,
            "Fixed selection requires metadata and recipe arguments",
        )

        expected = Path(
            f"arch/{package}/PKGBUILD"
        ).resolve()

        require(
            args.recipe.resolve() == expected
            and not args.recipe.is_symlink(),
            "Unexpected fixed recipe location",
        )

        updated, body, recipe = render(
            args.manifest.read_text(),
            decision,
            recipe_source=args.recipe.read_text(),
            metadata=json.loads(args.metadata.read_text()),
        )

        args.recipe.write_text(recipe)

    else:
        require(
            args.metadata is None and args.recipe is None,
            "Unexpected fixed-recipe arguments",
        )

        updated, body = render(
            args.manifest.read_text(), decision
        )

    args.manifest.write_text(updated)
    args.body_file.write_text(body)

    print("PASS: Guarded source selection prepared")


if __name__ == "__main__":
    main()
