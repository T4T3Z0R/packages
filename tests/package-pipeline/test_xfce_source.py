"""Regression coverage for stable XFCE source handling."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

import discover_upstream
import fixed_recipe_metadata as metadata
import fixed_recipe_selection as selection
import resolve_candidate
import verify_source_contract
import xfce_source
from candidate_selection_pr_writer import render


CONFIG = {
    "upstream": "https://gitlab.xfce.org/xfce/thunar.git",
    "source_ref": "thunar-4.20.10",
    "release_policy": "stable-xfce-git-tag",
    "license": "GPL-2.0-or-later AND LGPL-2.1-only",
    "recipe": "arch/thunar/PKGBUILD",
    "status": "approved",
    "auto_publish": False,
}

CHECKSUM = (
    "535214e04df1a56b94233e7b6f231f30"
    "f39eafe7a67bb235b0c3b4931edd10b6"
)


def refs(*tags):
    return "\n".join(
        "a" * 40 + "\trefs/tags/" + tag
        for tag in tags
    )


def compare(old, new):
    a = tuple(map(int, old.split(".")))
    b = tuple(map(int, new.split(".")))
    return (a > b) - (a < b)


def candidate_metadata():
    return {
        "package": "thunar",
        "candidate": "thunar-4.20.11",
        "pkgver": "4.20.11",
        "sha256": "b" * 64,
    }


class XfceSourceTests(unittest.TestCase):
    def setUp(self):
        self.config = copy.deepcopy(CONFIG)
        self.source = (ROOT / CONFIG["recipe"]).read_text()

    def test_stable_tags(self):
        for tag, version in (
            ("thunar-4.20.10", "4.20.10"),
            ("thunar-4.22.0", "4.22.0"),
            ("thunar-5.0.0", "5.0.0"),
        ):
            with self.subTest(tag=tag):
                self.assertEqual(
                    xfce_source.stable_version(tag),
                    version,
                )

    def test_invalid_tags(self):
        for tag in (
            "thunar-4.21.7",
            "thunar-4.19.2",
            "thunar-4.20.11-rc1",
            "thunar-04.20.10",
            "thunar-4.020.10",
            "thunar-4.20.010",
            "thunar-4x20x10",
            "thunar-4.20.10\n",
            "thunar-4.20.10.1",
            "v4.20.10",
            "4.20.10",
            "xfce-4.20.10",
            None,
        ):
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    xfce_source.stable_version(tag)

    def test_upstream_allowlist(self):
        for package, upstream in (
            ("other", CONFIG["upstream"]),
            ("thunar", "xfce/thunar"),
            ("thunar", "https://example.com/thunar.git"),
            ("thunar", CONFIG["upstream"] + "/"),
        ):
            with self.subTest(upstream=upstream):
                with self.assertRaises(ValueError):
                    xfce_source.validate_source(
                        package, upstream, CONFIG["source_ref"]
                    )

    def test_numeric_tag_sorting(self):
        self.assertEqual(
            xfce_source.latest_stable_tag(refs(
                "thunar-4.20.9",
                "thunar-4.20.10",
                "thunar-4.21.7",
                "xfce-4.22.0",
            )),
            "thunar-4.20.10",
        )

    def test_invalid_reference_listing(self):
        for output in (
            "",
            "invalid",
            refs("thunar-4.21.7"),
            refs("thunar-4.20.10", "thunar-4.20.10"),
            "invalid\trefs/tags/thunar-4.20.10",
        ):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    xfce_source.latest_stable_tag(output)

    def test_discovery_isolation(self):
        def forbidden_fetch(url):
            self.fail(f"Unexpected GitHub API request: {url}")

        with patch.object(
            xfce_source.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=refs(
                    "thunar-4.20.10",
                    "thunar-4.21.7",
                ),
                stderr="",
            ),
        ) as native:
            result = discover_upstream.discover(
                "thunar", self.config, fetch=forbidden_fetch
            )

        self.assertEqual(
            result["candidate"], "thunar-4.20.10"
        )

        env = native.call_args.kwargs["env"]

        self.assertEqual(set(env), {
            "PATH",
            "LANG",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_TERMINAL_PROMPT",
        })

        self.assertIn(
            "credential.helper=", native.call_args.args[0]
        )

        self.assertEqual(
            env["GIT_CONFIG_GLOBAL"], "/dev/null"
        )

    def test_candidate_decisions(self):
        for candidate, status in (
            ("thunar-4.20.11", "update"),
            ("thunar-4.22.0", "update"),
            ("thunar-4.20.9", "blocked"),
            ("thunar-4.20.10", "unchanged"),
        ):
            with self.subTest(candidate=candidate):
                result = resolve_candidate.decide(
                    xfce_source.POLICY,
                    CONFIG["source_ref"],
                    candidate,
                    compare=compare,
                )
                self.assertEqual(result["status"], status)

    def test_development_candidate_rejected(self):
        with self.assertRaises(ValueError):
            resolve_candidate.decide(
                xfce_source.POLICY,
                CONFIG["source_ref"],
                "thunar-4.21.7",
                compare=compare,
            )

    def test_native_checksum_recipe(self):
        def fake_run(args, *, cwd=None):
            source = (Path(cwd) / "PKGBUILD").read_text()

            self.assertEqual(args, [
                "makepkg", "--geninteg", "--noconfirm",
            ])

            self.assertIn("pkgver=4.20.10\n", source)

            self.assertIn(
                'source=("git+https://gitlab.xfce.org/'
                'xfce/thunar.git#tag=$pkgname-$pkgver")',
                source,
            )

            self.assertNotIn("prepare()", source)
            self.assertNotIn("build()", source)
            self.assertNotIn("package()", source)
            self.assertNotIn("SKIP", source)

            return f"sha256sums=('{CHECKSUM}')"

        with patch.object(
            metadata.os, "geteuid", return_value=1000
        ), patch.object(metadata, "run", side_effect=fake_run):
            self.assertEqual(
                metadata.thunar_checksum("4.20.10"),
                CHECKSUM,
            )

    def test_native_checksum_refuses_root(self):
        with patch.object(
            metadata.os, "geteuid", return_value=0
        ), patch.object(metadata, "run") as native:
            with self.assertRaises(ValueError):
                metadata.thunar_checksum("4.20.10")

        native.assert_not_called()

    def test_metadata_resolution(self):
        with patch.object(
            metadata,
            "thunar_checksum",
            return_value="b" * 64,
        ) as native:
            result = metadata.resolve(
                "thunar", "thunar-4.20.11", self.config
            )

        self.assertEqual(result, candidate_metadata())
        native.assert_called_once_with("4.20.11")

    def test_invalid_metadata_source_rejected(self):
        with patch.object(
            metadata, "thunar_checksum"
        ) as native:
            for candidate in (
                "thunar-4.21.7",
                "v4.20.11",
                "4.20.11",
                CONFIG["source_ref"],
            ):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(ValueError):
                        metadata.resolve(
                            "thunar", candidate, self.config
                        )

            self.config["upstream"] = "xfce/thunar"

            with self.assertRaises(ValueError):
                metadata.resolve(
                    "thunar", "thunar-4.20.11", self.config
                )

        native.assert_not_called()

    def test_render_exact_recipe_changes(self):
        updated = selection.render_recipe(
            "thunar",
            self.config,
            "thunar-4.20.11",
            self.source,
            candidate_metadata(),
            compare=compare,
        )

        expected = self.source.replace(
            "pkgver=4.20.10", "pkgver=4.20.11", 1
        ).replace(CHECKSUM, "b" * 64, 1)

        self.assertEqual(updated, expected)

    def test_render_rejects_development_release(self):
        proposed = candidate_metadata()
        proposed["candidate"] = "thunar-4.21.7"
        proposed["pkgver"] = "4.21.7"

        with self.assertRaises(ValueError):
            selection.render_recipe(
                "thunar",
                self.config,
                proposed["candidate"],
                self.source,
                proposed,
                compare=compare,
            )

    def test_original_source_contract(self):
        result = verify_source_contract.verify(
            "thunar", self.config, ROOT
        )

        self.assertTrue(result["verified"])
        self.assertEqual(result["pkgver"], "4.20.10")
        self.assertEqual(result["pkgrel"], 1)

    def test_source_contract_rejects_mutations(self):
        variants = (
            self.source.replace(
                "gitlab.xfce.org", "github.com"
            ),
            self.source.replace(
                "#tag=$pkgname-$pkgver", "#branch=master"
            ),
            self.source.replace(
                CHECKSUM, "SKIP"
            ),
            self.source.replace(
                "pkgname=thunar", "pkgname=other"
            ),
            self.source + "\nsha256sums=('SKIP')\n",
            self.source + '\nsource=("unexpected")\n',
        )

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recipe = root / CONFIG["recipe"]
            recipe.parent.mkdir(parents=True)

            for source in variants:
                with self.subTest(source=source):
                    recipe.write_text(source)

                    with self.assertRaises(ValueError):
                        verify_source_contract.verify(
                            "thunar", self.config, root
                        )

    def test_full_candidate_pr_render(self):
        manifest = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )

        manifest["packages"]["thunar"] = self.config

        original = json.dumps(manifest, indent=2) + "\n"

        candidate = "thunar-4.20.11"

        decision = {
            "status": "fixed_pr_ready",
            "package": "thunar",
            "selected": CONFIG["source_ref"],
            "candidate": candidate,
            "issue_number": 42,
            "branch": "source-selection/issue-42-thunar",
            "pr_marker": (
                "<!-- t4t3z0r:source-selection:v1 issue=42"
                f" package=thunar candidate={candidate} -->"
            ),
            "pr_title": f"Select thunar candidate {candidate}",
            "pr_created": False,
            "validation_dispatched": False,
            "publication_authorized": False,
        }

        result = render(
            original,
            decision,
            recipe_source=self.source,
            metadata=candidate_metadata(),
            compare=compare,
        )

        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)

        updated_manifest, body, updated_recipe = result

        expected_manifest = copy.deepcopy(manifest)
        expected_manifest["packages"]["thunar"]["source_ref"] = (
            candidate
        )

        self.assertEqual(
            updated_manifest,
            json.dumps(expected_manifest, indent=2) + "\n",
        )

        expected_recipe = self.source.replace(
            "pkgver=4.20.10", "pkgver=4.20.11", 1
        ).replace(CHECKSUM, "b" * 64, 1)

        self.assertEqual(updated_recipe, expected_recipe)

        self.assertIn(decision["pr_marker"], body)
        self.assertIn("Review issue: #42", body)
        self.assertIn(
            "Requires human PR review and merge.", body
        )
        self.assertIn(
            "No signing or publication is authorized.", body
        )
        self.assertIn(
            "Unsigned validation is a separate subsequent step.",
            body,
        )
