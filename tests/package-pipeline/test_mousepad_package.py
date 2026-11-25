"""Mousepad package registration and lifecycle regression tests."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from fixed_recipe_selection import FIXED_PACKAGES
from merged_selection_validation import (
    MOUSEPAD_BOOTSTRAP_BASE,
    MOUSEPAD_BOOTSTRAP_CONFIG,
    changed_source,
)
from package_release_contract import CONTRACTS
from verify_source_contract import verify


class MousepadPackageTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )

        self.config = self.manifest["packages"]["mousepad"]

    def bootstrap(self):
        before = copy.deepcopy(self.manifest)

        before["packages"] = {
            name: config
            for name, config in before["packages"].items()
            if name in MOUSEPAD_BOOTSTRAP_BASE
        }

        after = copy.deepcopy(before)

        after["packages"]["mousepad"] = dict(
            MOUSEPAD_BOOTSTRAP_CONFIG
        )

        return before, after

    def test_current_source_contract(self):
        result = verify("mousepad", self.config, ROOT)

        self.assertTrue(result["verified"])
        self.assertEqual(
            result["source_ref"], self.config["source_ref"]
        )

    def test_fixed_recipe_registration(self):
        self.assertIn("mousepad", FIXED_PACKAGES)
        self.assertEqual(self.config["status"], "approved")
        self.assertIs(self.config["auto_publish"], False)

    def test_bootstrap_does_not_dispatch(self):
        before, after = self.bootstrap()

        self.assertEqual(len(before["packages"]), 11)
        self.assertEqual(len(after["packages"]), 12)

        self.assertIsNone(changed_source(before, after))

    def test_bootstrap_rejects_modified_registration(self):
        for field, value in (
            ("upstream", "other/mousepad"),
            ("source_ref", "mousepad-0.7.1-rc1"),
            ("release_policy", "stable-tag"),
            ("recipe", "arch/mousepad/PKGBUILD.in"),
            ("license", "MIT"),
            ("status", "candidate"),
            ("auto_publish", True),
        ):
            with self.subTest(field=field):
                before, after = self.bootstrap()

                after["packages"]["mousepad"][field] = value

                with self.assertRaises(ValueError):
                    changed_source(before, after)

    def test_bootstrap_rejects_unrelated_changes(self):
        for operation in ("change", "remove", "add"):
            with self.subTest(operation=operation):
                before, after = self.bootstrap()

                if operation == "change":
                    after["packages"]["broot"][
                        "source_ref"
                    ] = "v99.9.9"
                elif operation == "remove":
                    after["packages"].pop("broot")
                else:
                    after["packages"]["unexpected"] = dict(
                        MOUSEPAD_BOOTSTRAP_CONFIG
                    )

                with self.assertRaises(ValueError):
                    changed_source(before, after)

    def test_future_source_change_recognized(self):
        before = copy.deepcopy(self.manifest)
        after = copy.deepcopy(before)

        candidate = "mousepad-99.99.99"

        after["packages"]["mousepad"]["source_ref"] = candidate

        result = changed_source(before, after)

        self.assertEqual(result[0], "mousepad")
        self.assertEqual(result[2], candidate)

    def test_publisher_registration(self):
        spec = CONTRACTS["mousepad"]

        self.assertEqual(spec.workflow, "publish-mousepad.yml")
        self.assertEqual(spec.recipe_style, "fixed")

        workflow = (
            ROOT / ".github/workflows" / spec.workflow
        ).read_text()

        for marker in (
            "name: Build and validate unsigned Mousepad",
            "makepkg --noconfirm --cleanbuild",
            "name: arch-repo-publish",
            "inputs.publish == true",
            "mousepad-debug",
            "usr/bin/mousepad",
            "usr/lib/libmousepad.so.0",
            "usr/lib/mousepad/plugins/libmousepad-plugin-gspell.so",
            "usr/share/applications/org.xfce.mousepad.desktop",
        ):
            self.assertIn(marker, workflow)

        for forbidden in (
            "--nocheck",
            "--skipinteg",
            "--skipchecksums",
            "--skippgpcheck",
            "gh release upload",
            "gh release delete-asset",
        ):
            self.assertNotIn(forbidden, workflow)

    def test_reconciliation_registration(self):
        workflow = (
            ROOT / ".github/workflows/"
            "reconcile-package-candidates.yml"
        ).read_text()

        self.assertIn("      - Publish Mousepad\n", workflow)

    def test_retention_policy(self):
        policy = json.loads(
            (ROOT / "arch/packages/retention.json").read_text()
        )

        for package in ("mousepad", "mousepad-debug"):
            self.assertEqual(
                policy["previous_versions"][package], 2
            )

    def test_native_ci_registration(self):
        workflow = (
            ROOT / ".github/workflows/"
            "test-package-pipeline.yml"
        ).read_text()

        for marker in (
            "test_xfce_source.py",
            "test_mousepad_package.py",
            "mousepad_checksum(version)",
            "PASS: XFCE native version comparison",
            "scripts/package-pipeline/xfce_source.py",
        ):
            self.assertIn(marker, workflow)


class MousepadSourceTests(unittest.TestCase):
    def setUp(self):
        import xfce_source

        self.xfce = xfce_source
        self.package = "mousepad"
        self.upstream = xfce_source.UPSTREAMS[self.package]

        self.manifest_path = ROOT / "arch/packages/manifest.json"
        self.manifest = json.loads(self.manifest_path.read_text())
        self.config = self.manifest["packages"][self.package]

        self.source = (ROOT / self.config["recipe"]).read_text()
        self.version = self.xfce.validate_source(
            self.package,
            self.upstream,
            self.config["source_ref"],
        )

        parts = list(map(int, self.version.split(".")))
        parts[-1] += 1
        self.next_version = ".".join(map(str, parts))
        self.candidate = "mousepad-" + self.next_version

    @staticmethod
    def compare(old, new):
        a = tuple(map(int, old.split(".")))
        b = tuple(map(int, new.split(".")))
        return (a > b) - (a < b)

    @staticmethod
    def refs(*tags):
        return "\n".join(
            "a" * 40 + "\trefs/tags/" + tag
            for tag in tags
        )

    def metadata(self):
        return {
            "package": self.package,
            "candidate": self.candidate,
            "pkgver": self.next_version,
            "sha256": "b" * 64,
        }

    def test_numeric_release_policy(self):
        for version in ("0.7.0", "0.8.90", "1.1.99"):
            with self.subTest(version=version):
                self.assertEqual(
                    self.xfce.validate_source(
                        self.package,
                        self.upstream,
                        "mousepad-" + version,
                    ),
                    version,
                )

    def test_invalid_source_tags(self):
        for tag in (
            "mousepad-0.7.1-rc1",
            "mousepad-0.8.0-alpha",
            "mousepad-0.8.0-beta",
            "mousepad-00.7.0",
            "mousepad-0.07.0",
            "mousepad-0.7.00",
            "mousepad-0.7",
            "mousepad-0.7.0.1",
            "mousepad-0.7.0\n",
            "thunar-4.20.10",
            "xfce-4.6.0",
            "v0.7.0",
        ):
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    self.xfce.validate_source(
                        self.package, self.upstream, tag
                    )

    def test_upstream_isolation(self):
        for upstream in (
            self.xfce.UPSTREAMS["thunar"],
            self.upstream + "/",
            "https://example.com/mousepad.git",
        ):
            with self.subTest(upstream=upstream):
                with self.assertRaises(ValueError):
                    self.xfce.validate_source(
                        self.package,
                        upstream,
                        "mousepad-0.7.0",
                    )

    def test_numeric_discovery_ordering(self):
        output = self.refs(
            "mousepad-0.7.9",
            "mousepad-0.7.10",
            "mousepad-0.8.0-rc1",
            "thunar-4.22.0",
        )

        self.assertEqual(
            self.xfce.latest_stable_tag(output, self.package),
            "mousepad-0.7.10",
        )

    def test_discovery_rejects_invalid_reference_listings(self):
        for output in (
            "",
            "invalid",
            self.refs("thunar-4.20.10"),
            self.refs("mousepad-0.7.1-rc1"),
            self.refs("mousepad-0.7.0", "mousepad-0.7.0"),
        ):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    self.xfce.latest_stable_tag(
                        output, self.package
                    )

    def test_candidate_decisions(self):
        from resolve_candidate import decide

        for candidate, expected in (
            ("mousepad-0.7.1", "update"),
            ("mousepad-0.8.90", "update"),
            ("mousepad-0.7.0", "unchanged"),
            ("mousepad-0.6.5", "blocked"),
        ):
            with self.subTest(candidate=candidate):
                result = decide(
                    self.xfce.POLICY,
                    "mousepad-0.7.0",
                    candidate,
                    compare=self.compare,
                )

                self.assertEqual(result["status"], expected)

    def test_cross_package_candidate_rejection(self):
        from resolve_candidate import decide

        for selected, candidate in (
            ("mousepad-0.7.0", "thunar-4.22.0"),
            ("thunar-4.20.10", "mousepad-0.7.1"),
            ("thunar-4.20.10", "thunar-4.21.7"),
        ):
            with self.subTest(
                selected=selected, candidate=candidate
            ):
                with self.assertRaises(ValueError):
                    decide(
                        self.xfce.POLICY,
                        selected,
                        candidate,
                        compare=self.compare,
                    )

    def test_native_checksum_recipe(self):
        from unittest.mock import patch
        import fixed_recipe_metadata as metadata

        def native(args, *, cwd=None):
            recipe = (Path(cwd) / "PKGBUILD").read_text()

            self.assertEqual(
                args,
                ["makepkg", "--geninteg", "--noconfirm"],
            )

            self.assertIn("pkgname=mousepad\n", recipe)
            self.assertIn(
                f"pkgver={self.next_version}\n", recipe
            )

            self.assertIn(
                'source=("git+https://gitlab.xfce.org/'
                'apps/mousepad.git#tag=$pkgname-$pkgver")',
                recipe,
            )

            for forbidden in (
                "build()", "package()", "prepare()", "SKIP"
            ):
                self.assertNotIn(forbidden, recipe)

            return f"sha256sums=('{self.metadata()['sha256']}')"

        with patch.object(
            metadata.os, "geteuid", return_value=1000
        ), patch.object(
            metadata, "run", side_effect=native
        ):
            result = metadata.resolve(
                self.package,
                self.candidate,
                self.config,
            )

        self.assertEqual(result, self.metadata())

    def test_native_checksum_refuses_root(self):
        from unittest.mock import patch
        import fixed_recipe_metadata as metadata

        with patch.object(
            metadata.os, "geteuid", return_value=0
        ), patch.object(metadata, "run") as native:
            with self.assertRaises(ValueError):
                metadata.mousepad_checksum(self.next_version)

            native.assert_not_called()

    def test_invalid_metadata_never_resolves_checksum(self):
        from unittest.mock import patch
        import fixed_recipe_metadata as metadata

        with patch.object(
            metadata, "mousepad_checksum"
        ) as native:
            for candidate in (
                self.config["source_ref"],
                "thunar-4.22.0",
                "mousepad-99.0.0-rc1",
            ):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(ValueError):
                        metadata.resolve(
                            self.package,
                            candidate,
                            self.config,
                        )

            native.assert_not_called()

    def test_source_contract_rejects_recipe_mutations(self):
        import re
        import tempfile

        checksum = re.search(
            r"^sha256sums=\('([0-9a-f]{64})'\)$",
            self.source,
            re.MULTILINE,
        ).group(1)

        mutations = (
            self.source.replace(
                "gitlab.xfce.org", "example.com"
            ),
            self.source.replace(
                "#tag=$pkgname-$pkgver", "#branch=master"
            ),
            self.source.replace(checksum, "SKIP"),
            self.source.replace(
                "pkgname=mousepad", "pkgname=thunar"
            ),
            self.source + "\nsha256sums=('SKIP')\n",
            self.source + '\nsource=("unexpected")\n',
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recipe = root / self.config["recipe"]
            recipe.parent.mkdir(parents=True)

            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    self.assertNotEqual(mutation, self.source)
                    recipe.write_text(mutation)

                    with self.assertRaises(ValueError):
                        verify(
                            self.package, self.config, root
                        )

    def test_exact_recipe_update(self):
        import re
        from fixed_recipe_selection import render_recipe

        rendered = render_recipe(
            self.package,
            self.config,
            self.candidate,
            self.source,
            self.metadata(),
            compare=self.compare,
        )

        expected = self.source.replace(
            f"pkgver={self.version}\n",
            f"pkgver={self.next_version}\n",
            1,
        )

        expected = re.sub(
            r"^pkgrel=[1-9][0-9]*$",
            "pkgrel=1",
            expected,
            count=1,
            flags=re.MULTILINE,
        )

        expected = re.sub(
            r"^sha256sums=\('[0-9a-f]{64}'\)$",
            f"sha256sums=('{self.metadata()['sha256']}')",
            expected,
            count=1,
            flags=re.MULTILINE,
        )

        self.assertEqual(rendered, expected)

    def test_recipe_render_rejects_cross_package_source(self):
        from fixed_recipe_selection import render_recipe

        proposed = self.metadata()
        proposed["candidate"] = "thunar-4.22.0"
        proposed["pkgver"] = "4.22.0"

        with self.assertRaises(ValueError):
            render_recipe(
                self.package,
                self.config,
                proposed["candidate"],
                self.source,
                proposed,
                compare=self.compare,
            )

    def test_complete_candidate_pr_render(self):
        from candidate_selection_pr_writer import render
        from fixed_recipe_selection import render_recipe

        decision = {
            "status": "fixed_pr_ready",
            "package": self.package,
            "selected": self.config["source_ref"],
            "candidate": self.candidate,
            "issue_number": 42,
            "branch": "source-selection/issue-42-mousepad",
            "pr_marker": (
                "<!-- t4t3z0r:source-selection:v1 issue=42"
                f" package=mousepad candidate={self.candidate} -->"
            ),
            "pr_title": f"Select mousepad candidate {self.candidate}",
            "pr_created": False,
            "validation_dispatched": False,
            "publication_authorized": False,
        }

        manifest, body, recipe = render(
            self.manifest_path.read_text(),
            decision,
            recipe_source=self.source,
            metadata=self.metadata(),
            compare=self.compare,
        )

        expected = copy.deepcopy(self.manifest)

        expected["packages"]["mousepad"]["source_ref"] = (
            self.candidate
        )

        self.assertEqual(
            manifest, json.dumps(expected, indent=2) + "\n"
        )

        self.assertEqual(
            recipe,
            render_recipe(
                self.package,
                self.config,
                self.candidate,
                self.source,
                self.metadata(),
                compare=self.compare,
            ),
        )

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


if __name__ == "__main__":
    unittest.main()
