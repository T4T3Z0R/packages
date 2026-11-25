"""Regression coverage for the restricted Engrampa package lifecycle."""

import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "scripts/package-pipeline"

sys.path.insert(0, str(PIPELINE))

import candidate_selection_pr_writer as writer
import discover_upstream
import fixed_recipe_metadata as metadata
import fixed_recipe_selection as selection
import mate_source
import merged_selection_validation as merged
import package_release_contract as registry
import resolve_candidate
import verify_source_contract as contract


PACKAGE = "engrampa"
DIRECTORY = ROOT / "arch" / PACKAGE
RECIPE = DIRECTORY / "PKGBUILD"
PUBLISHER = ROOT / ".github/workflows/publish-engrampa.yml"
MANIFEST = ROOT / "arch/packages/manifest.json"

BOOTSTRAP = {
    "upstream": "mate-desktop/engrampa",
    "source_ref": "v1.28.5",
    "release_policy": "stable-mate-git-tag",
    "license": "GPL-2.0-or-later",
    "recipe": "arch/engrampa/PKGBUILD",
    "status": "approved",
    "auto_publish": False,
}

SOURCE_SHA256 = (
    "58e898331dd6145c7be43efbaafb8e2640"
    "9417d024683249a4a6e459605165ee"
)

PATCH_SHA256 = (
    "0b7c043a80a6e0feb776d1d5cf249a7e"
    "6397004cf5ba8b3308b0e823ec68e082"
)

REQUIRED_PATHS = (
    "usr/bin/engrampa",
    "usr/lib/engrampa/engrampa-server",
    "usr/lib/engrampa/engrampa/isoinfo.sh",
    "usr/lib/caja/extensions-2.0/libcaja-engrampa.so",
    "usr/share/caja/extensions/libcaja-engrampa.caja-extension",
    "usr/share/applications/engrampa.desktop",
    "usr/share/dbus-1/services/org.mate.Engrampa.service",
    "usr/share/glib-2.0/schemas/org.mate.engrampa.gschema.xml",
    "usr/share/metainfo/engrampa.appdata.xml",
)


def compare(old, new):
    a = tuple(map(int, old.split(".")))
    b = tuple(map(int, new.split(".")))
    return (a > b) - (a < b)


class EngrampaTests(unittest.TestCase):
    def setUp(self):
        self.source = RECIPE.read_text()
        self.manifest = json.loads(MANIFEST.read_text())
        self.config = self.manifest["packages"][PACKAGE]
        self.match = mate_source.verify_recipe_layout(self.source)
        self.digest = "a" * 128

    def next_candidate(self):
        major, minor, revision = map(
            int,
            mate_source.stable_version(
                self.config["source_ref"]
            ).split("."),
        )

        version = f"{major}.{minor}.{revision + 1}"

        return "v" + version, version

    def proposed_metadata(self):
        candidate, version = self.next_candidate()

        return {
            "package": PACKAGE,
            "candidate": candidate,
            "pkgver": version,
            "b2": self.digest,
        }

    def test_manifest_registration(self):
        self.assertEqual(
            self.config["upstream"],
            mate_source.UPSTREAM,
        )

        self.assertEqual(
            self.config["release_policy"],
            mate_source.POLICY,
        )

        self.assertEqual(
            self.config["recipe"],
            "arch/engrampa/PKGBUILD",
        )

        self.assertEqual(
            self.config["status"], "approved"
        )

        self.assertIs(
            self.config["auto_publish"], False
        )

    def test_initial_recipe_provenance(self):
        if self.config["source_ref"] == BOOTSTRAP["source_ref"]:
            self.assertEqual(
                hashlib.sha256(RECIPE.read_bytes()).hexdigest(),
                SOURCE_SHA256,
            )

            self.assertEqual(
                hashlib.sha256(
                    (DIRECTORY / mate_source.PATCH_NAME).read_bytes()
                ).hexdigest(),
                PATCH_SHA256,
            )

    def test_packaging_licenses(self):
        for filename in (
            "LICENSE.packaging",
            "LICENSES/0BSD.txt",
            "LICENSES/GPL-2.0-or-later.txt",
            "REUSE.toml",
            "README.packaging.md",
        ):
            with self.subTest(filename=filename):
                self.assertTrue(
                    (DIRECTORY / filename).read_text().strip()
                )

    def test_registry_alignment(self):
        self.assertIn(PACKAGE, selection.FIXED_PACKAGES)

        self.assertNotIn(
            PACKAGE,
            registry.TEMPLATE_PACKAGES,
        )

        self.assertEqual(
            registry.workflow_file(PACKAGE),
            "publish-engrampa.yml",
        )

        self.assertEqual(
            registry.VALIDATION_JOBS[PACKAGE],
            "Build and validate unsigned Engrampa",
        )

    def test_retention(self):
        retention = json.loads(
            (ROOT / "arch/packages/retention.json").read_text()
        )["previous_versions"]

        self.assertEqual(retention[PACKAGE], 2)
        self.assertEqual(retention[PACKAGE + "-debug"], 2)

    def test_stable_tags(self):
        for tag in (
            "v1.28.5",
            "v1.30.0",
            "v2.0.0",
        ):
            with self.subTest(tag=tag):
                self.assertEqual(
                    mate_source.stable_version(tag),
                    tag[1:],
                )

    def test_invalid_tags(self):
        for tag in (
            "v1.27.1",
            "v1.29.0",
            "v1.028.5",
            "v01.28.5",
            "v1.28.05",
            "v1.28.5-rc1",
            "v1.28.5.1",
            "1.28.5",
            "engrampa-1.28.5",
            "",
            None,
        ):
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    mate_source.stable_version(tag)

    def test_upstream_allowlist(self):
        for package, upstream in (
            ("mousepad", mate_source.UPSTREAM),
            (PACKAGE, "untrusted/engrampa"),
            (PACKAGE, mate_source.UPSTREAM + "/"),
        ):
            with self.subTest(package=package, upstream=upstream):
                with self.assertRaises(ValueError):
                    mate_source.validate_source(
                        package,
                        upstream,
                        "v1.28.5",
                    )

    def test_discovery(self):
        def fetch(url):
            self.assertEqual(
                url,
                "https://api.github.com/repos/"
                "mate-desktop/engrampa/git/matching-refs/tags/v",
            )

            return [
                {"ref": "refs/tags/" + tag}
                for tag in (
                    "v1.28.5",
                    "v1.29.0",
                    "v1.30.2",
                    "v1.30.10",
                    "v1.31.0",
                    "v9.99.0",
                    "v1.032.0",
                    "v2.0.0-rc1",
                )
            ]

        result = discover_upstream.discover(
            PACKAGE,
            BOOTSTRAP,
            fetch=fetch,
        )

        self.assertEqual(result["candidate"], "v1.30.10")
        self.assertEqual(result["channel"], mate_source.POLICY)

    def test_generic_policy_rejected(self):
        config = dict(
            self.config,
            release_policy="stable-git-tag",
        )

        with self.assertRaises(ValueError):
            discover_upstream.discover(
                PACKAGE,
                config,
                fetch=lambda url: self.fail(
                    "Unexpected upstream request"
                ),
            )

        with self.assertRaises(ValueError):
            contract.verify(PACKAGE, config, ROOT)

    def test_candidate_decisions(self):
        for candidate, status in (
            ("v1.30.0", "update"),
            ("v1.28.5", "unchanged"),
            ("v1.28.4", "blocked"),
        ):
            result = resolve_candidate.decide(
                mate_source.POLICY,
                "v1.28.5",
                candidate,
                compare=compare,
            )

            self.assertEqual(result["status"], status)

    def test_development_candidate_rejected(self):
        with self.assertRaises(ValueError):
            resolve_candidate.decide(
                mate_source.POLICY,
                "v1.28.5",
                "v1.29.0",
                compare=compare,
            )

    def test_current_source_contract(self):
        result = contract.verify(
            PACKAGE, self.config, ROOT
        )

        self.assertIs(result["verified"], True)

        self.assertEqual(
            result["pkgver"],
            mate_source.stable_version(
                self.config["source_ref"]
            ),
        )

    def test_source_layout_mutations(self):
        for source in (
            self.source.replace(
                "github.com/mate-desktop/mate-submodules.git",
                "github.com/unknown/mate-submodules.git",
            ),
            self.source.replace(
                "github.com/mate-desktop/engrampa.git",
                "github.com/unknown/engrampa.git",
            ),
            self.source.replace(
                self.match.group(1), "SKIP", 1
            ),
            self.source.replace(
                self.match.group(2), "SKIP", 1
            ),
            self.source + "\nsource=('unexpected')\n",
            self.source + "\nsha256sums=('SKIP')\n",
            self.source + "\nsource_x86_64=('unexpected')\n",
        ):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    mate_source.verify_recipe_layout(source)

    def test_patch_integrity(self):
        self.assertEqual(
            mate_source.verify_patch(
                self.source, DIRECTORY
            ),
            self.match.group(2),
        )

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / mate_source.PATCH_NAME

            path.write_bytes(b"modified patch")

            with self.assertRaises(ValueError):
                mate_source.verify_patch(
                    self.source, path.parent
                )

            path.unlink()

            with self.assertRaises(ValueError):
                mate_source.verify_patch(
                    self.source, path.parent
                )

            path.symlink_to(
                DIRECTORY / mate_source.PATCH_NAME
            )

            with self.assertRaises(ValueError):
                mate_source.verify_patch(
                    self.source, path.parent
                )

    def test_primary_checksum_replacement(self):
        updated = mate_source.replace_primary_checksum(
            self.source, self.digest
        )

        expected = self.source.replace(
            self.match.group(1),
            self.digest,
            1,
        )

        self.assertEqual(updated, expected)

        self.assertEqual(
            mate_source.verify_recipe_layout(updated).group(2),
            self.match.group(2),
        )

        with self.assertRaises(ValueError):
            mate_source.replace_primary_checksum(
                self.source, "SKIP"
            )

    def test_exact_candidate_recipe_changes(self):
        proposed = self.proposed_metadata()

        rendered = selection.render_recipe(
            PACKAGE,
            self.config,
            proposed["candidate"],
            self.source,
            proposed,
            compare=compare,
        )

        expected = self.source.replace(
            self.match.group(1),
            self.digest,
            1,
        )

        expected = re.sub(
            r"^pkgver=.*$",
            "pkgver=" + proposed["pkgver"],
            expected,
            count=1,
            flags=re.MULTILINE,
        )

        expected = re.sub(
            r"^pkgrel=.*$",
            "pkgrel=1",
            expected,
            count=1,
            flags=re.MULTILINE,
        )

        self.assertEqual(rendered, expected)

    def test_candidate_metadata_restrictions(self):
        proposed = self.proposed_metadata()

        for mutation in (
            {"package": "mousepad"},
            {"b2": "SKIP"},
            {"b2": "a" * 64},
            {"sha256": "a" * 64},
            {"pkgver": "0.0.0"},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    selection.render_recipe(
                        PACKAGE,
                        self.config,
                        proposed["candidate"],
                        self.source,
                        dict(proposed, **mutation),
                        compare=compare,
                    )

    def test_native_checksum_recipe(self):
        def fake_run(args, *, cwd=None):
            self.assertEqual(
                args,
                ["makepkg", "--geninteg", "--noconfirm"],
            )

            source = (cwd / "PKGBUILD").read_text()

            self.assertIn(
                'source=("git+https://github.com/'
                'mate-desktop/engrampa.git#tag=v$pkgver")',
                source,
            )

            self.assertIn("b2sums=", source)
            self.assertNotIn("prepare()", source)
            self.assertNotIn("build()", source)
            self.assertNotIn("mate-submodules", source)

            return "b2sums=('" + self.digest + "')"

        proposed = self.proposed_metadata()

        with patch.object(metadata.os, "geteuid", return_value=1000):
            with patch.object(metadata, "run", side_effect=fake_run):
                result = metadata.resolve(
                    PACKAGE,
                    proposed["candidate"],
                    self.config,
                )

        self.assertEqual(result, proposed)

    def test_native_checksum_refuses_root(self):
        with patch.object(metadata.os, "geteuid", return_value=0):
            with self.assertRaises(ValueError):
                metadata.engrampa_checksum("1.30.0")

    def test_invalid_native_checksum_output(self):
        for output in (
            "invalid",
            "b2sums=('SKIP')",
            "b2sums=('" + "a" * 64 + "')",
            (
                "b2sums=('" + self.digest + "')\n"
            ) * 2,
        ):
            with patch.object(metadata.os, "geteuid", return_value=1000):
                with patch.object(metadata, "run", return_value=output):
                    with self.assertRaises(ValueError):
                        metadata.engrampa_checksum("1.30.0")

    def test_complete_candidate_pr_render(self):
        proposed = self.proposed_metadata()
        candidate = proposed["candidate"]

        decision = {
            "status": "fixed_pr_ready",
            "pr_created": False,
            "validation_dispatched": False,
            "publication_authorized": False,
            "package": PACKAGE,
            "selected": self.config["source_ref"],
            "candidate": candidate,
            "issue_number": 42,
            "branch": "source-selection/issue-42-engrampa",
            "pr_marker": (
                "<!-- t4t3z0r:source-selection:v1 "
                f"issue=42 package=engrampa candidate={candidate} -->"
            ),
            "pr_title": f"Select engrampa candidate {candidate}",
        }

        changed, body, recipe = writer.render(
            MANIFEST.read_text(),
            decision,
            recipe_source=self.source,
            metadata=proposed,
            compare=compare,
        )

        expected = copy.deepcopy(self.manifest)

        expected["packages"][PACKAGE]["source_ref"] = candidate

        self.assertEqual(json.loads(changed), expected)
        self.assertIn(decision["pr_marker"], body)

        self.assertEqual(
            mate_source.verify_recipe_layout(recipe).group(1),
            self.digest,
        )

    def test_bootstrap_safety(self):
        import ast

        tree = ast.parse(Path(merged.__file__).read_text())

        names = [
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and any(
                isinstance(child, ast.Name)
                and child.id == "ENGRAMPA_BOOTSTRAP_BASE"
                for child in ast.walk(node)
            )
        ]

        self.assertEqual(len(names), 1)

        transition = getattr(merged, names[0])

        before = copy.deepcopy(self.manifest)

        before["packages"] = {
            name: before["packages"][name]
            for name in merged.ENGRAMPA_BOOTSTRAP_BASE
        }

        after = copy.deepcopy(before)
        after["packages"][PACKAGE] = copy.deepcopy(BOOTSTRAP)

        self.assertIsNone(transition(before, after))

        for mutation in (
            {"auto_publish": True},
            {"source_ref": "v1.30.0"},
            {"release_policy": "stable-git-tag"},
        ):
            changed = copy.deepcopy(after)

            changed["packages"][PACKAGE].update(mutation)

            with self.assertRaises(ValueError):
                transition(before, changed)

        changed = copy.deepcopy(after)
        changed["packages"]["mousepad"]["auto_publish"] = True

        with self.assertRaises(ValueError):
            transition(before, changed)

    def test_publisher_contract(self):
        workflow = PUBLISHER.read_text()

        for marker in (
            "name: Publish Engrampa",
            "Build and validate unsigned Engrampa",
            "Sign and publish approved Engrampa package(s)",
            "--package engrampa",
            "name: arch-repo-publish",
            "group: arch-repo-publish",
            "queue: max",
            "retention-days: 7",
            "default: false",
            "makepkg --noconfirm --cleanbuild --nobuild",
            "makepkg --noconfirm --noextract",
            "rev-parse HEAD:mate-submodules",
            'test "$actual_submodule" = "$expected_submodule"',
            "assemble-repository.sh",
            "publish-repository.sh",
            "engrampa-debug",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, workflow)

        for path in REQUIRED_PATHS:
            with self.subTest(path=path):
                self.assertIn(path, workflow)

        self.assertNotIn("mousepad", workflow.lower())

    def test_workflow_registration(self):
        directory = ROOT / ".github/workflows"

        expected = {
            "create-package-candidate-review.yml": (
                "- engrampa",
                "broot|engrampa|gameshell|",
            ),
            "review-package-candidate-approval.yml": (
                "mousepad|engrampa)",
                "broot|engrampa|gameshell|",
                "scripts/package-pipeline/mate_source.py",
            ),
            "package-validation-controller.yml": (
                "mousepad engrampa; do",
            ),
            "reconcile-package-candidates.yml": (
                "- Publish Engrampa",
            ),
            "test-package-pipeline.yml": (
                "feature/engrampa-package",
                "publish-engrampa.yml",
                "arch/engrampa/**",
                "test_engrampa_package.py",
                "engrampa_checksum(version)",
                "PASS: MATE native version comparison",
                "scripts/package-pipeline/mate_source.py",
            ),
        }

        for filename, markers in expected.items():
            source = (directory / filename).read_text()

            for marker in markers:
                with self.subTest(filename=filename, marker=marker):
                    self.assertIn(marker, source)



class SubmoduleVerificationTests(unittest.TestCase):
    """Execute the publisher's verification against real Git objects."""

    def git(self, directory, *args):
        return subprocess.check_output(
            [
                "git", "-C", str(directory),
                "-c", "user.name=Package Pipeline Test",
                "-c", "user.email=test@example.invalid",
                "-c", "commit.gpgsign=false",
                *args,
            ],
            text=True,
            stderr=subprocess.PIPE,
        ).strip()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.root = Path(temporary.name)

        upstream = self.root / "auxiliary"
        upstream.mkdir()

        self.git(upstream, "init", "-q")

        content = upstream / "fixture.txt"
        content.write_text("first revision\n")

        self.git(upstream, "add", "fixture.txt")
        self.git(upstream, "commit", "-qm", "First revision")

        self.pinned = self.git(upstream, "rev-parse", "HEAD")

        content.write_text("second revision\n")
        self.git(upstream, "commit", "-qam", "Second revision")

        self.other = self.git(upstream, "rev-parse", "HEAD")

        self.parent = self.root / "src" / "engrampa"
        self.parent.mkdir(parents=True)

        self.git(self.parent, "init", "-q")

        self.git(
            self.parent,
            "-c", "protocol.file.allow=always",
            "submodule", "add",
            str(upstream), "mate-submodules",
        )

        self.submodule = self.parent / "mate-submodules"

        self.git(
            self.submodule,
            "checkout", "--detach", self.pinned,
        )

        self.git(self.parent, "add", ".")
        self.git(
            self.parent,
            "commit", "-qm", "Pin auxiliary revision",
        )

        self.git(self.parent, "tag", "v1.28.5")

        # Execute the actual verification block from the publisher,
        # excluding makepkg itself.
        workflow = PUBLISHER.read_text()

        start_marker = '              parent="src/engrampa"\n'
        end_marker = '              makepkg --noconfirm --noextract\n'

        self.assertEqual(workflow.count(start_marker), 1)
        self.assertEqual(workflow.count(end_marker), 1)

        start = workflow.index(start_marker)
        end = workflow.index(end_marker, start)

        self.script = workflow[start:end]

    def verify_checkout(self):
        return subprocess.run(
            [
                "bash", "-euo", "pipefail",
                "-c", self.script,
                "_", str(self.root), "1.28.5",
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_correct_submodule_checkout(self):
        result = self.verify_checkout()

        self.assertEqual(
            result.returncode, 0,
            result.stdout + result.stderr,
        )

        self.assertIn(self.pinned, result.stdout)

    def test_wrong_submodule_revision(self):
        self.git(
            self.submodule,
            "checkout", "--detach", self.other,
        )

        self.assertNotEqual(
            self.verify_checkout().returncode, 0,
        )

    def test_dirty_submodule(self):
        (self.submodule / "fixture.txt").write_text(
            "unexpected modification\n"
        )

        self.assertNotEqual(
            self.verify_checkout().returncode, 0,
        )

    def test_untracked_submodule_content(self):
        (self.submodule / "unexpected.txt").write_text(
            "untracked content\n"
        )

        self.assertNotEqual(
            self.verify_checkout().returncode, 0,
        )

    def test_wrong_parent_revision(self):
        self.git(
            self.parent, "commit",
            "--allow-empty", "-qm", "Unexpected parent",
        )

        self.assertNotEqual(
            self.verify_checkout().returncode, 0,
        )

    def test_missing_submodule_checkout(self):
        import shutil

        shutil.rmtree(self.submodule)

        self.assertNotEqual(
            self.verify_checkout().returncode, 0,
        )



if __name__ == "__main__":
    unittest.main()
