import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
class WorkflowParityTests(unittest.TestCase):
    def test_publishing_dependencies(self):
        names = (
            "publish-gameshell.yml",
            "publish-noctalia-custom.yml",
            "publish-noctalia-greeter.yml",
            "publish-wezterm.yml",
            "publish-ghostty.yml",
            "publish-keepassxc.yml",
            "publish-moonlight-qt.yml",
            "publish-yazi.yml",
            "publish-syncthing.yml",
        )

        for name in names:
            with self.subTest(workflow=name):
                source = (
                    ROOT / ".github/workflows" / name
                ).read_text()

                block = source.split(
                    "      - name: Install publishing dependencies", 1
                )[1].split("\n      - name:", 1)[0]

                self.assertIn("diffutils", block)

    def test_ghostty_shared_pipeline(self):
        source = (
            ROOT / ".github/workflows/publish-ghostty.yml"
        ).read_text()

        required = (
            "PACKAGE_NAME: ghostty",
            "name: Verify pinned recipe and compiler",
            "name: Build split packages as unprivileged user",
            "ghostty-shell-integration",
            "ghostty-terminfo",
            "ghostty-nautilus",
            "name: Download exact validated candidate",
            "name: Verify validated candidate",
            "name: Sign approved packages",
            "name: Send Pushover approval notification",
            "name: arch-repo-publish",
            "ADDITIONAL_PACKAGE_FILES",
            "scripts/package-pipeline/assemble-repository.sh",
            "scripts/package-pipeline/publish-repository.sh",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        self.assertNotIn("gh release upload", source)
        self.assertNotIn("gh release delete-asset", source)


    def test_gameshell_release_lookup_fails_closed(self):
        source = (
            ROOT / ".github/workflows/publish-gameshell.yml"
        ).read_text()

        start = '          package_exists=false\n'
        end = '          {\n            echo "source_ref=$SOURCE_REF"\n'

        self.assertEqual(source.count(start), 1)
        self.assertEqual(source.count(end), 1)

        body = start + source.split(start, 1)[1].split(end, 1)[0]

        script = (
            "set -euo pipefail\n"
            "package_file=gameshell-2.0-1-any.pkg.tar.zst\n"
            + body
            + '\nprintf "%s:%s\\n" "$package_exists" "$update"\n'
        )

        with tempfile.TemporaryDirectory() as directory:
            stub = Path(directory) / "gh"
            stub.write_text(
                "#!/bin/sh\n"
                "case \"$TEST_GH_MODE\" in\n"
                "  found) echo gameshell-2.0-1-any.pkg.tar.zst;;\n"
                "  missing) echo unrelated-1.0-1-any.pkg.tar.zst;;\n"
                "  error) echo 'API unavailable' >&2; exit 17;;\n"
                "  *) exit 99;;\n"
                "esac\n"
            )
            stub.chmod(0o755)

            cases = (
                ("pull_request", "", "error", 0, "false:true\n"),
                ("workflow_dispatch", "false", "error", 0, "false:true\n"),
                ("workflow_dispatch", "true", "error", 17, ""),
                ("workflow_dispatch", "true", "found", 0, "true:false\n"),
                ("workflow_dispatch", "true", "missing", 0, "false:true\n"),
            )

            for event, intent, mode, status, output in cases:
                with self.subTest(event=event, intent=intent, mode=mode):
                    env = os.environ.copy()
                    env.update({
                        "PATH": directory + os.pathsep + env.get("PATH", ""),
                        "TEST_GH_MODE": mode,
                        "RELEASE_TAG": "arch-repo",
                        "GITHUB_REPOSITORY": "T4T3Z0R/packages",
                        "GITHUB_EVENT_NAME": event,
                        "REQUESTED_PUBLISH": intent,
                    })

                    result = subprocess.run(
                        ["bash", "-c", script],
                        env=env,
                        capture_output=True,
                        text=True,
                    )

                    self.assertEqual(
                        result.returncode, status, result.stderr
                    )
                    self.assertEqual(result.stdout, output)

    def test_gameshell_shared_pipeline(self):
        source = (
            ROOT / ".github/workflows/publish-gameshell.yml"
        ).read_text()

        required = (
            "name: Resolve upstream candidate",
            "name: Validate unsigned candidate",
            "name: Download exact validated candidate",
            "name: Verify validated candidate",
            "name: Sign approved package",
            "name: Send Pushover approval notification",
            "name: arch-repo-publish",
            "PACKAGE_NAME: gameshell",
            "scripts/package-pipeline/assemble-repository.sh",
            "scripts/package-pipeline/publish-repository.sh",
            "github.event_name == 'workflow_dispatch'",
        )

        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

        self.assertNotIn("gh release upload", source)
        self.assertNotIn("gh release delete-asset", source)

    def test_custom_shared_pipeline(self):
        source = (
            ROOT / ".github/workflows/publish-noctalia-custom.yml"
        ).read_text()

        required = (
            "name: Download exact validated candidate",
            "name: Verify validated candidate",
            "name: Sign approved package",
            "name: Send Pushover approval notification",
            "name: arch-repo-publish",
            "ARCH_REPO_SIGNING_PASSPHRASE",
            "PACKAGE_NAME: noctalia-custom",
            "scripts/package-pipeline/assemble-repository.sh",
            "scripts/package-pipeline/publish-repository.sh",
        )

        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

        self.assertNotIn("gh release upload", source)
        self.assertNotIn("gh release delete-asset", source)

    def test_greeter_shared_pipeline(self):
        source = (
            ROOT / ".github/workflows/publish-noctalia-greeter.yml"
        ).read_text()

        required = (
            "name: Download exact validated candidate",
            "name: Verify validated candidate",
            "name: Sign approved package",
            "name: Send Pushover approval notification",
            "name: arch-repo-publish",
            "ARCH_REPO_SIGNING_PASSPHRASE",
            "PACKAGE_NAME: noctalia-greeter-t4t3z0r",
            "scripts/package-pipeline/assemble-repository.sh",
            "scripts/package-pipeline/publish-repository.sh",
        )

        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

        self.assertNotIn("gh release upload", source)
        self.assertNotIn("gh release delete-asset", source)
        self.assertNotIn("default: v1.2.1", source)


    def test_moonlight_shared_pipeline(self):
        source = (
            ROOT / ".github/workflows/publish-moonlight-qt.yml"
        ).read_text()

        required = (
            "PACKAGE_NAME: moonlight-qt",
            "name: Build and validate unsigned Moonlight Qt",
            "makepkg --noconfirm --cleanbuild",
            "moonlight-qt-debug",
            "name: Download exact validated candidate",
            "name: Verify validated candidate",
            "name: Sign approved packages",
            "name: Send Pushover approval notification",
            "name: arch-repo-publish",
            "name: Refuse existing version collisions",
            "scripts/package-pipeline/assemble-repository.sh",
            "scripts/package-pipeline/publish-repository.sh",
        )

        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

        for forbidden in (
            "--nocheck", "--skipinteg", "--skippgpcheck",
            "gh release upload", "gh release delete-asset",
        ):
            self.assertNotIn(forbidden, source)

    def test_keepassxc_shared_pipeline(self):
        source = (
            ROOT / ".github/workflows/publish-keepassxc.yml"
        ).read_text()

        required = (
            "PACKAGE_NAME: keepassxc",
            "name: Build and validate unsigned KeePassXC",
            "makepkg --noconfirm --cleanbuild",
            "name: Download exact validated candidate",
            "name: Verify validated candidate",
            "name: Sign approved packages",
            "name: Send Pushover approval notification",
            "name: arch-repo-publish",
            "name: Refuse existing version collisions",
            "scripts/package-pipeline/assemble-repository.sh",
            "scripts/package-pipeline/publish-repository.sh",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

        self.assertNotIn("makepkg --noconfirm --cleanbuild --nocheck", source)
        self.assertNotIn("gh release upload", source)
        self.assertNotIn("gh release delete-asset", source)



    def test_syncthing_shared_pipeline(self):
        source = (
            ROOT / ".github/workflows/publish-syncthing.yml"
        ).read_text()

        required = (
            "PACKAGE_NAME: syncthing",
            "syncthing-discosrv",
            "syncthing-relaysrv",
            "makepkg --noconfirm --cleanbuild",
            "name: Download exact validated candidate",
            "name: Verify validated candidate",
            "name: Sign approved packages",
            "name: Send Pushover approval notification",
            "name: arch-repo-publish",
            "name: Refuse existing version collisions",
            "ADDITIONAL_PACKAGE_FILES",
            "scripts/package-pipeline/assemble-repository.sh",
            "scripts/package-pipeline/publish-repository.sh",
        )

        for value in required:
            with self.subTest(marker=value):
                self.assertIn(value, source)

        self.assertNotIn("--nocheck", source)
        self.assertNotIn("gh release upload", source)
        self.assertNotIn("gh release delete-asset", source)




    def test_validation_only_legacy_publishers(self):
        names = (
            "noctalia-custom",
            "noctalia-greeter",
            "gameshell",
        )

        for name in names:
            with self.subTest(package=name):
                source = (
                    ROOT / ".github/workflows"
                    / f"publish-{name}.yml"
                ).read_text()

                dispatch = source.split("permissions:", 1)[0]
                self.assertIn("      publish:", dispatch)
                self.assertIn("        type: boolean", dispatch)
                self.assertIn("        default: false", dispatch)

                lines = source.splitlines()
                approval_start = lines.index("  approval-ready:")
                publish_start = lines.index("  publish:")

                approval = lines[approval_start:publish_start]
                publishing = lines[publish_start:]

                if name == "gameshell":
                    for job in (approval, publishing):
                        self.assertTrue(any(
                            "inputs.publish == true" in line
                            for line in job
                        ))
                        self.assertTrue(any(
                            "github.event_name == 'workflow_dispatch'" in line
                            for line in job
                        ))
                        self.assertFalse(any(
                            "github.event_name == 'schedule'" in line
                            for line in job
                        ))
                else:
                    self.assertIn(
                        "    if: inputs.publish == true",
                        approval,
                    )
                    self.assertIn(
                        "    if: inputs.publish == true",
                        publishing,
                    )

                    self.assertTrue(any(
                        "name: arch-repo-publish" in line
                        for line in publishing
                    ))

    def test_only_approved_housekeeping_workflows_are_scheduled(self):
        workflows = ROOT / ".github/workflows"
        self.assertFalse((
            workflows / "check-noctalia-greeter.yml"
        ).exists())
        scheduled = sorted(
            p.name for p in workflows.glob("*.yml")
            if "\n  schedule:\n" in p.read_text()
        )
        self.assertEqual(scheduled, [
            "check-package-upstream.yml",
            "reconcile-package-candidates.yml",
        ])

        reconciliation = (
            workflows / "reconcile-package-candidates.yml"
        ).read_text()

        self.assertIn("workflow_run:", reconciliation)
        self.assertIn("types: [completed]", reconciliation)
        self.assertIn("workflow_dispatch:", reconciliation)
        self.assertIn("issues: write", reconciliation)
        self.assertIn(
            "close_published_candidates.py", reconciliation
        )
        self.assertIn(
            "group: package-candidate-issue-writes",
            reconciliation,
        )
        self.assertIn(
            "persist-credentials: false", reconciliation
        )

        for forbidden in (
            "contents: write",
            "actions: write",
            "pull-requests: write",
            "environment:",
            "gh workflow run",
            "gh release upload",
            "gh release delete-asset",
            "ARCH_REPO_SIGNING",
            "publish-repository.sh",
            "assemble-repository.sh",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, reconciliation)
        discovery = (
            workflows / "check-package-upstream.yml"
        ).read_text()
        self.assertIn("report_upstream.py", discovery)
        self.assertIn("write-reviews:", discovery)
        for path in workflows.glob("*.yml"):
            with self.subTest(workflow=path.name):
                self.assertNotIn("-f publish=true", path.read_text())


    def test_noctalia_source_ref_shell_safety(self):
        source = (
            ROOT / ".github/workflows/publish-noctalia-custom.yml"
        ).read_text()

        for name in ("Candidate summary", "Publication summary"):
            with self.subTest(step=name):
                marker = f"      - name: {name}" + chr(10)
                self.assertEqual(source.count(marker), 1)

                block = source.split(marker, 1)[1].split(
                    chr(10) + "      - name:", 1
                )[0]

                self.assertIn(
                    "SOURCE_REF: ${{ inputs.source_ref }}", block
                )
                self.assertIn("        run: |", block)

                shell = block.split("        run: |", 1)[1]

                self.assertIn('echo "- Requested source:', shell)
                self.assertEqual(shell.count("${SOURCE_REF}"), 1)
                self.assertNotIn("${{ inputs.source_ref }}", shell)

if __name__ == "__main__":
    unittest.main()
