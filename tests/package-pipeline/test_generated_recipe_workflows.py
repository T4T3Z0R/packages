"""Exercise generated-recipe publisher shell steps in isolation."""

import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

DIGEST = "a" * 64

PACKAGES = {
    "noctalia-custom": (
        "publish-noctalia-custom.yml",
        "Generate package source",
        "build/noctalia-custom/PKGBUILD",
    ),
    "noctalia-greeter-t4t3z0r": (
        "publish-noctalia-greeter.yml",
        "Create package source",
        "build/noctalia-greeter/PKGBUILD",
    ),
    "gameshell": (
        "publish-gameshell.yml",
        "Generate package sources",
        "build/gameshell/PKGBUILD",
    ),
}


def workflow_step(workflow, name):
    """Extract the literal run block of one uniquely named step."""

    source = (
        ROOT / ".github/workflows" / workflow
    ).read_text()

    marker = f"      - name: {name}\n"

    if source.count(marker) != 1:
        raise AssertionError(
            f"Unexpected step identity: {workflow}: {name}"
        )

    block = source.split(marker, 1)[1]
    block = block.split("\n      - name:", 1)[0]

    lines = block.splitlines()

    if lines.count("        run: |") != 1:
        raise AssertionError("Expected one literal run block")

    start = lines.index("        run: |") + 1

    script = []

    for line in lines[start:]:
        if line and not line.startswith("          "):
            break

        script.append(line)

    if not script:
        raise AssertionError("Empty workflow shell step")

    return textwrap.dedent("\n".join(script)) + "\n"


def render_command(package):
    """Extract the actual publisher rendering command."""

    workflow, step, destination = PACKAGES[package]

    script = workflow_step(workflow, step)

    lines = script.splitlines()

    starts = [
        index for index, line in enumerate(lines)
        if line.startswith(
            "python3 scripts/package-pipeline/"
            "generated_recipe_metadata.py "
        )
    ]

    if len(starts) != 1:
        raise AssertionError("Unexpected rendering interface")

    index = starts[0]
    command = [lines[index]]

    while command[-1].rstrip().endswith("\\"):
        index += 1
        command.append(lines[index])

    if f"render --package {package}" not in "\n".join(command):
        raise AssertionError("Wrong rendering package")

    if command[-1].strip() != f"> {destination}":
        raise AssertionError("Unexpected rendering destination")

    return "set -euo pipefail\n" + "\n".join(command) + "\n"


class PublisherWorkflowTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.root = Path(temporary.name)

        self.home = self.root / "home"
        self.home.mkdir()

        self.bin = self.root / "bin"
        self.bin.mkdir()

        self.envfile = self.root / "github-env"
        self.outputfile = self.root / "github-output"
        self.summaryfile = self.root / "github-summary"

        for path in (
            self.envfile,
            self.outputfile,
            self.summaryfile,
        ):
            path.touch()

        # No inherited GitHub credentials or Git configuration.
        self.env = {
            "PATH": str(self.bin) + os.pathsep + os.defpath,
            "HOME": str(self.home),
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(self.home / ".gitconfig"),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "file",
            "GITHUB_ENV": str(self.envfile),
            "GITHUB_OUTPUT": str(self.outputfile),
            "GITHUB_STEP_SUMMARY": str(self.summaryfile),
            "GITHUB_WORKSPACE": str(self.root),
            "GITHUB_EVENT_NAME": "pull_request",
            "GH_TOKEN": "fixture-token-not-a-secret",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        # Explicitly forbid unexpected external-service calls.
        for executable in ("gh", "curl"):
            self.stub(executable, "exit 91\n")

        scripts = self.root / "scripts/package-pipeline"
        scripts.mkdir(parents=True)

        shutil.copy2(
            ROOT / "scripts/package-pipeline"
            / "generated_recipe_metadata.py",
            scripts,
        )

        for package in PACKAGES:
            recipe = self.root / "arch" / package
            recipe.mkdir(parents=True)

            shutil.copy2(
                ROOT / "arch" / package / "PKGBUILD.in",
                recipe,
            )

    def stub(self, executable, body):
        path = self.bin / executable

        path.write_text(
            "#!/bin/bash\nset -euo pipefail\n" + body
        )

        path.chmod(0o700)

    def git(self, directory, *args):
        result = subprocess.run(
            ["git", "-C", str(directory), *args],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=20,
            check=True,
        )

        return result.stdout.strip()

    def repository(self, relative):
        repository = self.root / relative
        repository.mkdir(parents=True)

        self.git(repository, "init", "-q", "-b", "fixture")

        self.git(
            repository, "config", "user.name", "Fixture"
        )

        self.git(
            repository, "config", "user.email",
            "fixture@example.invalid",
        )

        self.git(
            repository, "config", "commit.gpgsign", "false"
        )

        self.git(
            repository, "config", "tag.gpgSign", "false"
        )

        self.git(
            repository, "commit", "--allow-empty",
            "-qm", "Initial fixture",
        )

        return repository

    def execute(self, script, **variables):
        return subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", script],
            cwd=self.root,
            env={**self.env, **variables},
            capture_output=True,
            text=True,
            timeout=30,
        )

    def assert_success(self, result):
        self.assertEqual(
            result.returncode, 0,
            result.stdout + result.stderr,
        )

    def assert_rejected(self, result):
        self.assertNotEqual(
            result.returncode, 0,
            result.stdout + result.stderr,
        )

        self.assertEqual(self.envfile.read_text(), "")
        self.assertEqual(self.outputfile.read_text(), "")

    def noctalia_fixture(self, tag):
        repository = self.repository("source/noctalia")

        self.git(repository, "tag", tag)

        self.git(
            repository, "commit", "--allow-empty",
            "-qm", "Custom fixture",
        )

        # Redirect the exact upstream fetch to a local clone.
        upstream = self.root / "upstream-noctalia.git"

        self.git(
            self.root, "clone", "-q", "--bare",
            str(repository), str(upstream),
        )

        self.git(
            repository,
            "config",
            "--global",
            f"url.{upstream}.insteadOf",
            "https://github.com/noctalia-dev/noctalia.git",
        )

        return self.git(repository, "rev-parse", "HEAD")

    def test_noctalia_valid_metadata(self):
        sha = self.noctalia_fixture("v5.6.0")

        result = self.execute(
            workflow_step(
                "publish-noctalia-custom.yml",
                "Resolve source metadata",
            )
        )

        self.assert_success(result)

        self.assertEqual(
            self.envfile.read_text(),
            f"SOURCE_SHA={sha}\n"
            "BASE_TAG=v5.6.0\n"
            f"PKGVER=5.6.0.custom.{sha[:8]}\n",
        )

    def test_noctalia_malformed_git_tag_stops_export(self):
        self.noctalia_fixture("v5.6.0;false")

        result = self.execute(
            workflow_step(
                "publish-noctalia-custom.yml",
                "Resolve source metadata",
            )
        )

        self.assert_rejected(result)
        self.assertIn("Invalid Noctalia source tag", result.stderr)

    def gameshell_fixture(self, tag):
        repository = self.repository("source/GameShell")

        self.git(repository, "tag", tag)

        self.git(
            repository, "commit", "--allow-empty",
            "-qm", "Development fixture",
        )

        sha = self.git(repository, "rev-parse", "HEAD")
        short = self.git(
            repository, "rev-parse", "--short=12", sha
        )

        self.git(repository, "tag", "latest")

        return repository, sha, short

    def gameshell_resolve(self):
        return self.execute(
            workflow_step(
                "publish-gameshell.yml",
                "Resolve version and update state",
            ),
            SOURCE_REF="latest",
            REQUESTED_PUBLISH="false",
        )

    def test_gameshell_valid_metadata_with_competing_branch(self):
        repository, sha, short = self.gameshell_fixture(
            "v0.6.0"
        )

        # Same name as the selected tag, different commit.
        self.git(
            repository, "branch", "latest", "HEAD^"
        )

        result = self.gameshell_resolve()

        self.assert_success(result)

        outputs = dict(
            line.split("=", 1)
            for line in self.outputfile.read_text().splitlines()
        )

        self.assertEqual(outputs["source_ref"], "latest")
        self.assertEqual(outputs["source_sha"], sha)
        self.assertEqual(
            outputs["pkgver"],
            f"0.6.0.r1.g{short}",
        )
        self.assertEqual(outputs["update"], "true")

    def test_gameshell_malformed_base_tag_stops_export(self):
        self.gameshell_fixture("v0.6.0;false")

        result = self.gameshell_resolve()

        self.assert_rejected(result)
        self.assertIn("Invalid upstream version tag", result.stderr)

    def greeter_fixture(self):
        repository = self.repository(
            "source/noctalia-greeter"
        )

        sha = self.git(repository, "rev-parse", "HEAD")

        self.git(
            repository, "tag", "-a", "v1.7.1",
            "-m", "Fixture annotated release",
        )

        tag_sha = self.git(
            repository, "rev-parse", "refs/tags/v1.7.1"
        )

        ref = {
            "object": {
                "type": "tag",
                "sha": tag_sha,
            },
        }

        tag = {
            "sha": tag_sha,
            "tag": "v1.7.1",
            "object": {
                "sha": sha,
                "type": "commit",
            },
            "verification": {
                "verified": True,
                "reason": "valid",
                "verified_at": None,
            },
        }

        return repository, sha, ref, tag

    def mock_greeter_api(self, ref, tag):
        (self.root / "ref.json").write_text(json.dumps(ref))
        (self.root / "tag.json").write_text(json.dumps(tag))

        self.stub(
            "curl",
            '''
case "${@: -1}" in
  https://api.github.com/repos/noctalia-dev/noctalia-greeter/git/ref/tags/v1.7.1)
    cat "$GITHUB_WORKSPACE/ref.json"
    ;;
  https://api.github.com/repos/noctalia-dev/noctalia-greeter/git/tags/*)
    cat "$GITHUB_WORKSPACE/tag.json"
    ;;
  *) exit 92 ;;
esac
''',
        )

    def greeter_resolve(self, sha, tag="v1.7.1"):
        return self.execute(
            workflow_step(
                "publish-noctalia-greeter.yml",
                "Verify upstream tag and security baseline",
            ),
            SOURCE_TAG=tag,
            SECURITY_FIX=sha,
            UPSTREAM_REPOSITORY="noctalia-dev/noctalia-greeter",
        )

    def test_greeter_validated_tag_and_checkout_identity(self):
        repository, sha, ref, tag = self.greeter_fixture()

        self.mock_greeter_api(ref, tag)

        result = self.greeter_resolve(sha)

        self.assert_success(result)

        self.assertEqual(
            self.envfile.read_text(),
            "SOURCE_TAG=v1.7.1\n"
            f"TAG_SHA={tag['sha']}\n"
            f"SOURCE_SHA={sha}\n"
            "PKGVER=1.7.1\n",
        )

    def test_greeter_malformed_tag_stops_before_api_lookup(self):
        result = self.greeter_resolve(
            "a" * 40, tag="v1.7.1;false"
        )

        self.assert_rejected(result)
        self.assertIn("Invalid Greeter source tag", result.stderr)

    def test_greeter_mismatched_checkout_stops_export(self):
        repository, sha, ref, tag = self.greeter_fixture()

        self.git(
            repository, "commit", "--allow-empty",
            "-qm", "Unexpected checkout",
        )

        self.mock_greeter_api(ref, tag)

        result = self.greeter_resolve(sha)

        self.assert_rejected(result)

        self.assertIn(
            "Checkout does not match verified tag identity",
            result.stderr,
        )

    def test_greeter_mismatched_tag_object_stops_export(self):
        repository, sha, ref, tag = self.greeter_fixture()

        self.git(
            repository, "tag", "-f", "-a", "v1.7.1",
            "-m", "Different annotated tag object",
        )

        self.mock_greeter_api(ref, tag)

        result = self.greeter_resolve(sha)

        self.assert_rejected(result)

        self.assertIn(
            "Checkout does not match verified tag identity",
            result.stderr,
        )

    def test_greeter_unverified_signature_stops_export(self):
        repository, sha, ref, tag = self.greeter_fixture()

        tag["verification"]["verified"] = False

        self.mock_greeter_api(ref, tag)

        result = self.greeter_resolve(sha)

        self.assert_rejected(result)

        self.assertIn(
            "Upstream tag signature is not verified",
            result.stderr,
        )

    def rendering_environment(self, package):
        values = {
            "PKGVER": "1.2.3",
            "source_sha256": DIGEST,
        }

        if package == "gameshell":
            values.update(
                SOURCE_SHA="b" * 40,
                archive_sha256=DIGEST,
                launcher_sha256=DIGEST,
                license_sha256=DIGEST,
                readme_sha256=DIGEST,
            )

        return values

    def test_all_publisher_render_commands_preserve_recipe(self):
        for package, (_, _, destination) in PACKAGES.items():
            with self.subTest(package=package):
                output = self.root / destination
                output.parent.mkdir(parents=True, exist_ok=True)

                variables = self.rendering_environment(package)

                result = self.execute(
                    render_command(package), **variables
                )

                self.assert_success(result)

                expected = (
                    self.root / "arch" / package / "PKGBUILD.in"
                ).read_text()

                for key, value in variables.items():
                    expected = expected.replace(
                        f"@{key.upper()}@", value
                    )

                self.assertEqual(output.read_text(), expected)

    def test_all_publisher_render_commands_reject_unsafe_values(self):
        for package, (_, _, destination) in PACKAGES.items():
            with self.subTest(package=package):
                output = self.root / destination
                output.parent.mkdir(parents=True, exist_ok=True)

                variables = self.rendering_environment(package)
                variables["PKGVER"] = "1.2.3;false"

                result = self.execute(
                    render_command(package), **variables
                )

                self.assert_rejected(result)

                # Shell redirection may create an empty file.
                # It must never contain a rendered recipe.
                self.assertEqual(output.read_bytes(), b"")
                self.assertIn("Invalid PKGVER", result.stderr)


if __name__ == "__main__":
    unittest.main()
