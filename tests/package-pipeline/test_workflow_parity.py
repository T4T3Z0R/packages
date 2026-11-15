import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
class WorkflowParityTests(unittest.TestCase):
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
            'github.event_name != \'pull_request\'',
            'timezone: "America/New_York"',
            "cron: '37 9 * * *'",
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


if __name__ == "__main__":
    unittest.main()
