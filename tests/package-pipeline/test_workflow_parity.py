import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = (
    "publish-noctalia-custom.yml",
    "publish-gameshell.yml",
)

class WorkflowParityTests(unittest.TestCase):
    def test_existing_publishers(self):
        for filename in WORKFLOWS:
            with self.subTest(workflow=filename):
                path = ROOT / ".github/workflows" / filename
                source = path.read_text()

                required = (
                    "name: Assemble signed repository",
                    "name: Publish rolling Arch repository",
                    "name: Sign approved package",
                    "name: Download exact validated candidate",
                    "name: Verify validated candidate",
                    "name: Send Pushover approval notification",
                    "arch-repo-publish",
                    "ARCH_REPO_SIGNING_PASSPHRASE",
                    "repo-add",
                    "gpg --verify",
                    "gh release upload",
                    "gh release delete-asset",
                )

                for marker in required:
                    self.assertIn(marker, source)

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
