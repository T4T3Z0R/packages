import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = (
    "publish-noctalia-custom.yml",
    "publish-noctalia-greeter.yml",
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

if __name__ == "__main__":
    unittest.main()
