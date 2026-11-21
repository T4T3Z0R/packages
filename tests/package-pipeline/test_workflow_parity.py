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



if __name__ == "__main__":
    unittest.main()
