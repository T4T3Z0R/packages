import copy
import importlib.util
import sys
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))
SCRIPT = ROOT / "scripts/package-pipeline/verify_source_contract.py"

spec = importlib.util.spec_from_file_location("source_contract", SCRIPT)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)

MANIFEST = json.loads(
    (ROOT / "arch/packages/manifest.json").read_text()
)


class SourceContractTests(unittest.TestCase):
    def test_existing_registered_packages(self):
        for name in ("ghostty", "keepassxc", "syncthing", "wezterm", "moonlight-qt", "yazi", "broot"):
            with self.subTest(package=name):
                config = MANIFEST["packages"][name]
                result = contract.verify(name, config)
                self.assertTrue(result["verified"])

    def fixture(self, name="ghostty"):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        config = copy.deepcopy(MANIFEST["packages"][name])
        recipe = root / config["recipe"]
        recipe.parent.mkdir(parents=True)
        original = (ROOT / config["recipe"]).read_text()
        recipe.write_text(original)
        return root, config, recipe


    def test_ghostty_updated_version_and_checksum_allowed(self):
        root, config, recipe = self.fixture()
        source = recipe.read_text()

        old_version = contract.assignment(source, "pkgver")
        old_line = f"pkgver={old_version}\n"

        checksum = re.search(
            r"^sha256sums=\('[0-9a-f]{64}'\)$",
            source, re.MULTILINE
        )
        self.assertIsNotNone(checksum)
        self.assertEqual(source.count(old_line), 1)

        replacement = "sha256sums=('" + ("a" * 64) + "')"

        source = source.replace(
            old_line, "pkgver=1.4.1\n", 1
        ).replace(
            checksum.group(0), replacement, 1
        )

        config["source_ref"] = "v1.4.1"
        recipe.write_text(source)

        result = contract.verify("ghostty", config, root)

        self.assertTrue(result["verified"])
        self.assertEqual(result["pkgver"], "1.4.1")

    def test_ghostty_unpinned_or_dynamic_checksum_rejected(self):
        root, config, recipe = self.fixture()
        source = recipe.read_text()

        checksum = re.search(
            r"^sha256sums=\('[0-9a-f]{64}'\)$",
            source, re.MULTILINE
        )
        self.assertIsNotNone(checksum)

        invalid = (
            "sha256sums=('SKIP')",
            "sha256sums=('not-a-digest')",
            "sha256sums=($(echo unsafe))",
            "",
        )

        for replacement in invalid:
            with self.subTest(replacement=replacement):
                recipe.write_text(
                    source.replace(
                        checksum.group(0), replacement, 1
                    )
                )

                with self.assertRaisesRegex(
                    ValueError, "literal pinned SHA-256"
                ):
                    contract.verify("ghostty", config, root)

    def test_ghostty_duplicate_checksum_assignment_rejected(self):
        root, config, recipe = self.fixture()

        source = recipe.read_text()
        source += "\nsha256sums=('" + ("b" * 64) + "')\n"
        recipe.write_text(source)

        with self.assertRaisesRegex(
            ValueError, "literal pinned SHA-256"
        ):
            contract.verify("ghostty", config, root)

    def test_ghostty_workflow_uses_contract_not_fixed_digest(self):
        source = (
            ROOT / ".github/workflows/publish-ghostty.yml"
        ).read_text()

        load = source.index(
            "      - name: Load verified Ghostty source selection"
        )
        build = source.index(
            "      - name: Build split packages as unprivileged user"
        )
        self.assertLess(load, build)

        self.assertIn(
            "verify_source_contract.py --package ghostty",
            source[load:build],
        )

        verify_block = source.split(
            "      - name: Verify pinned recipe and compiler", 1
        )[1].split("\n      - name:", 1)[0]

        self.assertNotIn("sha256sums", verify_block)
        self.assertIn(
            "bash -n arch/ghostty/PKGBUILD",
            verify_block,
        )

    def test_moonlight_invalid_sha512_rejected(self):
        root, config, recipe = self.fixture("moonlight-qt")
        source = recipe.read_text()

        checksum = re.search(
            r"^sha512sums=\('[0-9a-f]{128}'\)$",
            source,
            re.MULTILINE,
        )
        self.assertIsNotNone(checksum)

        for replacement in (
            "sha512sums=('SKIP')",
            "sha512sums=('" + "a" * 64 + "')",
            "sha512sums=($(echo unsafe))",
            "",
        ):
            with self.subTest(replacement=replacement):
                recipe.write_text(
                    source.replace(checksum.group(0), replacement, 1)
                )
                with self.assertRaisesRegex(ValueError, "SHA-512"):
                    contract.verify("moonlight-qt", config, root)

    def test_moonlight_duplicate_sha512_rejected(self):
        root, config, recipe = self.fixture("moonlight-qt")
        recipe.write_text(
            recipe.read_text()
            + "\nsha512sums=('" + "a" * 128 + "')\n"
        )
        with self.assertRaisesRegex(ValueError, "SHA-512"):
            contract.verify("moonlight-qt", config, root)

    def test_moonlight_wrong_upstream_rejected(self):
        root, config, recipe = self.fixture("moonlight-qt")
        config["upstream"] = "other/moonlight-qt"

        with self.assertRaises(ValueError):
            contract.verify("moonlight-qt", config, root)

    def test_wrong_stable_version_rejected(self):
        root, config, recipe = self.fixture()
        config["source_ref"] = "v9.9.9"
        with self.assertRaisesRegex(ValueError, "mismatch"):
            contract.verify("ghostty", config, root)

    def test_wrong_development_commit_rejected(self):
        root, config, recipe = self.fixture("wezterm")
        config["source_ref"] = "a" * 40
        with self.assertRaisesRegex(ValueError, "mismatch"):
            contract.verify("wezterm", config, root)

    def test_duplicate_pkgver_rejected(self):
        root, config, recipe = self.fixture()
        recipe.write_text(recipe.read_text() + "\npkgver=9.9.9\n")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            contract.verify("ghostty", config, root)

    def test_invalid_pkgrel_rejected(self):
        root, config, recipe = self.fixture()
        content = recipe.read_text().replace("pkgrel=1\n", "pkgrel=0\n", 1)
        recipe.write_text(content)
        with self.assertRaisesRegex(ValueError, "invalid pkgrel"):
            contract.verify("ghostty", config, root)

    def test_missing_recipe_rejected(self):
        root, config, recipe = self.fixture()
        recipe.unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            contract.verify("ghostty", config, root)

    def test_unapproved_package_rejected(self):
        root, config, recipe = self.fixture()
        config["status"] = "candidate"
        with self.assertRaisesRegex(ValueError, "not approved"):
            contract.verify("ghostty", config, root)

    def test_wrong_recipe_path_rejected(self):
        root, config, recipe = self.fixture()
        config["recipe"] = "arch/syncthing/PKGBUILD"
        with self.assertRaisesRegex(ValueError, "fixed PKGBUILD"):
            contract.verify("ghostty", config, root)

    def test_invalid_declared_package_version_rejected(self):
        root, config, recipe = self.fixture("wezterm")
        original = recipe.read_text()
        current = contract.assignment(original, "pkgver")
        old = f"pkgver={current}\n"
        self.assertEqual(original.count(old), 1)
        recipe.write_text(
            original.replace(old, "pkgver=$(echo wrong)\n", 1)
        )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            contract.verify("wezterm", config, root)

    def test_ghostty_git_tag_source_contract(self):
        config = MANIFEST["packages"]["ghostty"]
        self.assertEqual(
            config["release_policy"], "stable-git-tag"
        )
        result = contract.verify("ghostty", config)
        self.assertTrue(result["verified"])
        self.assertEqual(result["source_field"], "pkgver")
        self.assertEqual(result["source_value"], "1.4.0")

    def test_release_based_stable_tag_remains_supported(self):
        config = copy.deepcopy(
            MANIFEST["packages"]["ghostty"]
        )
        config["release_policy"] = "stable-tag"
        result = contract.verify("ghostty", config)
        self.assertTrue(result["verified"])

    def test_pinned_tag_remains_supported(self):
        config = copy.deepcopy(
            MANIFEST["packages"]["ghostty"]
        )
        config["release_policy"] = "pinned-tag"
        result = contract.verify("ghostty", config)
        self.assertTrue(result["verified"])

    def test_unknown_policy_still_rejected(self):
        config = copy.deepcopy(
            MANIFEST["packages"]["ghostty"]
        )
        config["release_policy"] = "unapproved-policy"
        with self.assertRaisesRegex(
            ValueError, "unsupported release policy"
        ):
            contract.verify("ghostty", config)

    def test_unprefixed_keepassxc_tag(self):
        result = contract.verify(
            "keepassxc", MANIFEST["packages"]["keepassxc"]
        )
        self.assertEqual(result["source_value"], "2.8.0")


if __name__ == "__main__":
    unittest.main()
