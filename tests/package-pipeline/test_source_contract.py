import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/package-pipeline/verify_source_contract.py"

spec = importlib.util.spec_from_file_location("source_contract", SCRIPT)
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)

MANIFEST = json.loads(
    (ROOT / "arch/packages/manifest.json").read_text()
)


class SourceContractTests(unittest.TestCase):
    def test_existing_registered_packages(self):
        for name in ("ghostty", "keepassxc", "syncthing", "wezterm"):
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

    def test_wezterm_declared_package_version(self):
        result = contract.verify(
            "wezterm", MANIFEST["packages"]["wezterm"]
        )
        self.assertEqual(
            result["pkgver"],
            "20240203.110809.5046fc22.r965.ge1eae81a5",
        )
        self.assertEqual(result["pkgrel"], 1)
        self.assertEqual(result["source_field"], "_commit")

    def test_invalid_declared_package_version_rejected(self):
        root, config, recipe = self.fixture("wezterm")
        original = recipe.read_text()
        old = "pkgver=20240203.110809.5046fc22.r965.ge1eae81a5"
        assert original.count(old) == 1
        recipe.write_text(
            original.replace(old, 'pkgver=$(echo wrong)', 1)
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
