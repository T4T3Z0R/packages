import copy
import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts/package-pipeline/validate_manifest.py"
MANIFEST = ROOT / "arch/packages/manifest.json"

spec = importlib.util.spec_from_file_location("manifest_validator", VALIDATOR)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.original = json.loads(MANIFEST.read_text())
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.old_path = validator.MANIFEST
        validator.MANIFEST = Path(self.temp.name) / "manifest.json"
        self.addCleanup(setattr, validator, "MANIFEST", self.old_path)

    def check(self, data, accepted):
        validator.MANIFEST.write_text(json.dumps(data))
        with redirect_stdout(StringIO()):
            if accepted:
                validator.validate()
            else:
                with self.assertRaises(ValueError):
                    validator.validate()

    def test_valid_manifest(self):
        self.check(self.original, True)

    def test_unsupported_schema(self):
        data = copy.deepcopy(self.original)
        data["schema_version"] = 2
        self.check(data, False)

    def test_invalid_package_name(self):
        data = copy.deepcopy(self.original)
        data["packages"]["../escape"] = data["packages"].pop("yazi")
        self.check(data, False)

    def test_unexpected_field(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["command"] = "echo unsafe"
        self.check(data, False)

    def test_invalid_upstream(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["upstream"] = "https://example.com/repo"
        self.check(data, False)

    def test_invalid_tag(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["source_ref"] = "main"
        self.check(data, False)

    def test_recipe_path_escape(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["recipe"] = "../../PKGBUILD"
        self.check(data, False)

    def test_existing_fixed_recipe(self):
        data = copy.deepcopy(self.original)
        package = data["packages"]["yazi"]
        package["recipe"] = "arch/yazi/PKGBUILD"
        package["status"] = "candidate"
        self.check(data, True)

    def test_existing_template_recipe(self):
        data = copy.deepcopy(self.original)
        package = data["packages"]["yazi"]
        package["recipe"] = "arch/yazi/PKGBUILD.in"
        package["status"] = "candidate"
        self.check(data, True)

    def test_cross_package_recipe_rejected(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["recipe"] = "arch/ghostty/PKGBUILD"
        self.check(data, False)

    def test_approved_missing_recipe_rejected(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["status"] = "approved"
        self.check(data, False)

    def test_approved_existing_recipe(self):
        data = copy.deepcopy(self.original)
        self.assertEqual(
            data["packages"]["ghostty"]["recipe"],
            "arch/ghostty/PKGBUILD",
        )
        self.check(data, True)

    def test_unprefixed_stable_tag(self):
        data = copy.deepcopy(self.original)
        data["packages"]["keepassxc"]["source_ref"] = "2.8.0"
        self.check(data, True)

    def test_registered_packages_have_real_recipes(self):
        for name in ("ghostty", "keepassxc", "syncthing", "wezterm"):
            with self.subTest(package=name):
                package = self.original["packages"][name]
                self.assertEqual(package["status"], "approved")
                self.assertTrue((ROOT / package["recipe"]).is_file())

    def test_approved_missing_real_recipe(self):
        data = copy.deepcopy(self.original)
        data["packages"]["ghostty"]["recipe"] = "arch/ghostty/PKGBUILD.in"
        self.check(data, False)

    def test_stable_git_tag_policy(self):
        data = copy.deepcopy(self.original)
        data["packages"]["ghostty"]["release_policy"] = (
            "stable-git-tag"
        )
        self.check(data, True)

    def test_stable_git_tag_rejects_commit(self):
        data = copy.deepcopy(self.original)
        data["packages"]["ghostty"]["source_ref"] = (
            "a" * 40
        )
        self.check(data, False)

    def test_unapproved_policy(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["release_policy"] = "arbitrary-commit"
        self.check(data, False)

    def test_pinned_stable_release(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["release_policy"] = "pinned-tag"
        self.check(data, True)

    def test_development_commit(self):
        data = copy.deepcopy(self.original)
        package = data["packages"]["yazi"]
        package["release_policy"] = "development-commit"
        package["source_ref"] = "a" * 40
        self.check(data, True)

    def test_pinned_commit(self):
        data = copy.deepcopy(self.original)
        package = data["packages"]["yazi"]
        package["release_policy"] = "pinned-commit"
        package["source_ref"] = "b" * 40
        self.check(data, True)

    def test_registered_tracking_refs(self):
        self.check(self.original, True)

    def test_stable_policy_rejects_tracking_ref(self):
        data = copy.deepcopy(self.original)
        data["packages"]["ghostty"]["tracking_ref"] = (
            "refs/heads/main"
        )
        self.check(data, False)

    def test_tracking_ref_rejects_traversal(self):
        data = copy.deepcopy(self.original)
        data["packages"]["gameshell"]["tracking_ref"] = (
            "refs/tags/../latest"
        )
        self.check(data, False)

    def test_development_ref_must_be_immutable(self):
        data = copy.deepcopy(self.original)
        package = data["packages"]["yazi"]
        package["release_policy"] = "development-commit"
        package["source_ref"] = "main"
        self.check(data, False)

    def test_stable_policy_rejects_commit(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["source_ref"] = "a" * 40
        self.check(data, False)

    def test_automatic_publication(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["auto_publish"] = True
        self.check(data, False)

    def test_boolean_schema_version(self):
        data = copy.deepcopy(self.original)
        data["schema_version"] = True
        self.check(data, False)

    def test_non_boolean_publication(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["auto_publish"] = 0
        self.check(data, False)


if __name__ == "__main__":
    unittest.main()
