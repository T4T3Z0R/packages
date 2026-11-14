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

    def test_unapproved_policy(self):
        data = copy.deepcopy(self.original)
        data["packages"]["yazi"]["release_policy"] = "arbitrary-commit"
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
