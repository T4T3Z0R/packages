import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/package-pipeline/validate_noctalia_namcap.py"
spec = importlib.util.spec_from_file_location("validate_noctalia_namcap", MODULE_PATH)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

ALLOWED = (
    "noctalia-custom E: ELF file "
    "('usr/libexec/noctalia/noctalia-pam-helper') outside of a valid path."
)


class NoctaliaNamcapValidationTests(unittest.TestCase):
    def run_reports(self, reports):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for name, content in reports.items():
                path = Path(directory) / name
                path.write_text(content)
                paths.append(path)
            return validator.find_errors(paths)

    def test_exact_verified_helper_error_is_allowed(self):
        self.assertTrue(validator.is_allowed_diagnostic(ALLOWED))
        self.assertEqual(self.run_reports({"package.txt": ALLOWED + "\n"}), [])

    def test_altered_path_and_wording_are_not_allowed(self):
        for line in (
            ALLOWED.replace("noctalia-pam-helper", "other-helper"),
            ALLOWED.replace("outside of a valid path", "outside valid path"),
        ):
            with self.subTest(line=line):
                self.assertFalse(validator.is_allowed_diagnostic(line))
                self.assertEqual(len(self.run_reports({"package.txt": line + "\n"})), 1)

    def test_unrelated_fatal_namcap_error_is_rejected(self):
        report = ALLOWED + "\nnoctalia-custom E: Package contains a broken symlink.\n"
        errors = self.run_reports({"package.txt": report})
        self.assertEqual(len(errors), 1)
        self.assertIn(" E: Package contains a broken symlink.", errors[0])

    def test_missing_expected_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = validator.find_errors([Path(directory) / "missing.txt"])
        self.assertEqual(len(errors), 1)
        self.assertIn("Missing expected namcap report", errors[0])

    def test_warning_is_nonfatal(self):
        self.assertEqual(self.run_reports({"package.txt": "noctalia-custom W: warning\n"}), [])


if __name__ == "__main__":
    unittest.main()
