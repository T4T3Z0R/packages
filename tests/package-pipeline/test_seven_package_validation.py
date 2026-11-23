import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))
import select_package_validation as selector
from package_fingerprint import fingerprint
from github_validation_history import validation_runs
from validation_ledger import VALIDATION_JOBS, classify
from verify_validation_source import verify

GENERATED = (
    "gameshell", "noctalia-custom", "noctalia-greeter-t4t3z0r"
)

class SevenPackageValidation(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(
            (ROOT / "arch/packages/manifest.json").read_text()
        )

    def test_seven_approved_packages_and_yazi_excluded(self):
        approved = {n for n, c in self.manifest["packages"].items()
                    if c["status"] == "approved"}
        self.assertEqual(approved, set(selector.SUPPORTED))
        self.assertNotIn("yazi", approved)

    def test_generated_recipes_and_workflow_mapping(self):
        for package in GENERATED:
            with self.subTest(package=package):
                self.assertEqual(
                    self.manifest["packages"][package]["recipe"],
                    f"arch/{package}/PKGBUILD.in")
                workflow = selector.workflow_file(package)
                self.assertTrue((ROOT / ".github/workflows" / workflow).is_file())
                self.assertIn(package, VALIDATION_JOBS)
        self.assertEqual(selector.workflow_file("noctalia-greeter-t4t3z0r"),
                         "publish-noctalia-greeter.yml")

    def test_recipe_and_publisher_changes_select_generated_packages(self):
        for package in GENERATED:
            with self.subTest(package=package):
                config = {"packages": {package: self.manifest["packages"][package]}}
                self.assertEqual(selector.select(
                    config, config, {f"arch/{package}/PKGBUILD.in"}), [package])
                self.assertEqual(selector.select(
                    config, config,
                    {f".github/workflows/{selector.workflow_file(package)}"}),
                    [package])

    def test_source_matches_manifest_exactly(self):
        for package in GENERATED:
            selected = self.manifest["packages"][package]["source_ref"]
            self.assertTrue(verify(self.manifest, package, selected)["verified"])
            with self.assertRaises(ValueError):
                verify(self.manifest, package, "invalid-source")
        with self.assertRaises(ValueError):
            verify(self.manifest, "yazi", "anything")

    def test_real_git_fingerprints_for_seven_packages(self):
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        for package in selector.SUPPORTED:
            with self.subTest(package=package):
                result = fingerprint(ROOT, revision, package)
                self.assertEqual(len(result), 64)

    def test_greeter_validation_history_uses_real_workflow_name(self):
        called = []
        def api(endpoint):
            called.append(endpoint)
            return {"total_count": 0, "workflow_runs": []}
        self.assertEqual(validation_runs(
            api, "T4T3Z0R/packages", "noctalia-greeter-t4t3z0r"), [])
        self.assertIn("publish-noctalia-greeter.yml", called[0])

    def test_three_publishers_have_guarded_source_and_uniform_artifacts(self):
        for package in GENERATED:
            with self.subTest(package=package):
                src = (ROOT / ".github/workflows" /
                       selector.workflow_file(package)).read_text()
                self.assertEqual(src.count("name: Verify selected manifest source"), 1)
                self.assertIn("inputs.publish != true", src)
                artifact = (f"{package}-${{{{ github.run_id }}}}-"
                            f"${{{{ github.run_attempt }}}}-candidate")
                self.assertEqual(src.count("name: " + artifact), 2)
                self.assertIn("name: arch-repo-publish", src)

    def test_ledger_requires_source_verification_before_acceptance(self):
        for package in GENERATED:
            with self.subTest(package=package):
                run = {"event": "workflow_dispatch", "head_sha": "b" * 40,
                       "id": 123, "run_attempt": 1, "status": "completed",
                       "conclusion": "success"}
                jobs = [
                    {"name": VALIDATION_JOBS[package], "conclusion": "success",
                     "steps": [
                         {"name": "Verify selected manifest source",
                          "conclusion": "success"},
                         {"name": "Upload unsigned candidate and evidence",
                          "conclusion": "success"}]},
                    {"name": "Sign and publish approved candidate",
                     "conclusion": "skipped"},
                    {"name": "Notify signing approval ready",
                     "conclusion": "skipped"},
                ]
                artifacts = [{"name": f"{package}-123-1-candidate",
                              "size_in_bytes": 42, "expired": False}]
                kwargs = {"package": package, "target": "a" * 64,
                          "fingerprint": lambda sha, name: "a" * 64}
                self.assertEqual(classify(run, jobs, artifacts, **kwargs),
                                 "validated")
                jobs[0]["steps"][0]["conclusion"] = "skipped"
                self.assertEqual(classify(run, jobs, artifacts, **kwargs),
                                 "retry")
                jobs[0]["steps"][0]["conclusion"] = "success"
                jobs[1]["conclusion"] = "success"
                self.assertEqual(classify(run, jobs, artifacts, **kwargs),
                                 "retry")

if __name__ == "__main__":
    unittest.main()
