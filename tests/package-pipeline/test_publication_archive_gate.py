import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts/package-pipeline/publication-archive-gate.py"
)

spec = importlib.util.spec_from_file_location("archive_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ArchiveGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = self.root / "retention.json"
        self.policy.write_text(json.dumps({
            "schema_version": 1,
            "default_previous_versions": 0,
            "previous_versions": {"gameshell": 2},
        }))
        self.policy_patch = patch.object(gate, "POLICY", self.policy)
        self.policy_patch.start()
        self.addCleanup(self.policy_patch.stop)

        self.package = "gameshell"
        self.candidate = "gameshell-2.0-1-any.pkg.tar.zst"
        self.old = "gameshell-1.0-1-any.pkg.tar.zst"
        self.state = self.root / "archive-state.txt"
        self.staging = self.root / "archive-output"
        self.staging.mkdir()
        self.set_state()
        self.files = {self.old, self.old + ".sig"}
        for name in self.files:
            (self.staging / name).write_bytes(b"fixture")

    def set_state(self, old=None):
        displaced = self.old if old is None else old
        self.state.write_text(
            "\n".join((self.package, self.candidate, displaced)) + "\n"
        )

    def execute(self):
        argv = [
            str(SCRIPT), "--package", self.package,
            "--candidate", self.candidate,
            "--state", str(self.state),
            "--staging", str(self.staging),
        ]
        with patch.object(sys, "argv", argv):
            with patch.dict(
                "os.environ", {"SIGNING_SUBKEY": "A" * 40}
            ):
                with redirect_stdout(io.StringIO()) as output:
                    gate.main()
        return json.loads(output.getvalue())

    def success_response(self):
        return {
            "published": True,
            "verified": True,
            "release": "arch-history-gameshell",
            "assets": sorted(self.files),
        }

    def test_retained_archive_success(self):
        with patch.object(
            gate, "invoke", return_value=self.success_response()
        ) as invoked:
            result = self.execute()
        self.assertTrue(result["gate_passed"])
        self.assertTrue(result["history_verified"])
        invoked.assert_called_once()
        self.assertEqual(invoked.call_args.args[0], "publish-history.py")
        self.assertTrue(invoked.call_args.kwargs["publish"])

    def test_archive_upload_failure_blocks(self):
        with patch.object(
            gate, "invoke",
            side_effect=subprocess.CalledProcessError(1, "mock"),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                self.execute()

    def test_unverified_success_response_blocks(self):
        response = self.success_response()
        response["verified"] = False
        with patch.object(gate, "invoke", return_value=response):
            with self.assertRaisesRegex(
                ValueError, "Historical publication not verified"
            ):
                self.execute()

    def test_wrong_history_release_blocks(self):
        response = self.success_response()
        response["release"] = "arch-history-other"
        with patch.object(gate, "invoke", return_value=response):
            with self.assertRaisesRegex(
                ValueError, "Historical publication not verified"
            ):
                self.execute()

    def test_missing_reported_signature_blocks(self):
        response = self.success_response()
        response["assets"] = [self.old]
        with patch.object(gate, "invoke", return_value=response):
            with self.assertRaisesRegex(
                ValueError, "Historical publication not verified"
            ):
                self.execute()

    def test_zero_retention_requires_preflight(self):
        self.package = "yazi"
        self.candidate = "yazi-2.0-1-any.pkg.tar.zst"
        self.old = "yazi-1.0-1-any.pkg.tar.zst"
        self.files = {self.old, self.old + ".sig"}
        for item in self.staging.iterdir():
            item.unlink()
        for name in self.files:
            (self.staging / name).write_bytes(b"fixture")
        self.set_state()

        response = {
            "verified": True,
            "archive_required": False,
            "file": self.old,
            "signature": self.old + ".sig",
        }
        with patch.object(
            gate, "invoke", return_value=response
        ) as invoked:
            result = self.execute()
        self.assertTrue(result["gate_passed"])
        self.assertFalse(result["history_verified"])
        self.assertEqual(
            invoked.call_args.args[0], "archive-repository.py"
        )

    def test_missing_staged_signature_blocks(self):
        (self.staging / (self.old + ".sig")).unlink()
        with patch.object(gate, "invoke") as invoked:
            with self.assertRaisesRegex(
                ValueError, "Staging does not match assembly state"
            ):
                self.execute()
        invoked.assert_not_called()

    def test_first_publication_needs_no_archive(self):
        self.set_state("")
        for item in self.staging.iterdir():
            item.unlink()
        with patch.object(gate, "invoke") as invoked:
            result = self.execute()
        self.assertTrue(result["gate_passed"])
        self.assertFalse(result["displaced"])
        invoked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
