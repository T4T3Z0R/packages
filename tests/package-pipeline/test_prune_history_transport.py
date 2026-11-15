import importlib.util
import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts/package-pipeline/prune-history.py"
)

spec = importlib.util.spec_from_file_location(
    "prune_history_transport", SCRIPT
)
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)

NAME = "gameshell-1.9-1-any.pkg.tar.zst"
PAIR = [NAME, NAME + ".sig"]


class PruneHistoryTransportTests(unittest.TestCase):
    def test_remote_lookup_is_read_only(self):
        output = json.dumps(PAIR)
        with patch.object(
            transport.subprocess, "run",
            return_value=SimpleNamespace(stdout=output),
        ) as runner:
            names = transport.remote_inventory(
                "gameshell", "fixture/offline"
            )

        self.assertEqual(names, PAIR)
        runner.assert_called_once()

        command = runner.call_args.args[0]
        self.assertEqual(command[:3], [
            "gh", "release", "view"
        ])
        self.assertEqual(command[3], "arch-history-gameshell")
        self.assertEqual(command[-2:], [
            "--repo", "fixture/offline"
        ])
        self.assertNotIn("delete-asset", command)
        self.assertNotIn("upload", command)

    def test_failed_lookup_propagates(self):
        with patch.object(
            transport.subprocess, "run",
            side_effect=subprocess.CalledProcessError(17, "gh"),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                transport.remote_inventory(
                    "gameshell", "fixture/offline"
                )

    def test_invalid_json_rejected(self):
        with patch.object(
            transport.subprocess, "run",
            return_value=SimpleNamespace(stdout="not-json"),
        ):
            with self.assertRaises(json.JSONDecodeError):
                transport.remote_inventory(
                    "gameshell", "fixture/offline"
                )

    def test_duplicate_remote_assets_rejected_by_planner(self):
        with self.assertRaisesRegex(
            ValueError, "Duplicate history release assets"
        ):
            transport.planner.build_plan(
                PAIR + [NAME], "gameshell", 2
            )

    def test_unexpected_remote_asset_rejected_by_planner(self):
        with self.assertRaisesRegex(
            ValueError, "Unexpected history asset"
        ):
            transport.planner.build_plan(
                PAIR + ["unexpected.json"], "gameshell", 2
            )

    def test_remote_preview_never_deletes(self):
        argv = [
            str(SCRIPT), "--package", "gameshell", "--remote"
        ]
        env = {
            "GH_REPO": "fixture/offline",
            "GH_TOKEN": "offline-test-token",
        }
        with patch.object(sys, "argv", argv):
            with patch.dict(os.environ, env):
                with patch.object(
                    transport, "remote_inventory",
                    return_value=PAIR,
                ) as lookup:
                    with redirect_stdout(io.StringIO()) as stdout:
                        transport.main()

        plan = json.loads(stdout.getvalue())
        self.assertTrue(plan["dry_run"])
        self.assertFalse(plan["deletion_enabled"])
        self.assertEqual(plan["inventory_source"], "github")
        self.assertEqual(plan["prune"], [])
        lookup.assert_called_once_with(
            "gameshell", "fixture/offline"
        )

    def test_missing_remote_credentials_rejected(self):
        argv = [
            str(SCRIPT), "--package", "gameshell", "--remote"
        ]
        with patch.object(sys, "argv", argv):
            with patch.dict(
                os.environ,
                {"GH_REPO": "", "GH_TOKEN": ""},
            ):
                with patch.object(
                    transport, "remote_inventory"
                ) as lookup:
                    with self.assertRaisesRegex(
                        ValueError, "GH_REPO and GH_TOKEN"
                    ):
                        transport.main()
        lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
