"""Offline tests for standalone historical maintenance."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/package-pipeline/maintain-history.py"

SPEC = importlib.util.spec_from_file_location(
    "history_maintenance", SCRIPT
)
maintenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(maintenance)

publisher = maintenance.publisher

PACKAGE = "noctalia-greeter-t4t3z0r"
RELEASE = "arch-history-" + PACKAGE
FILE = PACKAGE + "-1.7.0-1-x86_64.pkg.tar.zst"


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = {
            "release": RELEASE,
            "assets": {
                FILE: {"id": 200},
                FILE + ".sig": {"id": 201},
            },
        }

        self.journal = {
            "journal": {"retain": 3},
            "journal_asset": {"id": 999},
            "state": {
                "state": "interrupted",
                "remaining": [{"id": 300}],
            },
        }

    def inspect(self, recover=False, pending=False):
        if pending:
            self.snapshot["assets"][
                publisher.JOURNAL_NAME
            ] = self.journal["journal_asset"]

        with (
            patch.object(
                publisher, "history_snapshot",
                return_value=self.snapshot,
            ),
            patch.object(
                publisher, "require_unchanged_snapshot",
                return_value=self.snapshot,
            ),
            patch.object(
                publisher, "load_pruning_journal",
                return_value=self.journal,
            ) as load,
            patch.object(
                publisher, "execute_pruning_transaction",
                return_value={
                    "state": "complete", "deleted": 1,
                },
            ) as execute,
            patch.object(
                publisher, "prune_verified_history"
            ) as new_pruning,
        ):
            result = maintenance.maintain_package(
                PACKAGE, 3, recover=recover
            )

            new_pruning.assert_not_called()

            if pending:
                load.assert_called_once_with(RELEASE)
            else:
                load.assert_not_called()

            if pending and recover:
                execute.assert_called_once_with(
                    RELEASE, expected=self.journal
                )
            else:
                execute.assert_not_called()

        return result

    def test_clean_history_inspection(self):
        result = self.inspect()

        self.assertEqual(result["state"], "clean")
        self.assertEqual(result["archived_versions"], 1)
        self.assertFalse(result["over_limit"])

    def test_clean_history_recovery_is_noop(self):
        result = self.inspect(recover=True)

        self.assertEqual(result["state"], "clean")

    def test_pending_inspection_never_executes(self):
        result = self.inspect(pending=True)

        self.assertEqual(result["state"], "pending")
        self.assertEqual(result["remaining_assets"], 1)

    def test_pending_recovery_uses_existing_authorization(self):
        result = self.inspect(
            pending=True, recover=True
        )

        self.assertEqual(result["state"], "recovered")
        self.assertEqual(result["deleted_assets"], 1)

    def test_changed_policy_blocks_recovery(self):
        self.journal["journal"]["retain"] = 2

        with self.assertRaisesRegex(
            ValueError, "policy changed"
        ):
            self.inspect(pending=True, recover=True)

    def test_incomplete_pair_without_journal_rejected(self):
        del self.snapshot["assets"][FILE + ".sig"]

        with self.assertRaisesRegex(
            ValueError, "Incomplete historical package pair"
        ):
            self.inspect(recover=True)

    def test_over_limit_history_does_not_authorize_pruning(self):
        for version in ("1.6.0", "1.5.0", "1.4.0"):
            name = FILE.replace("1.7.0", version)
            self.snapshot["assets"][name] = {}
            self.snapshot["assets"][name + ".sig"] = {}

        result = self.inspect(recover=True)

        self.assertTrue(result["over_limit"])
        self.assertEqual(result["archived_versions"], 4)

    def test_disappearing_journal_blocks_recovery(self):
        self.snapshot["assets"][
            publisher.JOURNAL_NAME
        ] = self.journal["journal_asset"]

        with (
            patch.object(
                publisher, "history_snapshot",
                return_value=self.snapshot,
            ),
            patch.object(
                publisher, "load_pruning_journal",
                return_value=None,
            ),
            patch.object(
                publisher, "execute_pruning_transaction"
            ) as execute,
        ):
            with self.assertRaisesRegex(
                ValueError, "disappeared"
            ):
                maintenance.maintain_package(
                    PACKAGE, 3, recover=True
                )

        execute.assert_not_called()

    def test_replaced_journal_blocks_recovery(self):
        self.snapshot["assets"][
            publisher.JOURNAL_NAME
        ] = {"id": 998}

        with (
            patch.object(
                publisher, "history_snapshot",
                return_value=self.snapshot,
            ),
            patch.object(
                publisher, "load_pruning_journal",
                return_value=self.journal,
            ),
            patch.object(
                publisher, "execute_pruning_transaction"
            ) as execute,
        ):
            with self.assertRaisesRegex(
                ValueError, "journal changed"
            ):
                maintenance.maintain_package(
                    PACKAGE, 3, recover=True
                )

        execute.assert_not_called()

    def test_incomplete_recovery_is_failure(self):
        self.snapshot["assets"][
            publisher.JOURNAL_NAME
        ] = self.journal["journal_asset"]

        with (
            patch.object(
                publisher, "history_snapshot",
                return_value=self.snapshot,
            ),
            patch.object(
                publisher, "require_unchanged_snapshot"
            ),
            patch.object(
                publisher, "load_pruning_journal",
                return_value=self.journal,
            ),
            patch.object(
                publisher, "execute_pruning_transaction",
                return_value={"state": "no_transaction"},
            ),
        ):
            with self.assertRaisesRegex(
                ValueError, "not completed"
            ):
                maintenance.maintain_package(
                    PACKAGE, 3, recover=True
                )

    def test_failure_reported_without_skipping_other_packages(self):
        with (
            patch.object(
                maintenance, "configured_packages",
                return_value={"ghostty": 2, "wezterm": 2},
            ),
            patch.object(
                maintenance, "maintain_package",
                side_effect=[
                    ValueError("fixture failure"),
                    {"package": "wezterm", "state": "clean"},
                ],
            ) as check,
        ):
            result = maintenance.maintain(recover=True)

        self.assertFalse(result["success"])
        self.assertEqual(check.call_count, 2)
        self.assertEqual(
            [item["state"] for item in result["results"]],
            ["failed", "clean"],
        )

    def test_policy_rejects_arbitrary_release_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            policy = Path(temp) / "retention.json"
            policy.write_text(json.dumps({
                "schema_version": 1,
                "default_previous_versions": 0,
                "previous_versions": {"../arch-repo": 2},
            }))

            with patch.object(maintenance, "POLICY", policy):
                with self.assertRaisesRegex(
                    ValueError, "Invalid historical"
                ):
                    maintenance.configured_packages()

    def test_current_policy_contains_all_history_targets(self):
        packages = maintenance.configured_packages()

        self.assertEqual(len(packages), 28)
        self.assertEqual(packages["moonlight-qt"], 2)
        self.assertEqual(packages["moonlight-qt-debug"], 2)
        self.assertEqual(packages["yazi"], 2)
        self.assertEqual(packages["yazi-debug"], 2)
        self.assertEqual(packages["broot"], 2)
        self.assertEqual(packages["broot-debug"], 2)
        self.assertEqual(packages["thunar"], 2)
        self.assertEqual(packages["thunar-debug"], 2)
        self.assertEqual(packages["mousepad"], 2)
        self.assertEqual(packages["mousepad-debug"], 2)
        self.assertEqual(packages[PACKAGE], 3)
        self.assertEqual(packages["wezterm-debug"], 2)


if __name__ == "__main__":
    unittest.main()
