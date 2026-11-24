import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

import dispatch_unsigned_validation as dispatcher

REV = "f" * 40
BEFORE = "e" * 40
MANIFEST = json.loads(
    (ROOT / "arch/packages/manifest.json").read_text()
)

PLAN = {
    "decision": "review_validation",
    "revision": REV,
    "package": "wezterm",
    "selected": MANIFEST["packages"]["wezterm"]["source_ref"],
    "workflow": "publish-wezterm.yml",
    "inputs": {"publish": False},
    "validation_dispatched": False,
    "publication_authorized": False,
}

EVENT = {
    "ref": "refs/heads/main",
    "repository": {"full_name": "T4T3Z0R/packages"},
    "sender": {"login": "T4T3Z0R"},
    "forced": False,
    "deleted": False,
    "before": BEFORE,
    "after": REV,
}


def fake_git(_root, *args):
    if args == ("rev-parse", "HEAD"):
        return (REV + "\n").encode()
    if args == (
        "diff", "--no-renames", "--name-only", "-z", BEFORE, REV
    ):
        return (
            b"arch/packages/manifest.json\0"
            b"arch/wezterm/PKGBUILD\0"
        )
    raise AssertionError(f"Unexpected Git invocation: {args}")


class ProtectedDispatchTests(unittest.TestCase):
    def exercise(self, permitted):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event = root / "event.json"
            plan = root / "plan.json"
            event.write_text(json.dumps(EVENT))
            plan.write_text(json.dumps(PLAN))

            failure = (
                None if permitted
                else ValueError("approval policy rejected")
            )

            with (
                patch.dict(os.environ, {
                    "GITHUB_SHA": REV,
                    "GITHUB_STEP_SUMMARY": "",
                }),
                patch.object(dispatcher.sys, "argv", [
                    "dispatcher", str(plan), str(event)
                ]),
                patch.object(
                    dispatcher, "git", side_effect=fake_git
                ),
                patch.object(
                    dispatcher, "read_main_sha", return_value=REV
                ),
                patch.object(
                    dispatcher, "fresh_merge_plan", return_value=PLAN
                ),
                patch.object(
                    dispatcher, "fingerprint", return_value="a" * 64
                ),
                patch.object(
                    dispatcher, "evaluate",
                    return_value={"decision": "needs_validation"}
                ) as history,
                patch.object(
                    dispatcher, "verify_approval_policy",
                    side_effect=failure
                ) as policy,
                patch.object(
                    dispatcher.subprocess, "run"
                ) as post,
                redirect_stdout(io.StringIO()),
            ):
                if permitted:
                    dispatcher.main()
                else:
                    with self.assertRaisesRegex(
                        ValueError, "approval policy rejected"
                    ):
                        dispatcher.main()

                policy.assert_called_once_with(
                    dispatcher.github_api
                )

                if not permitted:
                    history.assert_called_once()
                    post.assert_not_called()
                    return

                self.assertEqual(history.call_count, 2)
                post.assert_called_once()
                args, kwargs = post.call_args

                self.assertEqual(args[0][:4], [
                    "gh", "api", "--method", "POST"
                ])
                self.assertIn(
                    "publish-wezterm.yml/dispatches",
                    args[0][4]
                )
                self.assertTrue(kwargs["check"])

                payload = json.loads(kwargs["input"])
                self.assertEqual(payload["ref"], "main")
                self.assertEqual(
                    payload["inputs"]["publish"], "true"
                )
                self.assertEqual(
                    payload["inputs"]["expected_revision"], REV
                )


    def test_changed_history_before_dispatch_fails_closed(self):
        scenarios = (
            {"decision": "in_flight", "history_count": 1},
            {"decision": "needs_validation", "history_count": 1},
            {"decision": "validated", "history_count": 0},
        )

        for latest in scenarios:
            with self.subTest(latest=latest):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    event = root / "event.json"
                    plan = root / "plan.json"

                    event.write_text(json.dumps(EVENT))
                    plan.write_text(json.dumps(PLAN))

                    with (
                        patch.dict(os.environ, {
                            "GITHUB_SHA": REV,
                            "GITHUB_STEP_SUMMARY": "",
                        }),
                        patch.object(dispatcher.sys, "argv", [
                            "dispatcher", str(plan), str(event)
                        ]),
                        patch.object(
                            dispatcher, "git", side_effect=fake_git
                        ),
                        patch.object(
                            dispatcher, "read_main_sha",
                            return_value=REV
                        ),
                        patch.object(
                            dispatcher, "fresh_merge_plan",
                            return_value=PLAN
                        ),
                        patch.object(
                            dispatcher, "fingerprint",
                            return_value="a" * 64
                        ),
                        patch.object(
                            dispatcher, "evaluate",
                            side_effect=[
                                {
                                    "decision": "needs_validation",
                                    "history_count": 0,
                                },
                                latest,
                            ],
                        ) as history,
                        patch.object(
                            dispatcher, "verify_approval_policy"
                        ) as policy,
                        patch.object(
                            dispatcher.subprocess, "run"
                        ) as post,
                        redirect_stdout(io.StringIO()),
                    ):
                        with self.assertRaisesRegex(
                            ValueError, "Release history changed"
                        ):
                            dispatcher.main()

                        self.assertEqual(history.call_count, 2)
                        policy.assert_called_once_with(
                            dispatcher.github_api
                        )
                        post.assert_not_called()

    def test_policy_rejection_prevents_dispatch(self):
        self.exercise(permitted=False)

    def test_verified_policy_allows_exact_request(self):
        self.exercise(permitted=True)


if __name__ == "__main__":
    unittest.main()
