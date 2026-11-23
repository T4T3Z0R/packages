import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))
from run_candidate_reviews import run
from select_candidate_write import select

OLD = "e1eae81a56be8b5487dc77a29616afa568fb57b7"
NEW = "ee6f3044d09f83f21a32aead8dac2bc2a32e7fcb"
REPORT = [
    {"package": "ghostty", "status": "unchanged",
     "selected": "v1.4.0", "candidate": "v1.4.0"},
    {"package": "wezterm", "status": "update",
     "selected": OLD, "candidate": NEW},
]


class CandidateWriteSelectionTests(unittest.TestCase):
    def test_exact_candidate_selected(self):
        self.assertEqual(select(REPORT, "wezterm", NEW), [REPORT[1]])

    def test_stale_candidate_rejected(self):
        with self.assertRaisesRegex(ValueError, "no longer current"):
            select(REPORT, "wezterm", "a" * 40)

    def test_unchanged_package_rejected(self):
        with self.assertRaisesRegex(ValueError, "no actionable update"):
            select(REPORT, "ghostty", "v1.4.0")

    def test_unknown_package_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            select(REPORT, "moonlight-qt", NEW)

    def test_unsafe_reference_rejected(self):
        with self.assertRaisesRegex(ValueError, "Invalid"):
            select(REPORT, "wezterm", "main;echo wrong")

    def test_malformed_report_rejected(self):
        with self.assertRaises(ValueError):
            select({"packages": REPORT}, "wezterm", NEW)

    def test_duplicate_package_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            select(REPORT + [REPORT[1]], "wezterm", NEW)

    def test_other_updates_not_selected(self):
        other = {**REPORT[0], "status": "update",
                 "candidate": "v1.5.0"}
        self.assertEqual(
            select([other, REPORT[1]], "wezterm", NEW), [REPORT[1]]
        )

    def test_second_pass_reuses_created_issue(self):
        issues = []
        writes = []

        def creator(title, body):
            writes.append((title, body))
            issue = {"id": 1042, "number": 42, "title": title,
                     "state": "open", "labels": []}
            issues.append(issue)
            return issue

        selected = select(REPORT, "wezterm", NEW)
        first = run(selected, lambda _: list(issues),
                    creator=creator, allow_create=True)
        second = run(selected, lambda _: list(issues),
                     creator=creator, allow_create=True)
        self.assertEqual(first[0]["action"], "created")
        self.assertEqual(first[0]["issue_number"], 42)
        self.assertEqual(second[0]["action"], "existing")
        self.assertEqual(second[0]["decision"], "pending")
        self.assertEqual(second[0]["issue_number"], 42)
        self.assertEqual(len(writes), 1)

    def test_existing_denial_prevents_write(self):
        selected = select(REPORT, "wezterm", NEW)
        history = [{"id": 1042, "number": 42,
                    "title": f"Package candidate: wezterm @ {NEW}",
                    "state": "closed",
                    "labels": [{"name": "candidate:denied"}]}]

        def forbidden(*args):
            self.fail("Unexpected GitHub write")

        result = run(selected, lambda _: history,
                     creator=forbidden, allow_create=True)
        self.assertEqual(result[0]["action"], "existing")
        self.assertEqual(result[0]["decision"], "denied")


if __name__ == "__main__":
    unittest.main()
