import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(
    0, str(ROOT / "scripts/package-pipeline")
)

from run_candidate_reviews import run


REPORT = [{
    "package": "ghostty",
    "status": "update",
    "selected": "v1.4.0",
    "candidate": "v1.5.0",
}]


def issue():
    return {
        "id": 1042,
        "number": 42,
        "title": "Package candidate: ghostty @ v1.5.0",
        "state": "open",
        "labels": [],
    }


class CandidateRunnerTests(unittest.TestCase):
    def test_read_only_default(self):
        result = run(REPORT, lambda _: [])
        self.assertEqual(result[0]["action"], "create")

    def test_read_only_never_calls_writer(self):
        def forbidden(*args):
            self.fail("Unexpected write")

        result = run(
            REPORT, lambda _: [],
            creator=forbidden,
        )
        self.assertEqual(result[0]["action"], "create")

    def test_existing_review(self):
        result = run(REPORT, lambda _: [issue()])
        self.assertEqual(result[0]["action"], "pending")

    def test_explicit_creation(self):
        writes = []

        def creator(title, body):
            writes.append((title, body))
            return issue()

        result = run(
            REPORT,
            lambda _: [],
            creator=creator,
            allow_create=True,
        )
        self.assertEqual(result[0]["action"], "created")
        self.assertEqual(len(writes), 1)

    def test_existing_review_blocks_creation(self):
        result = run(
            REPORT,
            lambda _: [issue()],
            creator=lambda *args: self.fail(
                "Unexpected write"
            ),
            allow_create=True,
        )
        self.assertEqual(result[0]["action"], "existing")

    def test_creation_requires_writer(self):
        with self.assertRaises(ValueError):
            run(
                REPORT,
                lambda _: [],
                allow_create=True,
            )

    def test_api_failure_blocks_creation(self):
        def api(_):
            raise RuntimeError("GitHub unavailable")

        with self.assertRaises(RuntimeError):
            run(
                REPORT,
                api,
                creator=lambda *args: self.fail(
                    "Unexpected write"
                ),
                allow_create=True,
            )

    def test_unchanged_report(self):
        report = [{
            **REPORT[0],
            "status": "unchanged",
            "candidate": "v1.4.0",
        }]
        self.assertEqual(run(report, lambda _: []), [])

    def test_duplicate_report_fails(self):
        with self.assertRaises(ValueError):
            run(REPORT + REPORT, lambda _: [])


if __name__ == "__main__":
    unittest.main()
