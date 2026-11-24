import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from github_validation_history import (
    fetch_pages,
    run_artifacts,
    run_attempt_evidence,
    run_evidence,
    validation_runs,
)


class HistoryReaderTests(unittest.TestCase):
    def test_empty_collection(self):
        calls = []

        def api(url):
            calls.append(url)
            return {"total_count": 0, "workflow_runs": []}

        self.assertEqual(
            fetch_pages(api, "example", "workflow_runs"),
            [],
        )
        self.assertEqual(len(calls), 1)

    def test_single_page(self):
        result = fetch_pages(
            lambda url: {
                "total_count": 2,
                "jobs": [{"id": 1}, {"id": 2}],
            },
            "example",
            "jobs",
        )
        self.assertEqual(len(result), 2)

    def test_multiple_pages(self):
        calls = []

        def api(url):
            calls.append(url)
            if "&page=1" in url:
                return {
                    "total_count": 101,
                    "jobs": [{"id": i + 1} for i in range(100)],
                }
            return {
                "total_count": 101,
                "jobs": [{"id": 101}],
            }

        result = fetch_pages(api, "example", "jobs")
        self.assertEqual(len(result), 101)
        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[0].endswith("&page=1"))
        self.assertTrue(calls[1].endswith("&page=2"))
        self.assertEqual(
            [item["id"] for item in result],
            list(range(1, 102)),
        )

    def test_overlapping_pages_rejected(self):
        def api(url):
            if url.endswith("&page=1"):
                return {
                    "total_count": 101,
                    "jobs": [
                        {"id": i + 1} for i in range(100)
                    ],
                }

            return {
                "total_count": 101,
                "jobs": [{"id": 100}],
            }

        with self.assertRaisesRegex(
            ValueError, "Overlapping"
        ):
            fetch_pages(api, "example", "jobs")

    def test_missing_record_identity_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "identity"
        ):
            fetch_pages(
                lambda url: {
                    "total_count": 1,
                    "jobs": [{}],
                },
                "example",
                "jobs",
            )

    def test_truncated_page_rejected(self):
        with self.assertRaises(ValueError):
            fetch_pages(
                lambda url: {
                    "total_count": 3,
                    "jobs": [{"id": 1}],
                },
                "example",
                "jobs",
            )

    def test_count_change_rejected(self):
        def api(url):
            if "&page=1" in url:
                return {
                    "total_count": 101,
                    "jobs": [{"id": i + 1} for i in range(100)],
                }
            return {
                "total_count": 102,
                "jobs": [{}],
            }

        with self.assertRaises(ValueError):
            fetch_pages(api, "example", "jobs")

    def test_invalid_response_rejected(self):
        with self.assertRaises(ValueError):
            fetch_pages(
                lambda url: {"jobs": []},
                "example",
                "jobs",
            )

    def test_api_failure_propagates(self):
        def api(url):
            raise RuntimeError("GitHub unavailable")

        with self.assertRaises(RuntimeError):
            fetch_pages(api, "example", "jobs")

    def test_unsupported_package_rejected(self):
        with self.assertRaises(ValueError):
            validation_runs(
                lambda url: None,
                "T4T3Z0R/packages",
                "moonlight-qt",
            )

    def test_correct_workflow_endpoint(self):
        calls = []

        def api(url):
            calls.append(url)
            return {
                "total_count": 0,
                "workflow_runs": [],
            }

        validation_runs(
            api, "T4T3Z0R/packages", "wezterm"
        )

        self.assertIn(
            "/publish-wezterm.yml/runs"
            "?event=workflow_dispatch",
            calls[0],
        )

    def test_run_evidence_fetches_both_collections(self):
        calls = []

        def api(url):
            calls.append(url)
            if "/jobs?" in url:
                return {"total_count": 1, "jobs": [{"id": 1}]}
            if "/artifacts?" in url:
                return {
                    "total_count": 1,
                    "artifacts": [{"id": 2}],
                }
            raise AssertionError(url)

        jobs, artifacts = run_evidence(
            api, "T4T3Z0R/packages", 123
        )

        self.assertEqual(len(jobs), 1)
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(len(calls), 2)



    def test_attempt_reader_uses_exact_attempt(self):
        calls = []

        def api(url):
            calls.append(url)
            if url.endswith("/attempts/2"):
                return {"id": 123, "run_attempt": 2}
            if "/attempts/2/jobs?" in url:
                return {
                    "total_count": 1,
                    "jobs": [
                        {"id": 21, "run_id": 123, "run_attempt": 2}
                    ],
                }
            raise AssertionError(url)

        result, jobs = run_attempt_evidence(
            api, "T4T3Z0R/packages", 123, 2
        )

        self.assertEqual(result["run_attempt"], 2)
        self.assertEqual(len(jobs), 1)
        self.assertEqual(len(calls), 2)
        self.assertTrue(
            calls[1].endswith(
                "/attempts/2/jobs?per_page=100&page=1"
            )
        )

    def test_attempt_reader_rejects_wrong_identity(self):
        def api(url):
            return {"id": 123, "run_attempt": 1}

        with self.assertRaisesRegex(ValueError, "identity"):
            run_attempt_evidence(
                api, "T4T3Z0R/packages", 123, 2
            )

    def test_attempt_reader_rejects_foreign_job(self):
        def api(url):
            if url.endswith("/attempts/2"):
                return {"id": 123, "run_attempt": 2}
            return {
                "total_count": 1,
                "jobs": [{"id": 21, "run_id": 999}],
            }

        with self.assertRaisesRegex(ValueError, "another workflow"):
            run_attempt_evidence(
                api, "T4T3Z0R/packages", 123, 2
            )

    def test_attempt_reader_propagates_api_failure(self):
        def api(url):
            raise RuntimeError("GitHub unavailable")

        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            run_attempt_evidence(
                api, "T4T3Z0R/packages", 123, 2
            )

    def test_run_artifacts_uses_complete_collection(self):
        calls = []

        def api(url):
            calls.append(url)
            return {
                "total_count": 1,
                "artifacts": [{"id": 31}],
            }

        artifacts = run_artifacts(
            api, "T4T3Z0R/packages", 123
        )

        self.assertEqual(artifacts, [{"id": 31}])
        self.assertEqual(len(calls), 1)
        self.assertTrue(
            calls[0].endswith(
                "/runs/123/artifacts?per_page=100&page=1"
            )
        )

if __name__ == "__main__":
    unittest.main()
