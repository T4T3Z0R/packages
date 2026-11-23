import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/package-pipeline"))

from verify_scheduled_snapshot import verify


MANIFEST = {
    "packages": {
        "ghostty": {
            "status": "approved",
            "auto_publish": False,
            "source_ref": "v1.4.0",
            "release_policy": "stable-git-tag",
            "upstream": "ghostty-org/ghostty",
        },
        "syncthing": {
            "status": "approved",
            "auto_publish": False,
            "source_ref": "v2.1.7",
            "release_policy": "stable-tag",
            "upstream": "syncthing/syncthing",
        },
        "yazi": {"status": "candidate"},
    }
}

REPORT = [
    {
        "package": "ghostty",
        "status": "update",
        "selected": "v1.4.0",
        "candidate": "v1.5.0",
        "policy": "stable-git-tag",
        "upstream": "ghostty-org/ghostty",
    },
    {
        "package": "syncthing",
        "status": "unchanged",
        "selected": "v2.1.7",
        "candidate": "v2.1.7",
        "policy": "stable-tag",
        "upstream": "syncthing/syncthing",
    },
]


class SnapshotTests(unittest.TestCase):
    def test_identical_snapshots(self):
        self.assertEqual(
            verify(MANIFEST, REPORT, copy.deepcopy(REPORT)), 2
        )

    def test_candidate_changes(self):
        fresh = copy.deepcopy(REPORT)
        fresh[0]["candidate"] = "v1.6.0"
        with self.assertRaisesRegex(ValueError, "Upstream changed"):
            verify(MANIFEST, REPORT, fresh)

    def test_status_changes(self):
        fresh = copy.deepcopy(REPORT)
        fresh[0]["status"] = "blocked"
        with self.assertRaisesRegex(ValueError, "Upstream changed"):
            verify(MANIFEST, REPORT, fresh)

    def test_missing_package(self):
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            verify(MANIFEST, REPORT, REPORT[:1])

    def test_duplicate_package(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            verify(MANIFEST, REPORT, REPORT + [REPORT[0]])

    def test_unapproved_package(self):
        bad = copy.deepcopy(REPORT)
        bad[0]["package"] = "yazi"
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            verify(MANIFEST, REPORT, bad)

    def test_manifest_source_mismatch(self):
        bad = copy.deepcopy(MANIFEST)
        bad["packages"]["ghostty"]["source_ref"] = "v1.3.0"
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            verify(bad, REPORT, REPORT)

    def test_publication_policy_fails_closed(self):
        bad = copy.deepcopy(MANIFEST)
        bad["packages"]["ghostty"]["auto_publish"] = True
        with self.assertRaisesRegex(ValueError, "publication"):
            verify(bad, REPORT, REPORT)


if __name__ == "__main__":
    unittest.main()
