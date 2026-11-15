import unittest
from pathlib import Path

PACKAGE = "gameshell"

def package(version):
    return f"{PACKAGE}-{version}-1-any.pkg.tar.zst"


class HistoryPruningTests(unittest.TestCase):
    def test_version_ordering_contract(self):
        versions = ["1.9", "1.10", "2.0"]
        self.assertEqual(
            ["1.9", "1.10", "2.0"],
            versions,
        )
        self.assertNotEqual(sorted(versions), versions)

    def test_retention_count_contract(self):
        history = [
            package("1.0"),
            package("1.5"),
            package("1.9"),
            package("1.10"),
        ]

        self.assertEqual(len(history), 4)

        retain = 2
        expected_keep = {
            package("1.9"),
            package("1.10"),
        }
        expected_prune = {
            package("1.0"),
            package("1.5"),
        }

        self.assertEqual(len(expected_keep), retain)
        self.assertEqual(
            expected_keep | expected_prune,
            set(history),
        )

    def test_signatures_follow_packages(self):
        old = package("1.0")
        pair = {old, old + ".sig"}

        self.assertEqual(len(pair), 2)
        self.assertIn(old + ".sig", pair)


import importlib.util
from functools import cmp_to_key

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts/package-pipeline/plan-history-pruning.py"
)

spec = importlib.util.spec_from_file_location(
    "history_pruning_planner", SCRIPT
)
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


def compare_fixture(left, right):
    def parts(value):
        version, release = value.rsplit("-", 1)
        return tuple(int(x) for x in version.split(".")) + (
            int(release),
        )

    a, b = parts(left), parts(right)
    return (a > b) - (a < b)


def inventory(*versions):
    names = []
    for version in versions:
        name = package(version)
        names.extend((name, name + ".sig"))
    return names


class HistoryPlannerBehaviorTests(unittest.TestCase):
    def plan(self, names, retain=2):
        return planner.build_plan(
            names, PACKAGE, retain, compare=compare_fixture
        )

    def test_numeric_version_ordering(self):
        result = self.plan(
            inventory("1.0", "1.5", "1.9", "1.10")
        )
        self.assertEqual(
            [item["package"] for item in result["keep"]],
            [package("1.10"), package("1.9")],
        )
        self.assertEqual(
            [item["package"] for item in result["prune"]],
            [package("1.5"), package("1.0")],
        )
        self.assertTrue(result["dry_run"])

    def test_exact_retention_requires_no_pruning(self):
        result = self.plan(inventory("1.9", "1.10"))
        self.assertEqual(len(result["keep"]), 2)
        self.assertEqual(result["prune"], [])

    def test_orphaned_signature_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "Incomplete historical pair"
        ):
            self.plan([package("1.9") + ".sig"])

    def test_orphaned_package_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "Incomplete historical pair"
        ):
            self.plan([package("1.9")])

    def test_unexpected_asset_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "Unexpected history asset"
        ):
            self.plan(inventory("1.9") + ["notes.json"])

    def test_duplicate_inventory_asset_rejected(self):
        names = inventory("1.9")
        with self.assertRaisesRegex(
            ValueError, "Duplicate history release assets"
        ):
            self.plan(names + [names[0]])

    def test_duplicate_version_different_arch_rejected(self):
        names = inventory("1.9")
        other = "gameshell-1.9-1-x86_64.pkg.tar.zst"
        names.extend((other, other + ".sig"))

        with self.assertRaisesRegex(
            ValueError, "Duplicate historical package version"
        ):
            self.plan(names)

    def test_other_package_rejected(self):
        other = "gameshell-extra-1.9-1-any.pkg.tar.zst"
        with self.assertRaisesRegex(
            ValueError, "Unexpected history asset"
        ):
            self.plan([other, other + ".sig"])

    def test_zero_retention_with_history_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "History exists for zero-retention"
        ):
            self.plan(inventory("1.9"), retain=0)

    def test_empty_inventory(self):
        result = self.plan([])
        self.assertEqual(result["keep"], [])
        self.assertEqual(result["prune"], [])

    def test_invalid_retention_rejected(self):
        for value in (-1, True, "2"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError, "Invalid retention count"
                ):
                    self.plan([], retain=value)



import shutil


@unittest.skipUnless(
    shutil.which("vercmp"),
    "Requires Arch pacman vercmp",
)
class PacmanVersionComparisonTests(unittest.TestCase):
    def test_numeric_version_ordering(self):
        self.assertGreater(
            planner.compare_versions("1.10-1", "1.9-1"), 0
        )

    def test_package_release_ordering(self):
        self.assertGreater(
            planner.compare_versions("1.7.0-2", "1.7.0-1"), 0
        )

    def test_epoch_ordering(self):
        self.assertGreater(
            planner.compare_versions("1:1.0-1", "9.0-1"), 0
        )

    def test_equal_versions(self):
        self.assertEqual(
            planner.compare_versions("1.7.0-2", "1.7.0-2"), 0
        )

    def test_planner_uses_pacman_ordering(self):
        names = inventory("1.9", "1.10", "2.0")
        result = planner.build_plan(names, PACKAGE, 2)
        self.assertEqual(
            [item["package"] for item in result["keep"]],
            [package("2.0"), package("1.10")],
        )
        self.assertEqual(
            [item["package"] for item in result["prune"]],
            [package("1.9")],
        )


if __name__ == "__main__":
    unittest.main()
