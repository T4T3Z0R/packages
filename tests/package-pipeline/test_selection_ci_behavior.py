import copy
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"

REPO = "T4T3Z0R/packages"
BASE = "a" * 40
HEAD = "b" * 40
CANDIDATE = "c" * 40
PACKAGE = "noctalia-custom"
BRANCH = "source-selection/issue-26-noctalia-custom"

TITLE = f"Package candidate: {PACKAGE} @ {CANDIDATE}"

MARKER = (
    "<!-- t4t3z0r:source-selection:v1 "
    f"issue=26 package={PACKAGE} "
    f"candidate={CANDIDATE} -->"
)

MOCK_GH = '''
import json
import os
import sys
from pathlib import Path

root = Path(os.environ["MOCK_ROOT"])
data = json.loads((root / "responses.json").read_text())
args = sys.argv[1:]

if args[:2] == ["workflow", "run"]:
    with (root / "dispatch.jsonl").open("a") as log:
        log.write(json.dumps(args) + "\\n")
    sys.exit(data.get("dispatch_exit", 0))

if not args or args[0] != "api":
    sys.exit("Unexpected gh invocation")

endpoint = args[1]

if endpoint not in data["api"]:
    sys.exit("Unexpected API endpoint: " + endpoint)

value = data["api"][endpoint]

if "--jq" in args:
    query = args[args.index("--jq") + 1]
    for key in query.lstrip(".").split("."):
        value = value[key]
    print(value)
else:
    print(json.dumps(value))
'''


def fixture():
    issue = {
        "number": 26,
        "id": 100,
        "state": "open",
        "title": TITLE,
        "body": "Approved candidate evidence",
        "user": {"login": "github-actions[bot]"},
        "labels": [{"name": "candidate:approved"}],
    }

    event = {
        "action": "labeled",
        "label": {"name": "candidate:approved"},
        "sender": {"login": "T4T3Z0R"},
        "issue": copy.deepcopy(issue),
    }

    pr = {
        "state": "open",
        "draft": True,
        "merged": False,
        "user": {"login": "github-actions[bot]"},
        "head": {
            "repo": {"full_name": REPO},
            "ref": BRANCH,
            "sha": HEAD,
        },
        "base": {
            "repo": {"full_name": REPO},
            "ref": "main",
            "sha": BASE,
        },
        "body": MARKER,
    }

    api = {
        f"repos/{REPO}/branches/main": {
            "commit": {"sha": BASE},
        },
        f"repos/{REPO}/issues/26": issue,
        f"repos/{REPO}/pulls/27": pr,
        f"repos/{REPO}/commits/{HEAD}": {
            "parents": [{"sha": BASE}],
        },
        f"repos/{REPO}/git/ref/heads/{BRANCH}": {
            "object": {"sha": HEAD},
        },
    }

    return event, {"api": api}


class SelectionCIBehaviorTests(unittest.TestCase):
    def setUp(self):
        source = (
            WORKFLOWS /
            "review-package-candidate-approval.yml"
        ).read_text()

        dispatcher = source.split(
            "\n  dispatch-selection-ci:", 1
        )[1]

        self.script = textwrap.dedent(
            dispatcher.split("        run: |\n", 1)[1]
        )

    def run_dispatcher(self, mutate=None):
        event, data = fixture()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            env = {
                "PATH": (
                    str(root) + os.pathsep +
                    os.environ["PATH"]
                ),
                "MOCK_ROOT": str(root),
                "GITHUB_EVENT_NAME": "issues",
                "GITHUB_REPOSITORY": REPO,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_ACTOR": "T4T3Z0R",
                "GITHUB_TRIGGERING_ACTOR": "T4T3Z0R",
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_SHA": BASE,
                "GITHUB_EVENT_PATH": str(root / "event.json"),
                "GITHUB_STEP_SUMMARY": str(root / "summary"),
                "PR_NUMBER": "27",
                "SELECTION_BRANCH": BRANCH,
                "EXPECTED_REVISION": HEAD,
            }

            if mutate:
                mutate(event, data, env)

            (root / "event.json").write_text(
                json.dumps(event)
            )

            (root / "responses.json").write_text(
                json.dumps(data)
            )

            gh = root / "gh"

            gh.write_text(
                f"#!{sys.executable}\n" + MOCK_GH
            )

            gh.chmod(0o755)

            result = subprocess.run(
                ["bash", "-c", self.script],
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
            )

            log = root / "dispatch.jsonl"

            dispatches = (
                [
                    json.loads(line)
                    for line in log.read_text().splitlines()
                ]
                if log.exists() else []
            )

            return result, dispatches

    def test_valid_candidate_dispatches_exact_revision(self):
        result, dispatches = self.run_dispatcher()

        self.assertEqual(
            result.returncode, 0, result.stderr
        )

        self.assertEqual(dispatches, [[
            "workflow", "run",
            "test-package-pipeline.yml",
            "--repo", REPO,
            "--ref", BRANCH,
            "-f", f"expected_revision={HEAD}",
        ]])

    def test_untrusted_events_never_dispatch(self):
        cases = {
            "wrong_actor": {
                "GITHUB_ACTOR": "stranger",
            },
            "wrong_triggering_actor": {
                "GITHUB_TRIGGERING_ACTOR": "stranger",
            },
            "wrong_repository": {
                "GITHUB_REPOSITORY": "other/repo",
            },
            "wrong_event": {
                "GITHUB_EVENT_NAME": "push",
            },
            "wrong_ref": {
                "GITHUB_REF": "refs/heads/other",
            },
            "rerun": {
                "GITHUB_RUN_ATTEMPT": "2",
            },
            "wrong_branch": {
                "SELECTION_BRANCH": "untrusted",
            },
            "invalid_revision": {
                "EXPECTED_REVISION": "main",
            },
            "invalid_pr": {
                "PR_NUMBER": "invalid",
            },
        }

        for name, updates in cases.items():
            with self.subTest(case=name):
                result, dispatches = self.run_dispatcher(
                    lambda e, d, env: env.update(updates)
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(dispatches, [])

    def test_untrusted_metadata_never_dispatches(self):
        issue = f"repos/{REPO}/issues/26"
        pr = f"repos/{REPO}/pulls/27"
        main = f"repos/{REPO}/branches/main"
        commit = f"repos/{REPO}/commits/{HEAD}"
        branch = f"repos/{REPO}/git/ref/heads/{BRANCH}"

        cases = {
            "approval_removed": lambda e, d, v:
                d["api"][issue].update(labels=[]),

            "conflicting_approval": lambda e, d, v:
                d["api"][issue]["labels"].append(
                    {"name": "candidate:denied"}
                ),

            "closed_issue": lambda e, d, v:
                d["api"][issue].update(state="closed"),

            "edited_issue": lambda e, d, v:
                d["api"][issue].update(body="edited"),

            "wrong_sender": lambda e, d, v:
                e["sender"].update(login="stranger"),

            "wrong_label": lambda e, d, v:
                e["label"].update(name="candidate:denied"),

            "closed_pr": lambda e, d, v:
                d["api"][pr].update(state="closed"),

            "non_draft_pr": lambda e, d, v:
                d["api"][pr].update(draft=False),

            "wrong_pr_author": lambda e, d, v:
                d["api"][pr]["user"].update(login="stranger"),

            "wrong_marker": lambda e, d, v:
                d["api"][pr].update(body="Unrelated PR"),

            "wrong_head": lambda e, d, v:
                d["api"][pr]["head"].update(sha="d"*40),

            "wrong_head_repo": lambda e, d, v:
                d["api"][pr]["head"]["repo"].update(
                    full_name="other/repo"
                ),

            "wrong_base": lambda e, d, v:
                d["api"][pr]["base"].update(sha="d"*40),

            "wrong_parent": lambda e, d, v:
                d["api"][commit]["parents"][0].update(
                    sha="d"*40
                ),

            "multiple_parents": lambda e, d, v:
                d["api"][commit]["parents"].append(
                    {"sha": "d"*40}
                ),

            "main_moved": lambda e, d, v:
                d["api"][main]["commit"].update(
                    sha="d"*40
                ),

            "branch_moved": lambda e, d, v:
                d["api"][branch]["object"].update(
                    sha="d"*40
                ),

            "missing_api_evidence": lambda e, d, v:
                d["api"].pop(pr),
        }

        for name, mutate in cases.items():
            with self.subTest(case=name):
                result, dispatches = self.run_dispatcher(
                    mutate
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(dispatches, [])

    def test_dispatch_api_failure_is_not_success(self):
        result, dispatches = self.run_dispatcher(
            lambda e, d, v: d.update(dispatch_exit=17)
        )

        self.assertEqual(result.returncode, 17)
        self.assertEqual(len(dispatches), 1)

    def test_receiver_rejects_wrong_revision(self):
        receiver = (
            WORKFLOWS / "test-package-pipeline.yml"
        ).read_text()

        step = receiver.split(
            "      - name: Verify dispatched revision",
            1
        )[1].split("      - name:", 1)[0]

        script = textwrap.dedent(
            step.split("        run: |\n", 1)[1]
        )

        for expected, actual, success in (
            (HEAD, HEAD, True),
            (HEAD, BASE, False),
            ("main", HEAD, False),
            ("", HEAD, False),
        ):
            with self.subTest(expected=expected, actual=actual):
                env = {
                    "PATH": os.environ["PATH"],
                    "GITHUB_REPOSITORY": REPO,
                    "EXPECTED_REVISION": expected,
                    "GITHUB_SHA": actual,
                }

                result = subprocess.run(
                    ["bash", "-c", script],
                    env=env,
                    capture_output=True,
                    timeout=10,
                )

                self.assertEqual(
                    result.returncode == 0, success
                )


if __name__ == "__main__":
    unittest.main()
