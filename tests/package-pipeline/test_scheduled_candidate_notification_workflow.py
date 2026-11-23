import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/package-pipeline'))
from candidate_review import plan
from candidate_notification_reader import inspect_outbox
from candidate_notification_state import ISSUE_MARKER, TRUSTED_AUTHOR

WORKFLOW=ROOT/'.github/workflows/check-package-upstream.yml'
CI=ROOT/'.github/workflows/test-package-pipeline.yml'
MANIFEST=ROOT/'arch/packages/manifest.json'

class ScheduledNotificationTests(unittest.TestCase):
    def setUp(self):
        self.text=WORKFLOW.read_text()
        self.assertEqual(self.text.count('  write-reviews:\n'),1)
        self.writer=self.text.split('  write-reviews:\n',1)[1]
        marker='      - name: Notify verified new candidate reviews\n'
        self.assertEqual(self.writer.count(marker),1)
        self.step=self.writer.split(marker,1)[1].split(
            '      - name: Upload scheduled review evidence\n',1
        )[0]

    def test_schedule_only_and_serialization(self):
        self.assertIn("if: ${{ github.event_name == 'schedule' }}",self.writer)
        self.assertIn('group: package-candidate-issue-writes',self.writer)
        self.assertIn('cancel-in-progress: false',self.writer)
        self.assertIn('queue: max',self.writer)
        self.assertIn('issues: write',self.writer)
        self.assertIn('test "$GITHUB_RUN_ATTEMPT" = 1',self.writer)

    def test_verified_issue_batch_precedes_send(self):
        self.assertLess(
            self.writer.index('name: Verify every issue against current GitHub history'),
            self.writer.index('name: Notify verified new candidate reviews')
        )
        self.assertIn('created-review-issues.json | tee notification-result.json',self.step)
        self.assertNotIn('upstream-report.json | tee notification-result.json',self.step)

    def test_only_adapter_gets_notification_credentials(self):
        self.assertIn('GH_TOKEN: ${{ github.token }}',self.step)
        self.assertIn('PUSHOVER_APP_TOKEN: ${{ secrets.PUSHOVER_APP_TOKEN }}',self.step)
        self.assertIn('PUSHOVER_USER_KEY: ${{ secrets.PUSHOVER_USER_KEY }}',self.step)
        self.assertIn('CANDIDATE_NOTIFICATION_WRITE_ENABLED: "1"',self.step)
        self.assertEqual(self.writer.count('CANDIDATE_NOTIFICATION_WRITE_ENABLED:'),1)

    def test_fresh_branch_guards_in_send_step(self):
        for required in (
            'test "$GITHUB_EVENT_NAME" = schedule',
            'test "$GITHUB_REPOSITORY" = T4T3Z0R/packages',
            'test "$GITHUB_REF" = refs/heads/main',
            'test "$GITHUB_RUN_ATTEMPT" = 1',
            'gh api "repos/$GITHUB_REPOSITORY/branches/main"',
            ')" = "$GITHUB_SHA"',
        ):
            self.assertIn(required,self.step)

    def test_manual_discovery_remains_read_only(self):
        discovery=self.text.split('  discover:\n',1)[1].split('  write-reviews:\n',1)[0]
        self.assertNotIn('candidate_notification_io.py',discovery)
        self.assertNotIn('CANDIDATE_NOTIFICATION_WRITE_ENABLED',discovery)
        self.assertNotIn('PUSHOVER_APP_TOKEN',discovery)

    def test_preserve_evidence_and_human_review_boundary(self):
        self.assertIn('notification-result.json',self.writer)
        self.assertIn('No source selections, builds, signing, or publication performed.',self.writer)
        self.assertNotIn('or notifications performed.',self.writer)
        self.assertIn('test_scheduled_candidate_notification_workflow.py',CI.read_text())
        self.assertLess(
            self.writer.index('name: Notify verified new candidate reviews'),
            self.writer.index('name: Upload scheduled review evidence')
        )

    def test_issue_planner_marker_reaches_outbox(self):
        manifest=json.loads(MANIFEST.read_text())
        self.assertEqual(manifest['packages']['ghostty']['status'],'approved')
        self.assertIs(manifest['packages']['ghostty']['auto_publish'],False)
        proposals=plan([{
            'package':'ghostty', 'status':'update',
            'selected':'v1.4.0', 'candidate':'v1.5.0',
        }])
        self.assertEqual(len(proposals),1)
        self.assertEqual(proposals[0]['body'].count(ISSUE_MARKER),1)
        issue={
            'id':900, 'number':42, 'title':proposals[0]['title'],
            'body':proposals[0]['body'], 'state':'open',
            'comments':0, 'labels':[], 'user':{'login':TRUSTED_AUTHOR},
        }
        def api(endpoint):
            if endpoint.startswith('repos/T4T3Z0R/packages/issues?'):
                return [issue]
            if endpoint=='repos/T4T3Z0R/packages/issues/42/comments?per_page=100&page=1':
                return []
            raise AssertionError(f'Unexpected API read: {endpoint}')
        result=inspect_outbox(manifest,api)
        self.assertEqual(len(result),1)
        self.assertTrue(result[0]['deliverable'])
        self.assertEqual(result[0]['state'],'unclaimed')

if __name__=='__main__':
    unittest.main()
