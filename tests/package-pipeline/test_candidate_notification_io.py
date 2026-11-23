import json
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs
from types import SimpleNamespace
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/package-pipeline'))
from candidate_notification_io import (
    validate_targets, authorize, post_comment, send_pushover, deliver_batch,
)
from candidate_notification_state import TRUSTED_AUTHOR
TARGET = {'issue_number':42, 'package':'ghostty', 'candidate':'v1.5.0'}
SHA = 'a' * 40

class Fake:
    def __init__(self, targets=None):
        targets = targets or [TARGET]
        self.rows = [{**target, 'state':'unclaimed', 'decision':None,
                      'deliverable':True, 'run_id':None} for target in targets]
        self.posts = []
        self.sends = 0
        self.fail = None
        self.stale = False
    def inspect(self):
        if self.fail == 'read': raise RuntimeError('Read failed')
        result = [dict(r) for r in self.rows]
        if self.stale and self.posts:
            result[0].update(state='unclaimed', deliverable=True, run_id=None)
        return result
    def post(self, state, number, package, candidate, run_id, receipt=None):
        self.posts.append(state)
        if self.fail == state: raise RuntimeError('Write failed')
        row = next(r for r in self.rows if r['issue_number']==number)
        row.update(state=state, deliverable=False, run_id=run_id)
        if receipt is not None: row['pushover_request'] = receipt
    def send(self, n,p,c):
        self.sends += 1
        if self.fail == 'send': raise TimeoutError('timed out')
        if self.fail == 'rejected': return {'http_status':200,'status':0,'request':'abc-123'}
        return {'http_status':200,'status':1,'request':'abc-123'}
    def run(self, targets=None):
        return deliver_batch(targets or [TARGET], 100,
                             inspect=self.inspect, post=self.post, send=self.send)

class AdapterTests(unittest.TestCase):
    def test_happy_path(self):
        fake = Fake()
        result = fake.run()
        self.assertEqual(result[0]['pushover_request'], 'abc-123')
        self.assertEqual(fake.posts, ['claimed', 'accepted'])
        self.assertEqual(fake.sends, 1)
    def test_rerun_never_sends(self):
        fake = Fake(); fake.run()
        with self.assertRaises(ValueError): fake.run()
        self.assertEqual(fake.sends, 1)
    def test_ineligible_batch_preflights_before_writes(self):
        second = {'issue_number':43,'package':'wezterm','candidate':'v1.2.0'}
        fake = Fake([TARGET,second]); fake.rows[1]['decision'] = 'candidate:approved'
        with self.assertRaisesRegex(ValueError, 'ineligible'):
            fake.run([TARGET,second])
        self.assertEqual(fake.posts, [])
        self.assertEqual(fake.sends, 0)
    def test_claim_failure_never_sends(self):
        fake=Fake();fake.fail='claimed'
        with self.assertRaises(RuntimeError):fake.run()
        self.assertEqual(fake.sends, 0)
    def test_read_lag_after_claim_never_sends(self):
        fake=Fake();fake.stale=True
        with self.assertRaises(ValueError):fake.run()
        self.assertEqual(fake.sends, 0)
    def test_send_timeout_stays_claimed(self):
        fake=Fake();fake.fail='send'
        with self.assertRaises(TimeoutError):fake.run()
        self.assertEqual(fake.rows[0]['state'], 'claimed')
        self.assertEqual(fake.posts, ['claimed'])
    def test_pushover_rejection_stays_claimed(self):
        fake=Fake();fake.fail='rejected'
        with self.assertRaises(ValueError):fake.run()
        self.assertEqual(fake.rows[0]['state'],'claimed')
    def test_ack_failure_not_retried(self):
        fake=Fake();fake.fail='accepted'
        with self.assertRaises(RuntimeError):fake.run()
        self.assertEqual(fake.sends,1)
        with self.assertRaises(ValueError):fake.run()
        self.assertEqual(fake.sends,1)
    def test_invalid_targets_rejected(self):
        for batch in ('bad', [{**TARGET, 'issue_number':True}], [TARGET,TARGET],
                      [{**TARGET,'extra':1}], [{**TARGET,'candidate':'x;rm'}]):
            with self.subTest(batch=batch):
                with self.assertRaises(ValueError): validate_targets(batch)
    def test_authorization(self):
        env = {
            'CANDIDATE_NOTIFICATION_WRITE_ENABLED':'1',
            'GITHUB_EVENT_NAME':'schedule',
            'GITHUB_REPOSITORY':'T4T3Z0R/packages',
            'GITHUB_REF':'refs/heads/main',
            'GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_RUN_ID':'100',
            'GITHUB_SHA':SHA,
            'GH_TOKEN':'test',
            'PUSHOVER_APP_TOKEN':'test',
            'PUSHOVER_USER_KEY':'test',
        }
        self.assertEqual(authorize(env,SHA,SHA), 100)
        for key, value in [('GITHUB_EVENT_NAME','workflow_dispatch'),
                           ('GITHUB_RUN_ATTEMPT','2'),
                           ('GITHUB_REF','refs/heads/feature')]:
            with self.subTest(key=key):
                tampered = {**env,key:value}
                with self.assertRaises(ValueError): authorize(tampered,SHA,SHA)
        with self.assertRaises(ValueError): authorize(env,SHA,'b'*40)
    def test_github_comment_is_single_write(self):
        commands = []
        def runner(command, **kwargs):
            commands.append(command)
            body=command[-1].removeprefix('body=')
            return SimpleNamespace(stdout=json.dumps({'id':24,'body':body,
                    'user':{'login':TRUSTED_AUTHOR}}))
        post_comment('accepted',42,'ghostty','v1.5.0',100,'abc-123',runner=runner)
        self.assertEqual(len(commands),1)
        self.assertEqual(commands[0][2:4],['--method','POST'])
        self.assertIn('abc-123', commands[0][-1])
    def test_new_ack_requires_receipt(self):
        with self.assertRaisesRegex(ValueError, "receipt required"):
            post_comment("accepted",42,"ghostty","v1.5.0",100)

    def test_github_uncertain_response_does_not_retry(self):
        calls=[]
        def runner(command,**kw):
            calls.append(command)
            return SimpleNamespace(stdout='{}')
        with self.assertRaises(ValueError):
            post_comment('claimed',42,'ghostty','v1.5.0',100,runner=runner)
        self.assertEqual(len(calls),1)
    def test_pushover_one_post_and_receipt(self):
        calls=[]
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*a):return False
            def read(self,n):return b'{"status":1,"request":"abc-123"}'
        def opener(req, timeout):
            calls.append(req)
            self.assertEqual(timeout,15)
            fields=parse_qs(req.data.decode('utf-8'))
            self.assertEqual(fields['token'],['secret-app'])
            self.assertEqual(fields['user'],['secret-user'])
            self.assertEqual(req.get_method(),'POST')
            return Response()
        result=send_pushover(42,'ghostty','v1.5.0',app_token='secret-app',
                             user_key='secret-user',opener=opener)
        self.assertEqual(result,{'http_status':200,'status':1,'request':'abc-123'})
        self.assertEqual(len(calls),1)
    def test_empty_batch_never_reads(self):
        fake=Fake()
        self.assertEqual(deliver_batch([], 100, inspect=lambda: 1/0, post=fake.post, send=fake.send), [])

if __name__=='__main__': unittest.main()
