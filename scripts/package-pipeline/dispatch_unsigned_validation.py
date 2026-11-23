#!/usr/bin/env python3
"""Request protected signing approval after fresh owner-merge review.

Only a verified owner-approved merge may request protected signing approval.
Dispatch cannot grant signing approval or publish packages.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from evaluate_validation import REPOSITORY, evaluate, historical_identity
from github_validation_history import github_api
from package_fingerprint import fingerprint
from release_approval_policy import verify as verify_approval_policy
from select_package_validation import SUPPORTED, TEMPLATE_PACKAGES, workflow_file

SHA = re.compile(r"[0-9a-f]{40}\Z")
REVIEWER = Path(__file__).with_name('merged_selection_validation.py')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def permitted_changes(package, paths):
    """Reject unrelated changes riding along with a source selection."""
    require(isinstance(paths, set) and bool(paths),
            'Missing commit diff evidence')
    require('arch/packages/manifest.json' in paths,
            'Source selection must change the manifest')
    if package in TEMPLATE_PACKAGES:
        require(paths == {'arch/packages/manifest.json'},
                'Generated-recipe selection must change only the manifest')
    else:
        allowed = {'arch/packages/manifest.json',
                   'tests/package-pipeline/test_source_contract.py'}
        for path in paths:
            require(path in allowed or path.startswith(f'arch/{package}/'),
                    f'Unrelated file in source-selection commit: {path}')
        require(any(path.startswith(f'arch/{package}/') for path in paths),
                'Fixed-recipe selection must update package recipe inputs')


def request(plan, manifest, paths, history_decision):
    """Return an allowed dispatch request or skip, without side effects."""
    require(isinstance(plan, dict) and plan.get('decision') == 'review_validation',
            'No authorized merged selection')
    require(plan.get('validation_dispatched') is False and
            plan.get('publication_authorized') is False,
            'Unexpected prior dispatch or publication authorization')
    package = plan.get('package')
    revision = plan.get('revision')
    require(package in SUPPORTED and isinstance(revision, str)
            and SHA.fullmatch(revision), 'Invalid package or main revision')
    require(isinstance(manifest, dict) and
            isinstance(manifest.get('packages'), dict), 'Malformed manifest')
    config = manifest['packages'].get(package)
    require(isinstance(config, dict) and
            config.get('status') == 'approved' and
            config.get('auto_publish') is False and
            config.get('source_ref') == plan.get('selected'),
            'Current manifest no longer matches approved selection')
    permitted_changes(package, paths)
    require(plan.get('workflow') == workflow_file(package),
            'Unexpected publisher workflow')

    expected = {'publish': False}
    if package == 'noctalia-custom':
        expected['source_ref'] = config['source_ref']
    elif package == 'noctalia-greeter-t4t3z0r':
        expected['source_tag'] = config['source_ref']
    elif package == 'gameshell':
        require(config.get('tracking_ref') == 'refs/tags/latest',
                'GameShell tracking ref changed')
        expected['source_ref'] = 'latest'
    require(plan.get('inputs') == expected,
            'Merged approval contains unexpected publisher inputs')

    require(history_decision in ('needs_validation', 'in_flight',
                                 'validated', 'published', 'manual_review'),
            'Unknown or incomplete validation ledger decision')
    result = {'package': package, 'revision': revision,
              'workflow': workflow_file(package),
              'validation_decision': history_decision,
              'dispatch_requested': False}
    if history_decision in ('in_flight', 'published', 'manual_review'):
        return result

    # This requests the existing protected environment's approval.
    # It does not approve signing or provide signing secrets.
    payload = {'ref': 'main', 'inputs': {'publish': 'true',
               'expected_revision': revision}}
    for key, value in expected.items():
        if key != 'publish':
            payload['inputs'][key] = value
    return {**result, 'request': payload}


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def read_main_sha():
    data = github_api(f'repos/{REPOSITORY}/branches/main')
    require(isinstance(data, dict) and
            isinstance(data.get('commit'), dict),
            'Malformed live main branch response')
    sha = data['commit'].get('sha')
    require(isinstance(sha, str) and SHA.fullmatch(sha),
            'Malformed live main branch revision')
    return sha


def fresh_merge_plan(event_path):
    raw = subprocess.check_output(
        [sys.executable, str(REVIEWER), str(event_path)], text=True)
    result = json.loads(raw)
    require(isinstance(result, dict), 'Malformed merged-selection plan')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('plan', type=Path)
    parser.add_argument('event', type=Path)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    event = json.loads(args.event.read_text())
    original_plan = json.loads(args.plan.read_text())
    revision = event.get('after')
    before = event.get('before')

    require(event.get('ref') == 'refs/heads/main' and
            event.get('repository', {}).get('full_name') == REPOSITORY and
            event.get('sender', {}).get('login') == 'T4T3Z0R' and
            event.get('forced') is False and event.get('deleted') is False,
            'Untrusted production push event')
    require(isinstance(before, str) and SHA.fullmatch(before) and
            isinstance(revision, str) and SHA.fullmatch(revision) and
            before != revision, 'Invalid production revision pair')
    require(git(root, 'rev-parse', 'HEAD').decode().strip() == revision and
            revision == os.environ.get('GITHUB_SHA'),
            'Checkout does not match triggering main revision')
    require(original_plan.get('revision') == revision,
            'Handoff revision does not match triggering commit')
    require(read_main_sha() == revision, 'Production main moved before ledger check')
    paths = {p.decode() for p in
             git(root, 'diff', '--no-renames', '--name-only', '-z', before, revision)
             .split(b'\0') if p}
    manifest = json.loads((root / 'arch/packages/manifest.json').read_text())
    package = original_plan.get('package')
    require(package in SUPPORTED, 'Unknown package in handoff')

    # First independently query complete validation history.
    target = fingerprint(root, revision, package)
    ledger = evaluate(
        github_api, REPOSITORY, package, target,
        lambda sha, name: historical_identity(root, sha, name))
    result = request(original_plan, manifest, paths, ledger['decision'])
    if 'request' not in result:
        print(json.dumps(result, sort_keys=True))
        return

    # Repeat the real merge/approval review after ledger history retrieval.
    require(read_main_sha() == revision,
            'Production main moved before final approval review')
    require(fresh_merge_plan(args.event) == original_plan,
            'Live source-selection approval changed before dispatch')
    require(read_main_sha() == revision,
            'Production main moved before dispatch')

    # Refuse automated approval requests if the live signing gate
    # differs from the required owner-only protection policy.
    verify_approval_policy(github_api)
    require(read_main_sha() == revision,
            'Production main moved after signing policy review')

    subprocess.run(
        ['gh', 'api', '--method', 'POST',
         f'repos/{REPOSITORY}/actions/workflows/{result["workflow"]}/dispatches',
         '--input', '-'],
        input=json.dumps(result['request']), text=True,
        capture_output=True, check=True)
    result['dispatch_requested'] = True
    print(json.dumps(result, sort_keys=True))
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as f:
            f.write('## Guarded protected release-approval request\n\n')
            f.write(f'Package: `{package}`\n\n')
            f.write(f'Revision: `{revision}`\n\n')
            f.write(f'Workflow: `{result["workflow"]}`\n\n')
            f.write('Requested `publish: true`. Human signing approval remains required.\n')


if __name__ == '__main__':
    main()
