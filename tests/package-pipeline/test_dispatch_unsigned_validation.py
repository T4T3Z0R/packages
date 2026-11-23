import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/package-pipeline'))
from dispatch_unsigned_validation import request, permitted_changes

MANIFEST = json.loads((ROOT / 'arch/packages/manifest.json').read_text())
REV = 'f' * 40
TEMPLATES = {
    'gameshell': ('publish-gameshell.yml', {'publish': False, 'source_ref': 'latest'}),
    'noctalia-custom': ('publish-noctalia-custom.yml',
                        {'publish': False, 'source_ref': MANIFEST['packages']['noctalia-custom']['source_ref']}),
    'noctalia-greeter-t4t3z0r': ('publish-noctalia-greeter.yml',
                {'publish': False, 'source_tag': MANIFEST['packages']['noctalia-greeter-t4t3z0r']['source_ref']}),
}
FIXED = ('ghostty', 'keepassxc', 'syncthing', 'wezterm')


def approved_plan(package, inputs, workflow):
    return {'decision': 'review_validation', 'revision': REV,
            'package': package, 'selected': MANIFEST['packages'][package]['source_ref'],
            'workflow': workflow, 'inputs': inputs,
            'validation_dispatched': False, 'publication_authorized': False}


def paths_for(package):
    base = {'arch/packages/manifest.json'}
    if package in FIXED:
        base.add(f'arch/{package}/PKGBUILD')
    return base


class DispatchTests(unittest.TestCase):
    def test_all_seven_dispatch_exact_revision_and_publish_false(self):
        options = dict(TEMPLATES)
        options.update({name: (f'publish-{name}.yml', {'publish': False})
                        for name in FIXED})
        for name, (workflow, inputs) in options.items():
            with self.subTest(package=name):
                plan = approved_plan(name, inputs, workflow)
                result = request(plan, MANIFEST, paths_for(name), 'needs_validation')
                self.assertEqual(result['request']['ref'], 'main')
                self.assertEqual(result['request']['inputs']['publish'], 'false')
                self.assertEqual(result['request']['inputs']['expected_revision'], REV)
                self.assertEqual(result['workflow'], workflow)
                for key, value in inputs.items():
                    if key != 'publish':
                        self.assertEqual(result['request']['inputs'][key], value)
                self.assertFalse(result['dispatch_requested'])

    def test_validated_and_in_flight_never_dispatch(self):
        for decision in ('validated', 'in_flight'):
            with self.subTest(decision=decision):
                plan = approved_plan('ghostty', {'publish': False},
                                     'publish-ghostty.yml')
                result = request(plan, MANIFEST, paths_for('ghostty'), decision)
                self.assertNotIn('request', result)
                self.assertFalse(result['dispatch_requested'])

    def test_fails_closed_for_untrusted_input(self):
        plan = approved_plan('gameshell', TEMPLATES['gameshell'][1],
                             'publish-gameshell.yml')
        mutations = (
            lambda p: p.update(decision='no_source_change'),
            lambda p: p.update(validation_dispatched=True),
            lambda p: p.update(publication_authorized=True),
            lambda p: p.update(revision='malformed'),
            lambda p: p.update(workflow='publish-ghostty.yml'),
            lambda p: p.update(selected='0'*40),
            lambda p: p['inputs'].update(publish=True),
            lambda p: p['inputs'].update(expected_revision=REV),
        )
        for change in mutations:
            with self.subTest(change=str(change)):
                other = copy.deepcopy(plan)
                change(other)
                with self.assertRaises(ValueError):
                    request(other, MANIFEST, paths_for('gameshell'), 'needs_validation')

    def test_diff_scope_restricts_unrelated_changes(self):
        for name in TEMPLATES:
            with self.subTest(package=name):
                permitted_changes(name, {'arch/packages/manifest.json'})
                with self.assertRaises(ValueError):
                    permitted_changes(name, {'arch/packages/manifest.json',
                                             f'arch/{name}/PKGBUILD.in'})
        permitted_changes('wezterm', {'arch/packages/manifest.json',
                                      'arch/wezterm/PKGBUILD',
                                      'tests/package-pipeline/test_source_contract.py'})
        with self.assertRaises(ValueError):
            permitted_changes('wezterm', {'arch/packages/manifest.json',
                                          'scripts/package-pipeline/unsafe.py',
                                          'arch/wezterm/PKGBUILD'})
        with self.assertRaises(ValueError):
            permitted_changes('wezterm', {'arch/packages/manifest.json'})

    def test_invalid_history_decision_rejected(self):
        plan = approved_plan('gameshell', TEMPLATES['gameshell'][1],
                             'publish-gameshell.yml')
        with self.assertRaises(ValueError):
            request(plan, MANIFEST, paths_for('gameshell'), 'unknown')

    def test_publisher_revision_inputs_and_guards_exist(self):
        for name in (*TEMPLATES, *FIXED):
            workflow = ('publish-noctalia-greeter.yml'
                        if name == 'noctalia-greeter-t4t3z0r'
                        else f'publish-{name}.yml')
            text = (ROOT / '.github/workflows' / workflow).read_text()
            self.assertIn('      expected_revision:', text)
            self.assertIn('default: ""', text)
            self.assertEqual(text.count('name: Verify requested infrastructure revision'), 1)
            self.assertIn('test "$GITHUB_SHA" = "$EXPECTED_REVISION"', text)
            self.assertIn('inputs.publish == true', text)

    def test_gameshell_manual_validation_not_skipped_for_existing_asset(self):
        source = (ROOT / '.github/workflows/publish-gameshell.yml').read_text()
        self.assertIn('case "$REQUESTED_PUBLISH" in', source)
        self.assertIn('false)', source)
        self.assertIn('update=true', source)
        self.assertIn('if [[ "$package_exists" == true ]]', source)
        self.assertIn('github.event_name == \'workflow_dispatch\'', source)
        self.assertNotIn('github.event_name == \'schedule\'', source)

    def test_dispatch_permission_separate_from_read_only_verifier(self):
        workflow = (ROOT / '.github/workflows/package-validation-controller.yml').read_text()
        reader, writer = workflow.split('\n  dispatch-unsigned-validation:', 1)
        self.assertIn('needs.verify-merged-selection.outputs.decision', writer)
        self.assertNotIn('actions: write', reader)
        self.assertNotIn('contents: write', workflow)
        self.assertIn('actions: write', writer)
        self.assertIn('GITHUB_RUN_ATTEMPT', writer)
        self.assertNotIn('publish=true', writer)
        self.assertNotIn('gh workflow run', reader)
        self.assertIn('dispatch_unsigned_validation.py', writer)


if __name__ == '__main__':
    unittest.main()
