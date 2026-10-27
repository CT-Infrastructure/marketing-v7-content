import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vale_wrapper', BASE / 'lint.py')
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)

# Complete-keyword policy: whitespace after Vale; off/on end at a word
# boundary, or a rule-name assignment. Punctuation after off/on is denied.
# Prefix words remain prose unless they themselves introduce an assignment.
BENIGN_DIRECTIVE_PREFIX_PROSE = (
    'Vale offers a local check.', 'Vale only checks local prose.',
    'VALE OFFERS a local check.', 'vAlE OnLy checks local prose.',
    'Vale offering useful feedback.', 'Vale ongoing local checks.',
    'Vale offline checks local prose.', 'Vale offsite checks local prose.',
    'Vale onward checks local prose.', 'Vale on_call checks local prose.',
)
REJECTED_DIRECTIVE_TEXT = (
    'vale off', 'VALE ON', 'vAlE oFf', 'vale   on', 'vale\toff',
    'vale\non', '<!-- vale off -->', '<!-- VALE ON -->',
    'vale off.', 'vale on,', 'vale off: Local.Guard', 'vale on!',
    'vale off(Local.Guard)', 'vale on/Local.Guard',
    'vale Local.Guard = NO', 'VALE Local.Guard=YES',
    'vale\tLocal.Guard  = NO', 'vale offline = NO',
)

class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.binary = self.root / 'vale'
        self.binary.write_bytes(b'synthetic-not-executable')
        self.sha = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        (self.root / 'safe.txt').write_text('Safe synthetic prose.', encoding='utf-8')

    def run_lint(self, name='safe.txt', sha=None):
        return wrapper.lint(self.binary, sha or self.sha, self.root, name)

    def assert_held(self, result):
        self.assertEqual(result['outbound_state'], 'HOLD')
        self.assertTrue(result['approval_required'])
        self.assertFalse(result['publication_authorized'])

    def test_clean_warning_and_redaction(self):
        for report, status in [(b'{}', 'lint_clean'),
                (json.dumps({'document.txt': [{'Check': 'Local.Guard', 'Severity': 'warning',
                'Line': 1, 'Match': 'SECRET_CANARY', 'Message': 'SECRET_CANARY'}]}).encode(), 'lint_findings')]:
            with patch.object(wrapper, 'bounded', side_effect=[(0,b'vale version 3.25.1\n',b''),(0,report,b'')]):
                result = self.run_lint()
            self.assertEqual(result['status'], status)
            self.assertNotIn('SECRET_CANARY', json.dumps(result))
            self.assert_held(result)

    def test_invalid_paths_encoding_size_directive_and_hash(self):
        for name in ['../escape.txt', '-option.txt', 'bad.md', 'missing.txt']:
            self.assertEqual(self.run_lint(name)['status'], 'failed')
        for data in [b'\xff', b'x' * (wrapper.MAX_INPUT + 1), b'vale off', b'\0']:
            (self.root / 'safe.txt').write_bytes(data)
            self.assertEqual(self.run_lint()['status'], 'failed')
        self.assertEqual(self.run_lint(sha='0'*64)['error_code'], 'executable_digest_mismatch')

    def test_symlink(self):
        link = self.root / 'link.txt'
        try:
            link.symlink_to(self.root / 'safe.txt')
        except OSError as exc:
            self.fail('Setup requires symlink-capable disposable executor: ' + type(exc).__name__)
        self.assertEqual(self.run_lint('link.txt')['error_code'], 'unsafe_path')

    def test_version_errors_timeout_and_private_diagnostics(self):
        cases = [[(0,b'vale version 0.0.0',b'')],
                 [(0,b'vale version 3.25.1',b''),(2,b'SECRET_CANARY',b'SECRET_CANARY')],
                 [(0,b'vale version 3.25.1',b''),wrapper.Rejected('timeout')],
                 [(0,b'vale version 3.25.1',b''),(0,b'not JSON SECRET_CANARY',b'')]]
        for responses in cases:
            with patch.object(wrapper, 'bounded', side_effect=responses):
                result = self.run_lint()
            self.assertEqual(result['status'], 'failed')
            self.assertNotIn('SECRET_CANARY', json.dumps(result))
            self.assert_held(result)

    def test_benign_directive_prefix_prose_reaches_linter(self):
        for prose in BENIGN_DIRECTIVE_PREFIX_PROSE:
            with self.subTest(prose=prose):
                (self.root / 'safe.txt').write_text(prose, encoding='utf-8')
                with patch.object(wrapper, 'bounded', side_effect=[
                        (0, b'vale version 3.25.1\n', b''), (0, b'{}', b'')]) as process:
                    result = self.run_lint()
                self.assertEqual(result['status'], 'lint_clean', result)
                self.assertEqual(result['findings'], [])
                self.assertEqual(process.call_count, 2)
                self.assert_held(result)

    def test_complete_directives_reject_before_linter(self):
        for directive in REJECTED_DIRECTIVE_TEXT:
            with self.subTest(directive=directive):
                (self.root / 'safe.txt').write_text(directive, encoding='utf-8')
                with patch.object(wrapper, 'bounded') as process:
                    result = self.run_lint()
                self.assertEqual(result['status'], 'failed', result)
                self.assertEqual(result['error_code'], 'document_directive')
                process.assert_not_called()
                self.assert_held(result)

class RealValeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = os.environ.get('CP080_VALE_BINARY')
        cls.sha = os.environ.get('CP080_VALE_SHA256')
        if not cls.binary or not cls.sha:
            raise RuntimeError('NOT_RUN: root must supply independently verified CP080_VALE_BINARY and CP080_VALE_SHA256')
        binary = wrapper.regular(Path(cls.binary))
        if hashlib.sha256(binary.read_bytes()).hexdigest() != cls.sha:
            raise RuntimeError('NOT_RUN: executable digest mismatch')

    def test_real_rule_load_exit_semantics_and_content_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for text, expected in [('Safe synthetic prose.\n','lint_clean'),
                                   ('Safe first line.\nCP080_FORBIDDEN_PHRASE\n','lint_findings')]:
                doc = root / 'synthetic.txt'
                doc.write_text(text, encoding='utf-8')
                before = doc.read_bytes()
                result = wrapper.lint(self.binary, self.sha, root, doc.name)
                self.assertEqual(result['status'], expected, result)
                if expected == 'lint_findings':
                    self.assertEqual(result['findings'], [{'rule':'Local.Guard','severity':'warning','line':2}])
                self.assertEqual(doc.read_bytes(), before)
                self.assertEqual(result['outbound_state'], 'HOLD')

    def test_real_broken_config_and_rule_fail(self):
        # Direct pinned CLI probes distinguish real config errors from wrapper pin rejection.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'document.txt').write_text('CP080_FORBIDDEN_PHRASE', encoding='utf-8')
            (root / 'styles' / 'Local').mkdir(parents=True)
            for config, rule in [('StylesPath = styles\n[*.txt]\nBasedOnStyles = Missing\n', ''),
                    ('StylesPath = styles\n[*.txt]\nBasedOnStyles = Local\n', 'extends: nonexistent\nmessage: invalid\n')]:
                (root / '.vale.ini').write_text(config, encoding='utf-8')
                (root / 'styles' / 'Local' / 'Guard.yml').write_text(rule, encoding='utf-8')
                code, out, err = wrapper.bounded([self.binary,'--no-global','--config='+str(root/'.vale.ini'),
                    '--output=JSON',str(root/'document.txt')], tmp, {'HOME':tmp,'XDG_CONFIG_HOME':tmp})
                self.assertNotEqual(code, 0, 'Broken config/style must not lint clean')

    def test_real_benign_directive_prefix_prose_is_clean_and_held(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            doc = root / 'synthetic.txt'
            for prose in BENIGN_DIRECTIVE_PREFIX_PROSE:
                with self.subTest(prose=prose):
                    doc.write_text(prose + '\n', encoding='utf-8')
                    before = doc.read_bytes()
                    result = wrapper.lint(self.binary, self.sha, root, doc.name)
                    self.assertEqual(result['status'], 'lint_clean', result)
                    self.assertEqual(result['findings'], [])
                    self.assertEqual(result['input_sha256'], hashlib.sha256(before).hexdigest())
                    self.assertEqual(doc.read_bytes(), before)
                    self.assertEqual(result['outbound_state'], 'HOLD')
                    self.assertTrue(result['approval_required'])
                    self.assertFalse(result['publication_authorized'])

    def test_verified_binary_directives_still_reject_before_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            doc = root / 'synthetic.txt'
            for directive in REJECTED_DIRECTIVE_TEXT:
                with self.subTest(directive=directive):
                    doc.write_text(directive, encoding='utf-8')
                    before = doc.read_bytes()
                    with patch.object(wrapper, 'bounded') as process:
                        result = wrapper.lint(self.binary, self.sha, root, doc.name)
                    process.assert_not_called()
                    self.assertEqual(result['status'], 'failed', result)
                    self.assertEqual(result['error_code'], 'document_directive')
                    self.assertEqual(doc.read_bytes(), before)
                    self.assertEqual(result['outbound_state'], 'HOLD')
                    self.assertTrue(result['approval_required'])
                    self.assertFalse(result['publication_authorized'])

if __name__ == '__main__':
    unittest.main()

class ProcessBoundaryTests(unittest.TestCase):
    def test_actual_subprocess_timeout_and_output_cap(self):
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(wrapper.Rejected, 'timeout'):
                wrapper.bounded([sys.executable, '-c', 'import time; time.sleep(5)'], tmp, {}, timeout=0.05)
            with self.assertRaisesRegex(wrapper.Rejected, 'output_limit'):
                wrapper.bounded([sys.executable, '-c', 'import sys; sys.stdout.write("x"*2000000)'], tmp, {})

    def test_configuration_changed_disabled_or_missing(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            package = root / 'component'
            shutil.copytree(BASE, package)
            binary = root / 'vale'
            binary.write_bytes(b'synthetic')
            sha = hashlib.sha256(binary.read_bytes()).hexdigest()
            (root / 'safe.txt').write_text('Safe prose.', encoding='utf-8')
            with patch.object(wrapper, 'HERE', package):
                config = package / '.vale.ini'
                original = config.read_bytes()
                for data in [b'', original + b'\nLocal.Guard = NO\n']:
                    config.write_bytes(data)
                    result = wrapper.lint(binary, sha, root, 'safe.txt')
                    self.assertEqual(result['error_code'], 'configuration_digest_mismatch')
                config.write_bytes(original)
                (package / 'styles' / 'Local' / 'Guard.yml').unlink()
                self.assertEqual(wrapper.lint(binary, sha, root, 'safe.txt')['error_code'], 'missing_regular_file')

