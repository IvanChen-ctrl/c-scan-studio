# -*- coding: utf-8 -*-
"""Read-only Linux/Windows compatibility and mocked helper safety tests."""
from __future__ import annotations
import csv
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
import Advanced_Disk_Studio as app
import Security_Audit as audit
import Unified_Tools as helpers
import build_release


class SingleEntryAndSafetyTests(unittest.TestCase):
    def test_exactly_one_bat_in_user_root(self):
        entry = sorted(x.name for x in ROOT.glob('*.bat'))
        self.assertEqual(['00_启动C-Scan智能清理与安全中心.bat'], entry)

    def test_old_functions_are_accessible_in_gui(self):
        html = (ROOT / 'ui/dashboard.html').read_text(encoding='utf-8')
        for feature in ('page-tools', 'python_installer', 'defender_scan', 'signature_check',
                        'share_offline', 'everything_launch', 'windows_storage',
                        'btn-security-check', 'btn-setup-everything', 'page-large', 'page-cache'):
            self.assertIn(feature, html)
        self.assertIn('没有你的明确确认，不会删除文件', html)

    def test_unknown_action_is_rejected(self):
        tb = helpers.Toolbox()
        ok, _ = tb.start('execute_any_shell', 'SHOULD_NOT_RUN')
        self.assertFalse(ok)
        self.assertFalse(tb.busy)

    def test_known_action_requires_exact_confirmation(self):
        tb = helpers.Toolbox()
        for action in helpers.CONFIRMATIONS:
            ok, _ = tb.start(action, 'YES')
            self.assertFalse(ok)
        self.assertFalse(tb.busy)

    def test_defender_available_even_if_source_tampered(self):
        tb = helpers.Toolbox()
        ran = threading.Event()
        def simulated_defender():
            ran.set()
            return 'Test only: defender invocation was mocked'
        with mock.patch.object(helpers.audit, 'audit', return_value={'status': 'mismatch'}), \
             mock.patch.object(tb, '_defender', side_effect=simulated_defender):
            ok, _ = tb.start('defender_scan', 'DEFENDER_SCAN')
            self.assertTrue(ok)
            self.assertTrue(ran.wait(2))
            for _ in range(80):
                if not tb.busy:
                    break
                time.sleep(0.01)
        self.assertEqual('completed', tb.state()['last']['status'])

    def test_exec_actions_block_on_tampered_source(self):
        tb = helpers.Toolbox()
        called = threading.Event()
        with mock.patch.object(helpers.audit, 'audit', return_value={'status': 'mismatch'}), \
             mock.patch.object(tb, '_python_installer', side_effect=lambda: called.set()):
            ok, _ = tb.start('python_installer', 'OPEN_PYTHON_INSTALLER')
            self.assertTrue(ok)
            for _ in range(80):
                if not tb.busy:
                    break
                time.sleep(0.01)
        self.assertFalse(called.is_set())
        self.assertEqual('error', tb.state()['last']['status'])

    def test_no_general_shell_execution_endpoint(self):
        source = (ROOT / 'Advanced_Disk_Studio.py').read_text(encoding='utf-8')
        self.assertNotIn('subprocess.run(body[', source)
        self.assertIn('toolbox.start(body.get("action")', source)
        self.assertNotIn('/api/shell', source)

    def test_bat_does_not_open_legacy_auto_clean(self):
        cmd = (ROOT / 'internal/Bootstrap.cmd').read_text(encoding='utf-8-sig')
        self.assertIn('set "CLEAN_MODE=gui"', cmd)
        self.assertIn('(3,10) <= sys.version_info[:2]', cmd)
        self.assertIn('if exist "%%D:', cmd)

    def test_windows_launch_uses_utf8_even_on_cp1252(self):
        launcher = (ROOT / 'internal/Bootstrap.cmd').read_text(encoding='utf-8-sig')
        self.assertIn('set "PYTHONIOENCODING=utf-8"', launcher)
        self.assertIn('set "PYTHONUTF8=1"', launcher)

    def test_ci_forces_utf8_on_both_operating_systems(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        self.assertIn("PYTHONIOENCODING: 'utf-8'", workflow)
        self.assertIn("PYTHONUTF8: '1'", workflow)
        self.assertIn('windows-latest', workflow)

    def test_security_manifest_disclaimer_remains_honest(self):
        s = (ROOT / 'Security_Audit.py').read_text(encoding='utf-8')
        self.assertIn('未列入清单的新增文件不在本检查范围', s)
        self.assertIn('not a trust anchor', audit.__doc__.lower())


class PackagingTests(unittest.TestCase):
    def test_release_zip_has_no_third_party_binaries_or_private_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(0, build_release.main(['--root', str(ROOT), '--outdir', tmp]))
            name = Path(tmp) / ('C_Scan_Studio_v' + build_release.VERSION + '_Source.zip')
            self.assertTrue(name.is_file())
            with zipfile.ZipFile(name) as z:
                self.assertIsNone(z.testzip())
                names = z.namelist()
                self.assertTrue(any(x.endswith('Advanced_Disk_Studio.py') for x in names))
                self.assertTrue(any(x.endswith('/.github/workflows/codeql.yml') for x in names))
                self.assertFalse(any(x.lower().endswith(('.exe', '.msi', '.dll', '.whl')) for x in names))
                self.assertFalse(any('/_runtime/' in x or '/docs/historical/' in x for x in names))
                self.assertFalse(any('private_report' in x for x in names))
            self.assertTrue(name.with_name(name.name + '.sha256.txt').exists())

    def test_manifest_matches_real_source_files(self):
        files = build_release.eligible(ROOT)
        m = build_release.manifest_bytes(files)
        self.assertIn(b'SHA256', m)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, data in files:
                dest = root / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
            (root / 'FILE_INTEGRITY_SHA256.csv').write_bytes(m)
            check = audit.audit(root)
            self.assertEqual('matched', check['status'])
            self.assertEqual(len(files), check['matching'])

    def test_known_extension_restrictions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for required in build_release.SOURCE_NAMES:
                (root / required).write_bytes(b'example')
            (root / 'private_not_in_allowlist.exe').write_bytes(b'MZ!')
            (root / 'tests').mkdir()
            (root / 'tests' / 'bad.exe').write_bytes(b'MZ!')
            with self.assertRaises(RuntimeError):
                build_release.eligible(root)

    def test_developer_security_files_present(self):
        for item in ('SECURITY.md', 'NOTICE.md', 'LICENSE', 'README.md',
                     '.github/workflows/ci.yml', '.github/workflows/codeql.yml',
                     '.github/workflows/release.yml', '.github/dependabot.yml'):
            self.assertTrue((ROOT / item).is_file(), item)

    def test_github_release_requires_public_repository(self):
        release = (ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8')
        self.assertIn("github.repository_visibility == 'public'", release)
        self.assertIn('actions/attest@v4', release)
        self.assertIn('id-token: write', release)
        self.assertIn('gh release create', release)

    def test_github_script_prompts_before_public_upload(self):
        script = (ROOT / 'scripts/Publish_With_GitHub_CLI.ps1').read_text(encoding='utf-8')
        self.assertIn('Read-Host', script)
        self.assertIn('PUBLISH', script)
        self.assertIn('gh repo create c-scan-studio --public', script)
        self.assertNotIn('gh auth login --with-token', script)


if __name__ == '__main__':
    unittest.main(verbosity=2)
