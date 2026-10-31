from __future__ import annotations
import hashlib
import io
import json
import os
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import Everything_Official_Manager as vendor
import Advanced_Disk_Studio as app


def build_zip(path, filename, payload):
    with zipfile.ZipFile(path, 'w') as f:
        f.writestr(filename, payload)
    return vendor.hash_file(path)


class VendorSafetyTests(unittest.TestCase):
    def test_whitelisted_sources_are_https_and_pinned(self):
        for arch in ('x64', 'x86'):
            for s in vendor.files_for_arch(arch):
                self.assertTrue(s['url'].startswith('https://www.voidtools.com/'))
                self.assertRegex(s['sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual(len(vendor.files_for_arch('x64')), 2)

    def test_reject_symlink_archive(self):
        with tempfile.TemporaryDirectory() as td:
            orig = Path(td) / 'orig.zip'
            digest = build_zip(orig, 'Everything.exe', b'MZTEST')
            link = Path(td) / 'link.zip'
            link.symlink_to(orig)
            with self.assertRaisesRegex(RuntimeError, '缺少'):
                vendor.verify_archive(link, {'sha256': digest, 'name': 'link.zip'})

    def test_wrong_sha_raises_without_extraction(self):
        with tempfile.TemporaryDirectory() as td:
            orig = Path(td) / 'Everything-1.4.1.1032.x64.zip'
            build_zip(orig, 'Everything.exe', b'MZTEST')
            spec = {'sha256':'0'*64, 'name':orig.name}
            with self.assertRaisesRegex(RuntimeError, 'SHA256'):
                vendor.verify_archive(orig, spec)

    def test_zip_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            orig = Path(td) / 'test.zip'
            digest = build_zip(orig, '../Everything.exe', b'bad')
            with self.assertRaisesRegex(RuntimeError, '异常路径'):
                vendor.verify_archive(orig, {'sha256': digest, 'name':orig.name})

    def test_verify_two_archives_before_writing_any_executable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            offline = root / 'Tools' / 'Official_Offline'
            offline.mkdir(parents=True)
            s1 = {'kind':'everything','name':'first.zip'}
            s1['sha256'] = build_zip(offline/s1['name'],'Everything.exe',b'MZ-FIRST')
            build_zip(offline/'second.zip','es.exe',b'bad')
            s2 = {'kind':'es','name':'second.zip','sha256':'f'*64}
            with self.assertRaisesRegex(RuntimeError, 'SHA256'):
                vendor.prepare(root, offline_only=True, _test_specs=[s1,s2])
            self.assertFalse((root/'Tools'/'Everything'/'Everything.exe').exists())

    def test_rejects_symlink_vendor_install_folder(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'source'
            target=Path(t)/'elsewhere'
            root.mkdir()
            target.mkdir()
            (root/'Tools').mkdir()
            (root/'Tools'/'Official_Offline').symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError,'符号链接'):
                vendor.prepare(root, offline_only=True)
            self.assertFalse(list(target.iterdir()))

    def test_offline_prepare_installs_only_two_named_executables(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            offline = root/'Tools'/'Official_Offline'
            offline.mkdir(parents=True)
            a={'kind':'everything','name':'a.zip'}
            a['sha256']=build_zip(offline/'a.zip','nested/Everything.exe',b'MZ+')
            b={'kind':'es','name':'b.zip'}
            b['sha256']=build_zip(offline/'b.zip','es.exe',b'MZ-es')
            installed=vendor.prepare(root, offline_only=True, _test_specs=[a,b])
            self.assertEqual(installed['everything'].read_bytes(), b'MZ+')
            self.assertEqual(installed['es'].read_bytes(), b'MZ-es')
            self.assertEqual(len(list(root.rglob('*.exe'))), 2)

    def test_local_manifest_rejects_modified_binary(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'Tools'/'Official_Offline').mkdir(parents=True)
            (root/'Tools'/'Everything').mkdir(parents=True)
            (root/'Tools'/'ES').mkdir(parents=True)
            first=root/'Tools'/'Everything'/'Everything.exe'
            second=root/'Tools'/'ES'/'es.exe'
            first.write_bytes(b'MZ-1')
            second.write_bytes(b'MZ-2')
            s1={'kind':'everything','name':'a.zip'}
            s1['sha256']=build_zip(root/'Tools'/'Official_Offline'/'a.zip','Everything.exe',b'MZ-1')
            s2={'kind':'es','name':'b.zip'}
            s2['sha256']=build_zip(root/'Tools'/'Official_Offline'/'b.zip','es.exe',b'MZ-2')
            m={'architecture':'x64','vendor_archives':{s['name']:s['sha256'] for s in (s1,s2)},
               'executable_sha256':{'everything':vendor.hash_file(first),'es':vendor.hash_file(second)}}
            (root/'Tools'/vendor.MANIFEST_NAME).write_text(json.dumps(m),encoding='utf-8')
            with patch.object(vendor,'files_for_arch',return_value=[s1,s2]):
                self.assertIsNotNone(vendor.trusted_local(root))
                second.write_bytes(b'MZ-modified')
                self.assertIsNone(vendor.trusted_local(root))
                # Tamper with manifest to match the changed EXE: still rejected.
                m['executable_sha256']['es']=vendor.hash_file(second)
                (root/'Tools'/vendor.MANIFEST_NAME).write_text(json.dumps(m),encoding='utf-8')
                self.assertIsNone(vendor.trusted_local(root))

    def test_install_rejected_without_opt_in(self):
        a=app.Analyzer()
        with patch.object(vendor,'prepare',side_effect=AssertionError('Must not call prepare')):
            self.assertFalse(a.start_everything_setup('NO')[0])
        self.assertFalse(a.state()['everything']['ready'])

    def test_local_ui_has_vendor_setup_confirm(self):
        page=(Path(app.HERE)/'ui'/'dashboard.html').read_text(encoding='utf-8')
        self.assertIn('INSTALL_OFFICIAL',page)
        self.assertIn('setupEverything()',page)
        self.assertIn('btn-everything',page)

    def test_no_autoclean_on_large_files(self):
        for path in (r'C:\Projects\models\ai.safetensors',r'C:\Users\alex\Documents\notes.iso'):
            self.assertIn(app.classify_large_file(path)[0],('gray','red'))

if __name__ == '__main__':
    unittest.main()
