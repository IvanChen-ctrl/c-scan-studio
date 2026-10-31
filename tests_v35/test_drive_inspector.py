import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import Drive_Inspector as d
import Advanced_Disk_Studio as app


def f(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


class DriveClassificationTest(unittest.TestCase):
    def test_categories(self):
        fixtures = {'.jpg': 'images', '.mp4': 'videos', '.wav': 'audio', '.pdf': 'documents',
                    '.zip': 'archives', '.msi': 'installers', '.safetensors': 'models',
                    '.vhdx': 'virtual_disks', '.py': 'code', '.sqlite3': 'databases'}
        for ext, expected in fixtures.items():
            with self.subTest(ext=ext):
                self.assertEqual(d.classification('/disk/test'+ext)['id'], expected)

    def test_unknown_uses_low_confidence(self):
        x = d.classification('/folder/weird.xyz')
        self.assertEqual(x['id'], 'other')
        self.assertEqual(x['confidence'], '低')

    def test_filename_backup_rule_cannot_claim_contents(self):
        x = d.classification('/folder/Backup_From_My_PC.unknown')
        self.assertEqual(x['confidence'], '低')
        self.assertIn('文件名', x['reason'])

    def test_sensitive_types_protected(self):
        for ext in ['.pt', '.py', '.sqlite3', '.vhdx']:
            with self.subTest(ext=ext):
                cat = d.classification('/data/file'+ext)['id']
                self.assertTrue(d.protected_file('/data/file'+ext, cat)[0])

    def test_backup_directory_protected(self):
        self.assertTrue(d.protected_file('/data/Backups/photo.jpg', 'images')[0])

    def test_regular_image_is_manual_only(self):
        prot, note = d.protected_file('/data/pictures/photo.jpg', 'images')
        self.assertFalse(prot)
        self.assertIn('手动', note)


class DriveSelectionTest(unittest.TestCase):
    def setUp(self):
        self.choices = [{'id': 'D:', 'path': 'D:\\', 'type': '本地磁盘'},
                        {'id': 'F:', 'path': 'F:\\', 'type': '可移动磁盘'}]

    def test_two_selected_roots(self):
        self.assertEqual(len(d.select_drives(['D:', 'f:'], self.choices)), 2)

    def test_reject_c_and_unc(self):
        for value in ['C:', r'\\server\files', r'D:\Windows', 'E:']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                d.select_drives([value], self.choices)

    def test_reject_unavailable_and_duplicate(self):
        for value in [['Q:'], ['D:', 'd:'], [], ['D:']*9, ['D:\\'], ['D:..']]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                d.select_drives(value, self.choices)

    def test_reject_wrong_type(self):
        with self.assertRaises(ValueError):
            d.select_drives('D:', self.choices)
        with self.assertRaises(ValueError):
            d.select_drives([None], self.choices)

    def test_default_no_nonwindows_drives(self):
        if os.name != 'nt':
            self.assertEqual(d.available_drives(), [])


class DriveWalkTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stop = threading.Event()

    def scan(self, min_size=1, **kwargs):
        return d.inspect_roots([self.root], self.stop, min_duplicate_bytes=min_size,
                               max_files=2000, max_hash_bytes=16*1024**2, **kwargs)

    def test_hash_verified_cross_folder_duplicate(self):
        data = b'A'*700_000
        f(self.root/'data'/'a.png', data)
        f(self.root/'other'/'b.png', data)
        result = self.scan()
        self.assertTrue(result['complete'])
        self.assertEqual(result['total_duplicate_groups'], 1)
        group = result['duplicate_groups'][0]
        self.assertEqual(group['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(group['count'], 2)
        self.assertEqual(result['theoretical_savings'], len(data))
        self.assertTrue(group['manual_only'])
        self.assertTrue((self.root/'data'/'a.png').exists())
        self.assertTrue((self.root/'other'/'b.png').exists())

    def test_same_size_with_different_middle_does_not_match(self):
        data1 = b'a'*150000 + b'1'*100000 + b'z'*150000
        data2 = b'a'*150000 + b'2'*100000 + b'z'*150000
        f(self.root/'a.mp4', data1)
        f(self.root/'b.mp4', data2)
        result = self.scan()
        self.assertTrue(result['complete'])
        self.assertEqual(result['total_duplicate_groups'], 0)

    def test_identical_name_not_equal_without_content(self):
        f(self.root/'d1'/'same.jpg', b'XXX'*1000)
        f(self.root/'d2'/'same.jpg', b'YYY'*1000)
        result = self.scan()
        self.assertEqual(result['total_duplicate_groups'], 0)

    def test_hardlink_is_not_duplicate_space(self):
        original = f(self.root/'a.zip', b'Z'*2048)
        linked = self.root/'b.zip'
        try:
            os.link(original, linked)
        except (OSError, NotImplementedError):
            self.skipTest('hardlinks unsupported')
        result = self.scan()
        self.assertEqual(result['files_seen'], 1)
        self.assertEqual(result['total_duplicate_groups'], 0)
        self.assertGreaterEqual(result['skipped_links_hardlinks_protected'], 1)

    def test_symlink_is_never_traversed(self):
        outside = self.root.parent/'outside-test-safety'
        outside.mkdir(exist_ok=True)
        self.addCleanup(lambda: outside.rmdir() if outside.exists() else None)
        f(self.root/'regular.txt', b'hello')
        link = self.root/'link'
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('symlink unsupported')
        result = self.scan()
        self.assertEqual(result['files_seen'], 1)
        self.assertGreaterEqual(result['skipped_links_hardlinks_protected'], 1)

    def test_protected_tree_ignored(self):
        f(self.root/'Windows'/'system.dll', b'123')
        f(self.root/'node_modules'/'cache.js', b'abc')
        f(self.root/'safe'/'document.pdf', b'pdf')
        result = self.scan()
        self.assertEqual(result['files_seen'], 1)

    def test_protected_copy_is_read_only_and_red(self):
        data = b'A' * 1200
        f(self.root/'Backup'/'a.safetensors', data)
        f(self.root/'models'/'b.safetensors', data)
        result = self.scan()
        self.assertEqual(result['total_duplicate_groups'], 1)
        self.assertEqual(result['duplicate_groups'][0]['copies'][0]['risk'], 'red')
        self.assertTrue((self.root/'Backup'/'a.safetensors').exists())

    def test_low_scan_budget_marks_incomplete(self):
        f(self.root/'a.png', b'a'*100)
        f(self.root/'b.png', b'a'*100)
        result = self.scan(max_scan_seconds=0)
        self.assertFalse(result['complete'])
        self.assertFalse(result['inventory_complete'])
        self.assertIn('未完整', result['warning'])

    def test_hash_budget_rejects_unverified_files(self):
        data = b'q'*400_000
        f(self.root/'x'/'a.mp4', data)
        f(self.root/'y'/'b.mp4', data)
        result = d.inspect_roots([self.root], self.stop, min_duplicate_bytes=1,
                                 max_hash_bytes=10)
        self.assertFalse(result['hash_complete'])
        self.assertEqual(result['total_duplicate_groups'], 0)

    def test_cancel_event_does_not_touch_files(self):
        path = f(self.root/'a.png', b'data')
        self.stop.set()
        result = self.scan()
        self.assertTrue(result['cancelled'])
        self.assertFalse(result['complete'])
        self.assertEqual(path.read_bytes(), b'data')

    def test_invalid_root_symlink_rejected(self):
        target = self.root/'real'
        target.mkdir()
        link = self.root/'link'
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            self.skipTest('symlink unavailable')
        with self.assertRaises(ValueError):
            d.inspect_roots([link], self.stop)

    def test_multiroot_groups_across_roots(self):
        d1 = self.root/'diskD'; d2 = self.root/'diskE';d1.mkdir();d2.mkdir()
        f(d1/'alpha.png', b'C'*10000)
        f(d2/'beta.png', b'C'*10000)
        report = d.inspect_roots([d1, d2], self.stop, min_duplicate_bytes=1)
        self.assertEqual(report['total_duplicate_groups'], 1)
        self.assertEqual(len(report['roots']), 2)


class AppBoundaryTests(unittest.TestCase):
    def test_server_rejects_non_drive_input(self):
        mgr = app.Analyzer()
        ok, _ = mgr.start_inspection(['C:'])
        self.assertFalse(ok)
        ok, _ = mgr.start_inspection([r'D:\Projects'])
        self.assertFalse(ok)
        self.assertEqual(mgr.phase, 'idle')

    def test_state_has_readonly_inspection_and_no_cleanup_targets(self):
        mgr = app.Analyzer()
        st = mgr.state()
        self.assertIn('inventory', st)
        self.assertEqual(st['inventory']['duplicate_groups'], [])
        self.assertEqual(mgr.items, [])

    def test_classification_page_rejects_unscanned_categories(self):
        mgr = app.Analyzer()
        ok, message, page = mgr.classified_files_page('images', 0, 50)
        self.assertFalse(ok)
        self.assertIsNone(page)

    def test_classification_page_is_readonly_bounded(self):
        mgr = app.Analyzer()
        mgr.inventory['categories'] = [{'id': 'images', 'label': '图片/设计素材'}]
        mgr.inventory['classified_files'] = [{'path': 'D:/file_%02d.png' % i, 'category': 'images', 'size': 10,
                                              'mtime': '2026-10-31', 'confidence': '高', 'reason': '扩展名'}
                                             for i in range(61)]
        ok, _, page = mgr.classified_files_page('images', 50, 50)
        self.assertTrue(ok)
        self.assertEqual(len(page['files']), 11)
        self.assertEqual(page['total'], 61)
        self.assertIsNone(page['next_offset'])
        self.assertFalse(mgr.cleanup_preview)
        for offset, limit in [(-1, 50), (0, 10000), (True, 50), (0, True)]:
            self.assertFalse(mgr.classified_files_page('images', offset, limit)[0])

    def test_state_never_pushes_full_inventory_to_browser(self):
        mgr = app.Analyzer()
        mgr.inventory['classified_files'] = [{'path': 'D:/private_filename.jpg'}]
        st = mgr.state()
        self.assertNotIn('classified_files', st['inventory'])
        self.assertIn('classified_files', mgr.report()['inventory'])

    def test_report_includes_full_duplication_and_csv_safe(self):
        mgr=app.Analyzer()
        mgr.inventory['duplicate_groups']=[{'id':'dup-test','size':123,'sha256':'a'*64,'keeper':{'path':'D:\\original.png','reason':'人工保留'},'copies':[
            {'path':'=HYPERLINK("evil")','risk':'amber','suggestion':'仅手工确认','reason':'测试'}]}]
        report=mgr.report()
        self.assertEqual(report['inventory']['duplicate_groups'][0]['size'], 123)
        csv=app.csv_bytes(report)
        self.assertIn(b"'=HYPERLINK", csv)


if __name__ == '__main__':
    unittest.main()
