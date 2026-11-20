"""Everything and bounded file-search regression: mocks and owned temporary files only.

No actual Everything executable is launched; no Windows drive is enumerated;
no delete, move, or cleanup method is called.
"""
from __future__ import annotations

import os
import stat
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import Advanced_Disk_Studio as app


def _file_stat(size=1024):
    return os.stat_result((stat.S_IFREG | 0o644, 0, 0, 0, 0, 0, size, 0, 0, 0))


class EverythingScopeAndAccuracy(unittest.TestCase):
    def test_exact_threshold_and_file_only_cli(self):
        answer = types.SimpleNamespace(returncode=0,
            stdout=b'C:\\Folder\\exact.bin\r\n', stderr=b'')
        with mock.patch.object(app.subprocess, 'run', return_value=answer) as run, \
             mock.patch.object(app.os, 'lstat', return_value=_file_stat(1024)):
            rows, source = app.list_large_everything('verified-es.exe', 1024)
        self.assertEqual([1024], [x[1] for x in rows])
        self.assertIn('Everything', source)
        args = run.call_args.args[0]
        self.assertEqual('verified-es.exe', args[0])
        self.assertEqual('C:\\', args[2])
        self.assertIn('-a-d', args)
        self.assertIn('size:>=1024b', args)
        self.assertIn('-timeout', args)
        self.assertEqual('181', args[args.index('-n') + 1])
        self.assertFalse(run.call_args.kwargs.get('shell', False))

    def test_prefix_collision_parent_escape_and_other_drive_are_ignored(self):
        output = ('C:\\Data\\good.bin\n'
                  'C:\\Database\\wrong.bin\n'
                  'C:\\Data\\..\\secret.bin\n'
                  'D:\\Data\\elsewhere.bin\n'
                  'C:\\DATA\\GOOD.bin\n').encode('utf-8')
        result = types.SimpleNamespace(returncode=0, stdout=output, stderr=b'')
        with mock.patch.object(app.subprocess, 'run', return_value=result), \
             mock.patch.object(app.os, 'lstat', return_value=_file_stat()):
            rows, _ = app.list_large_everything('verified-es.exe', 500,
                                                 root='C:\\Data')
        self.assertEqual(1, len(rows))
        self.assertEqual(r'C:\Data\good.bin', rows[0][0])

    def test_unicode_filenames_and_case_insensitive_duplicate_control(self):
        path = 'C:\\资料\\模型.bin'
        result = types.SimpleNamespace(returncode=0,
            stdout=(path + '\n' + path.upper() + '\n').encode('utf-8'), stderr=b'')
        with mock.patch.object(app.subprocess, 'run', return_value=result), \
             mock.patch.object(app.os, 'lstat', return_value=_file_stat(9000)):
            rows, _ = app.list_large_everything('verified-es.exe', 1000)
        self.assertEqual(1, len(rows))
        self.assertEqual(path, rows[0][0])

    def test_stale_symlink_and_undersized_entries_never_leak_to_results(self):
        result = types.SimpleNamespace(returncode=0,
            stdout=b'C:\\small.bin\nC:\\link.bin\nC:\\fresh.bin\n',
            stderr=b'')
        symlink = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644,
                                        st_size=5000, st_mtime=0,
                                        st_file_attributes=app.REPARSE)
        def fake_stat(path):
            if path.endswith('small.bin'):
                return _file_stat(100)
            if path.endswith('link.bin'):
                return symlink
            return _file_stat(5000)
        with mock.patch.object(app.subprocess, 'run', return_value=result), \
             mock.patch.object(app.os, 'lstat', side_effect=fake_stat):
            rows, _ = app.list_large_everything('verified-es.exe', 1024)
        self.assertEqual([r'C:\fresh.bin'], [x[0] for x in rows])

    def test_bad_scope_rejected_without_executing_external_program(self):
        with mock.patch.object(app.subprocess, 'run', side_effect=AssertionError('ran')):
            for root in ('C:relative', r'\\server\share', 'D:relative', ''):
                rows, msg = app.list_large_everything('verified-es.exe', 1024, root=root)
                self.assertIsNone(rows, root)
                self.assertIn('范围', msg)
        self.assertFalse(app._within_search_root(r'C:\Database\wrong.bin', r'C:\Data'))

    def test_ipc_error_and_cancellation_are_not_success(self):
        failure = types.SimpleNamespace(returncode=8, stdout=b'', stderr=b'')
        with mock.patch.object(app.subprocess, 'run', return_value=failure):
            rows, msg = app.list_large_everything('verified-es.exe', 1024)
        self.assertIsNone(rows)
        self.assertIn('8', msg)
        cancelled = threading.Event()
        cancelled.set()
        with mock.patch.object(app.subprocess, 'run', side_effect=AssertionError('ran')):
            self.assertEqual(([], '已取消'),
                             app.list_large_everything('verified-es.exe', 1024, cancelled))

    def test_output_limit_is_enforced_and_result_order_is_stable(self):
        paths = [f'C:\\Data\\file{i}.bin' for i in range(8)]
        result = types.SimpleNamespace(returncode=0,
            stdout=('\r\n'.join(paths) + '\r\n').encode(), stderr=b'')
        def stat_for(path):
            return _file_stat(2000 + int(path.split('file')[1].split('.')[0]))
        with mock.patch.object(app.subprocess, 'run', return_value=result) as run, \
             mock.patch.object(app.os, 'lstat', side_effect=stat_for):
            rows, _ = app.list_large_everything('verified-es.exe', 1024, limit=3)
        self.assertEqual([2007, 2006, 2005], [x[1] for x in rows])
        self.assertEqual('4', run.call_args.args[0][run.call_args.args[0].index('-n') + 1])


class SearchFallbackAndReadOnly(unittest.TestCase):
    def create_analyzer(self):
        with mock.patch.object(app.vendor, 'local_cli_if_verified',
                               return_value='C:\\VERIFIED\\es.exe'):
            return app.Analyzer()

    def test_verified_index_with_rows_never_claims_whole_disk_complete(self):
        mgr = self.create_analyzer()
        with mock.patch.object(app.vendor, 'local_cli_if_verified',
                               return_value='C:\\VERIFIED\\es.exe'), \
             mock.patch.object(app, 'list_large_everything',
                               return_value=([(r'C:\Data\file.bin', 2*app.GIB, 0)], 'Everything 索引')), \
             mock.patch.object(app, 'list_large_bounded',
                               side_effect=AssertionError('unnecessary scan')), \
             mock.patch.object(mgr, '_auto_report'):
            mgr._large(512)
        self.assertEqual(1, len(mgr.large_files))
        self.assertFalse(mgr.large_info['complete'])
        self.assertIn('仅覆盖', mgr.large_info['warning'])
        self.assertEqual('idle', mgr.phase)

    def test_empty_index_uses_bounded_scan_without_cleaning(self):
        mgr = self.create_analyzer()
        row = (r'C:\Data\found.bin', app.GIB, 0)
        scan_info = {'scanned_entries': 1, 'permission_errors': 0,
                     'complete': True, 'stopped': False, 'limited': False,
                     'elapsed_seconds': 0.01}
        with mock.patch.object(app.vendor, 'local_cli_if_verified',
                               return_value='C:\\VERIFIED\\es.exe'), \
             mock.patch.object(app, 'list_large_everything',
                               return_value=([], 'Everything 索引（只读）')), \
             mock.patch.object(app.Path, 'is_dir', return_value=True), \
             mock.patch.object(app, 'list_large_bounded',
                               return_value=([row], scan_info)) as bounded, \
             mock.patch.object(mgr, '_auto_report'):
            mgr._large(512)
        bounded.assert_called_once()
        self.assertEqual('os.scandir 限时只读扫描', mgr.large_info['source'])
        self.assertEqual(row[0], mgr.large_files[0]['path'])

    def test_unreadable_folder_never_claims_complete_scan(self):
        with tempfile.TemporaryDirectory(prefix='cscan-search-owned-') as tmp:
            root = Path(tmp)
            forbidden = root / 'inaccessible'
            forbidden.mkdir()
            original = app.os.scandir
            def fail_on_child(path):
                if Path(path) == forbidden:
                    raise PermissionError('synthetic access denied')
                return original(path)
            with mock.patch.object(app.os, 'scandir', side_effect=fail_on_child):
                rows, report = app.list_large_bounded(root, 1, threading.Event())
        self.assertEqual([], rows)
        self.assertGreaterEqual(report['permission_errors'], 1)
        self.assertFalse(report['complete'])

    def test_symlink_directory_is_never_traversed_by_fallback(self):
        with tempfile.TemporaryDirectory(prefix='cscan-search-owned-') as owned, \
             tempfile.TemporaryDirectory(prefix='cscan-search-outside-') as outside:
            root = Path(owned)
            (Path(outside) / 'sensitive.bin').write_bytes(b'EXTERNAL')
            link = root / 'linked'
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest('symlink creation unavailable')
            rows, _ = app.list_large_bounded(root, 1, threading.Event())
        self.assertFalse(any('sensitive.bin' in name for name, _, _ in rows))


if __name__ == '__main__':
    unittest.main()
