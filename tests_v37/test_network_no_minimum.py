"""Network share searches are size-unrestricted; C: keeps its guarded size floor.

Only mocked ES outputs and files in owned temporary directories are used.
No Windows share is mounted and no file mutation/cleanup is exercised.
"""
from __future__ import annotations

import os
import re
import stat
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import Advanced_Disk_Studio as app
import Drive_Inspector as drives

MAPPED = {'id': 'O:', 'path': 'O:\\', 'type': '映射网络盘'}


def fake_file(size):
    return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_size=size,
                                 st_mtime=100, st_file_attributes=0)


class NetworkNoMinimum(unittest.TestCase):
    def test_zero_size_and_single_byte_file_are_in_es_results(self):
        data = b'O:\\share\\empty.txt\r\nO:\\share\\one.txt\r\n'
        answer = types.SimpleNamespace(returncode=0, stdout=data, stderr=b'')
        with mock.patch.object(app.subprocess, 'run', return_value=answer) as cmd, \
             mock.patch.object(app.os, 'lstat', side_effect=lambda p:
                               fake_file(0 if p.endswith('empty.txt') else 1)):
            rows, _ = app.list_large_everything('verified-es.exe', 0, root='O:\\')
        self.assertEqual([1, 0], [r[1] for r in rows])
        self.assertEqual(2, len(rows))
        self.assertFalse(any(x.startswith('size:') for x in cmd.call_args.args[0]))
        self.assertFalse(cmd.call_args.kwargs.get('shell', False))

    def test_unicode_keyword_filters_in_es_before_180_result_cap(self):
        keyword = '技术 报告.pdf'
        paths = ['O:\\Team\\技术 报告.pdf', 'O:\\Team\\unrelated.pdf']
        answer = types.SimpleNamespace(returncode=0,
                stdout=('\n'.join(paths)+'\n').encode('utf-8'), stderr=b'')
        with mock.patch.object(app.subprocess, 'run', return_value=answer) as cmd, \
             mock.patch.object(app.os, 'lstat', return_value=fake_file(1)):
            rows, _ = app.list_large_everything('verified-es.exe', 0, root='O:\\', name_contains=keyword)
        self.assertEqual([paths[0]], [r[0] for r in rows])
        argv = cmd.call_args.args[0]
        self.assertEqual(re.escape(keyword), argv[argv.index('-regex')+1])
        self.assertFalse(any(x.startswith('size:') for x in argv))
        self.assertEqual('181', argv[argv.index('-n')+1])

    def test_plain_keyword_is_not_treated_as_es_search_grammar(self):
        keyword='项目 (2026).pdf'
        answer=types.SimpleNamespace(returncode=0,
              stdout='O:\\docs\\项目 (2026).pdf\n'.encode('utf-8'), stderr=b'')
        with mock.patch.object(app.subprocess, 'run', return_value=answer) as cmd, \
             mock.patch.object(app.os, 'lstat', return_value=fake_file(10)):
            rows, _ = app.list_large_everything('verified-es.exe', 0, root='O:\\', name_contains=keyword)
        self.assertEqual(1, len(rows))
        self.assertIn(r'\(2026\)\.pdf', cmd.call_args.args[0][-1])

    def test_reject_invalid_name_without_starting_process(self):
        with mock.patch.object(app.subprocess, 'run', side_effect=AssertionError('Executed!')):
            for word in ('abc\n', 'abc\x00', 'one\\two', 'a'*121, 'report|log'):
                with self.subTest(word=repr(word)):
                    rows, message=app.list_large_everything('verified-es.exe', 0, root='O:\\', name_contains=word)
                    self.assertIsNone(rows)
                    self.assertIn('关键词', message)

    def test_server_ignores_any_c_size_minimum_for_network_drive(self):
        with mock.patch.object(app.vendor, 'local_cli_if_verified', return_value=None):
            manager=app.Analyzer()
        captures=[]
        def start(_phase, _msg, work):
            with mock.patch.object(manager, '_large') as worker:
                work()
                captures.append(worker.call_args.args)
            return True, 'synthetic'
        with mock.patch.object(drives,'available_network_drives', return_value=[MAPPED]), \
             mock.patch.object(manager, '_start', side_effect=start):
            self.assertTrue(manager.start_large(512, 'O:', False, '.txt')[0])
            self.assertTrue(manager.start_large(0, 'O:', False, '报告')[0])
            self.assertTrue(manager.start_large('not-a-size', 'O:')[0])
        self.assertEqual((0, 'O:', False, '.txt'), captures[0])
        self.assertEqual((0, 'O:', False, '报告'), captures[1])
        self.assertEqual((0, 'O:', False, ''), captures[2])

    def test_c_drive_requires_original_size_floor_and_no_keyword(self):
        with mock.patch.object(app.vendor, 'local_cli_if_verified', return_value=None):
            manager=app.Analyzer()
        for value in (0, 1, 64, 127, 16385):
            self.assertFalse(manager.start_large(value, 'C:')[0])
        with mock.patch.object(manager, '_start', return_value=(True, 'ok')) as start:
            self.assertTrue(manager.start_large(512, 'C:', False, 'ignore')[0])
        start.assert_called_once()

    def test_network_internal_worker_uses_zero_floor_and_filename(self):
        with mock.patch.object(app.vendor, 'local_cli_if_verified', return_value='C:\\VERIFIED\\es.exe'):
            manager=app.Analyzer()
        with mock.patch.object(drives, 'available_network_drives', return_value=[MAPPED]), \
             mock.patch.object(app.vendor, 'local_cli_if_verified', return_value='C:\\VERIFIED\\es.exe'), \
             mock.patch.object(app, 'list_large_everything', return_value=(
                 [(r'O:\Team\tiny.pdf', 0, 0)], 'Everything 索引（只读）')) as find, \
             mock.patch.object(manager, '_auto_report'):
            manager._large(4096, 'O:', False, 'tiny')
        self.assertEqual(0, find.call_args.args[1])
        self.assertEqual('tiny', find.call_args.kwargs['name_contains'])
        self.assertEqual(0, manager.large_info['min_mb'])
        self.assertEqual([0], [x['size'] for x in manager.large_files])
        self.assertFalse(manager.large_info['complete'])
        self.assertIn('不限', manager.large_info['warning'])

    def test_bounded_fallback_finds_empty_files_by_plain_filename(self):
        with tempfile.TemporaryDirectory(prefix='cscan-owned-no-min-') as temp:
            root=Path(temp)
            (root/'报告.txt').touch()
            (root/'unrelated.txt').write_bytes(b'a')
            rows, report=app.list_large_bounded(root, 0, threading.Event(),
                       max_seconds=3, max_entries=100, name_contains='报告')
        self.assertEqual([0], [x[1] for x in rows])
        self.assertTrue(report['complete'])


if __name__ == '__main__':
    unittest.main()
