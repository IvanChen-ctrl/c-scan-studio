"""Mapped network drive search regressions: no real share is mounted or read."""
import os
import stat
import threading
import types
import unittest
from pathlib import Path
from unittest import mock
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import Advanced_Disk_Studio as app
import Drive_Inspector as drives

O_DRIVE = {'id':'O:', 'path':'O:\\', 'type':'映射网络盘'}


class NetworkDriveTests(unittest.TestCase):
    def test_network_drive_selection_allowlist(self):
        self.assertEqual(str(drives.select_network_drive('o:', [O_DRIVE])), str(Path('O:\\')))
        for name in ('C:', r'\\server\share', r'O:\folder', 'O:..', 'O:/../', 'P:'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                drives.select_network_drive(name, [O_DRIVE])

    def test_local_and_network_scopes_are_isolated(self):
        output=b'O:\\team\\big.bin\nC:\\secret.bin\nP:\\other.bin\n'
        result=types.SimpleNamespace(returncode=0,stdout=output,stderr=b'')
        info=os.stat_result((stat.S_IFREG|0o644,0,0,0,0,0,4000,0,0,0))
        with mock.patch.object(app.subprocess, 'run', return_value=result) as run, \
             mock.patch.object(app.os, 'lstat', return_value=info):
            rows, _ = app.list_large_everything('verified-es.exe', 2000, root='O:\\')
        self.assertEqual([r'O:\team\big.bin'], [x[0] for x in rows])
        self.assertEqual('O:\\', run.call_args.args[0][2])

    def test_network_is_never_silently_walked_when_index_missing(self):
        with mock.patch.object(app.vendor, 'local_cli_if_verified', return_value='C:\\verified\\es.exe'):
            mgr=app.Analyzer()
        with mock.patch.object(drives, 'available_network_drives', return_value=[O_DRIVE]), \
             mock.patch.object(app.vendor, 'local_cli_if_verified', return_value='C:\\verified\\es.exe'), \
             mock.patch.object(app, 'list_large_everything', return_value=([], 'Everything 索引（只读）')), \
             mock.patch.object(app, 'list_large_bounded', side_effect=AssertionError('network traversed')), \
             mock.patch.object(mgr, '_auto_report'):
            mgr._large(512, 'O:', False)
        self.assertFalse(mgr.large_info['complete'])
        self.assertTrue(mgr.large_info['network'])
        self.assertIn('未就绪', mgr.large_info['source'])
        self.assertEqual([], mgr.large_files)

    def test_network_walk_requires_explicit_opt_in_and_budgets(self):
        with mock.patch.object(app.vendor, 'local_cli_if_verified', return_value=None):
            mgr=app.Analyzer()
        with mock.patch.object(drives, 'available_network_drives', return_value=[O_DRIVE]), \
             mock.patch.object(app, 'list_large_bounded', return_value=([], {
                  'complete':False,'scanned_entries':12000,'permission_errors':0,
                  'limited':True,'stopped':False,'elapsed_seconds':12
             })) as walk, \
             mock.patch.object(app.Path, 'is_dir', return_value=True), \
             mock.patch.object(mgr, '_auto_report'):
            mgr._large(512, 'O:', True)
        self.assertEqual(12, walk.call_args.kwargs['max_seconds'])
        self.assertEqual(12000, walk.call_args.kwargs['max_entries'])
        self.assertFalse(mgr.large_info['complete'])

    def test_no_arbitrary_network_or_bool_scan_settings(self):
        with mock.patch.object(app.vendor, 'local_cli_if_verified', return_value=None):
            mgr=app.Analyzer()
        with mock.patch.object(drives, 'available_network_drives', return_value=[O_DRIVE]), \
             mock.patch.object(mgr, '_start', side_effect=AssertionError('started')):
            for drive in ('C:\\secret', r'\\server\share', 'Z:', 'O:/x'):
                self.assertFalse(mgr.start_large(512, drive)[0])
            self.assertFalse(mgr.start_large(512, 'O:', 'yes')[0])

    def test_existing_local_inspector_never_adds_network_share(self):
        with mock.patch.object(drives, 'available_drives', return_value=[]):
            with self.assertRaises(ValueError):
                drives.select_drives(['O:'])


if __name__ == '__main__':
    unittest.main()
