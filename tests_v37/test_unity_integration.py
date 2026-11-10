"""Unity safety regressions. All file operations are in TemporaryDirectory."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import Advanced_Disk_Studio as app
import C_Drive_Cleanup as engine


class UnityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        valid = patch.object(engine.Target, 'valid', return_value=True)
        valid.start()
        self.addCleanup(valid.stop)

    def file(self, relative, data=b'cache', days=25):
        path = self.cache / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        age = time.time() - days * 86400
        os.utime(path, (age, age))
        return path

    def target(self, group='unity-upm', **kwargs):
        return engine.Target(group, 'Test Unity cache', self.cache, self.root,
                             process_names=('unity.exe', 'unity hub.exe',
                                            'unitypackagemanager.exe', 'bee_backend.exe'), **kwargs)

    def scan(self, target, days=0):
        return app.safe_scan_target(target, days, threading.Event(), time.monotonic() + 5)

    def manager(self, target, preserve=False):
        result, shots = self.scan(target)
        manager = app.Analyzer()
        manager.preserve_offline = preserve
        manager.items = [{'id': 'unity-test', 'group': target.group, 'name': target.name,
                          'path': str(target.path), 'risk': 'amber', 'allowed': True,
                          'complete': result['complete'], 'count': len(shots),
                          'size': result['bytes'], 'age_days': 0, 'priority': 'P2'}]
        manager.targets = {'unity-test': target}
        manager.snapshots = {'unity-test': shots}
        return manager

    def test_log_whitelist_only_direct_old_files(self):
        old = self.file('Editor-prev.log')
        recent = self.file('Editor.log', days=1)
        license_file = self.file('Unity_lic.ulf')
        nested = self.file('backup/Editor-prev.log')
        target = self.target('unity-logs', file_names=('Editor.log', 'Editor-prev.log'))
        outcome, shots = self.scan(target, 14)
        self.assertTrue(outcome['complete'])
        self.assertEqual([str(old)], [item.path for item in shots])
        with patch.object(engine, 'active_processes', return_value=set()):
            result = app.clean_snapshot_target(target, shots, 14, threading.Event(), set())
        self.assertEqual(1, result['deleted'])
        self.assertFalse(old.exists())
        self.assertTrue(all(path.exists() for path in (recent, license_file, nested)))

    def test_filename_whitelist_rechecked_before_unlink(self):
        other = self.file('Unity_lic.ulf')
        info = other.stat()
        shot = app.Snapshot(str(other), info.st_size, info.st_mtime_ns)
        target = self.target('unity-logs', file_names=('Editor.log',))
        self.assertFalse(app.still_safe_snapshot(target, shot, 0))

    def test_every_unity_process_blocks_and_unknown_fails_closed(self):
        file = self.file('db/cache.bin')
        target = self.target()
        _, shots = self.scan(target)
        for running in ({'unity.exe'}, {'Unity Hub.exe'}, {'UnityPackageManager.exe'},
                        {'bee_backend.exe'}, None):
            result = app.clean_snapshot_target(target, shots, 0, threading.Event(), running)
            self.assertEqual(0, result['deleted'])
            self.assertTrue(file.exists())

    def test_empty_or_malformed_tasklist_never_means_no_processes(self):
        for output in (b'', b'INFO: No tasks are running', b'"Unity.exe"',
                       b'"Unity.exe","bad pid","Console","1","1,000 K"',
                       b'"Unity.exe","123","Console","1","1,000 K"\nmalformed'):
            result = SimpleNamespace(returncode=0, stdout=output)
            with patch.object(engine.subprocess, 'run', return_value=result):
                self.assertIsNone(engine.active_processes())
        result = SimpleNamespace(returncode=0, stdout=(
            b'"System Idle Process","0","Services","0","8 K"\r\n'
            b'"Unity.exe","123","Console","1","1,000 K"\r\n'
            b'"explorer.exe","456","Console","1","2,000 K"\r\n'))
        with patch.object(engine.subprocess, 'run', return_value=result):
            self.assertEqual({'unity.exe', 'explorer.exe'}, engine.active_processes())

    def test_process_started_after_scan_blocks_execution(self):
        path = self.file('db/cache.bin')
        target = self.target()
        _, shots = self.scan(target)
        with patch.object(engine, 'active_processes', return_value={'unity hub.exe'}):
            result = app.clean_snapshot_target(target, shots, 0, threading.Event(), set())
        self.assertEqual(0, result['deleted'])
        self.assertTrue(path.exists())

    def test_offline_preference_is_enforced_server_side(self):
        path = self.file('db/offline-package.bin')
        manager = self.manager(self.target('unity-upm'), preserve=True)
        okay, _, preview = manager.preview_clean(['unity-test'])
        self.assertFalse(okay)
        self.assertIsNone(preview)
        self.assertTrue(path.exists())

    def test_frozen_preview_allows_confirmed_cleanup_only_once(self):
        path = self.file('db/package.bin')
        manager = self.manager(self.target('unity-upm'), preserve=False)
        okay, _, preview = manager.preview_clean(['unity-test'])
        self.assertTrue(okay)
        self.assertFalse(manager.start_clean(['unity-test'], 'DELETE')[0])
        self.assertTrue(path.exists())
        with patch.object(engine, 'active_processes', return_value=set()), \
                patch.object(manager, '_auto_report'), \
                patch.object(manager, '_disk', return_value={'total': 100, 'free': 10, 'used': 90}):
            self.assertTrue(manager.start_clean(['unity-test'], 'DELETE', preview['ticket'])[0])
            manager.thread.join(timeout=5)
            self.assertFalse(manager.thread.is_alive())
        self.assertFalse(path.exists())
        self.assertEqual(1, manager.last_cleanup['totals']['deleted'])
        self.assertFalse(manager.start_clean(['unity-test'], 'DELETE', preview['ticket'])[0])

    def test_cli_cannot_bypass_unity_frozen_preview(self):
        path = self.file('db/package.bin')
        result = engine.clean_target(self.target(), 0, set())
        self.assertEqual(0, result.metrics.deleted_files)
        self.assertTrue(path.exists())

    def test_unity_groups_never_enter_one_click_preset(self):
        self.assertFalse(any(group.startswith('unity-') for group in engine.ONE_CLICK_GROUPS))

    def test_project_dropped_in_cache_is_preserved(self):
        source = self.file('misplaced-project/Assets/art.asset')
        self.file('misplaced-project/ProjectSettings/ProjectVersion.txt')
        cached = self.file('db/download.bin')
        _, shots = self.scan(self.target())
        self.assertEqual([str(cached)], [shot.path for shot in shots])
        self.assertTrue(source.exists())

    def test_project_marker_added_after_scan_blocks_file(self):
        path = self.file('new-project/Assets/art.asset')
        target = self.target()
        _, shots = self.scan(target)
        self.file('new-project/ProjectSettings/ProjectVersion.txt')
        self.assertEqual(1, len(shots))
        self.assertFalse(app.still_safe_snapshot(target, shots[0], 0))
        self.assertTrue(path.exists())

    def test_same_size_same_mtime_replacement_cannot_use_old_snapshot(self):
        path = self.file('db/package.bin', b'AAAA')
        target = self.target()
        _, shots = self.scan(target)
        before = path.stat()
        replacement = self.root / 'replacement.bin'
        replacement.write_bytes(b'BBBB')
        os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
        os.replace(replacement, path)
        self.assertEqual(before.st_size, path.stat().st_size)
        self.assertEqual(before.st_mtime_ns, path.stat().st_mtime_ns)
        self.assertFalse(app.still_safe_snapshot(target, shots[0], 0))
        with patch.object(engine, 'active_processes', return_value=set()):
            cleaned = app.clean_snapshot_target(target, shots, 0, threading.Event(), set())
        self.assertEqual(0, cleaned['deleted'])
        self.assertEqual(b'BBBB', path.read_bytes())

    def test_generic_temp_protects_unity_project_and_metadata(self):
        files = [self.file('work/ProjectSettings/ProjectVersion.txt'),
                 self.file('work/Library/cache.bin'), self.file('work/Assets/data.bin'),
                 self.file('orphan.meta'), self.file('unityhub/cache.tmp')]
        discard = self.file('old.tmp')
        target = engine.Target('user-temp', 'temp', self.cache, self.root)
        _, shots = self.scan(target, 14)
        self.assertEqual([str(discard)], [shot.path for shot in shots])
        self.assertTrue(all(path.exists() for path in files))

    def test_permission_error_never_creates_cleanable_complete_scan(self):
        self.file('good.bin')
        self.file('unreadable/hidden.bin')
        real_scandir = os.scandir
        def guarded(path):
            if Path(path).name == 'unreadable':
                raise PermissionError('synthetic inaccessible child')
            return real_scandir(path)
        with patch.object(app.os, 'scandir', side_effect=guarded):
            outcome, shots = self.scan(self.target())
        self.assertFalse(outcome['complete'])
        self.assertEqual(1, outcome['errors'])
        self.assertEqual(1, len(shots))

    def test_unity_scan_filters_targets_and_respects_offline_flag(self):
        self.file('db/download.bin')
        target = self.target('unity-upm')
        other = engine.Target('pip', 'other', self.cache, self.root)
        for preserve in (True, False):
            manager = app.Analyzer()
            with patch.object(engine, 'make_targets', return_value=[target, other]), \
                    patch.object(engine, 'active_processes', return_value=set()), \
                    patch.object(app.unity_cache, 'audit', return_value={'items': [], 'complete': True}), \
                    patch.object(manager, '_auto_report'):
                manager._scan('unity', preserve)
            self.assertEqual(1, len(manager.items))
            self.assertEqual(not preserve, manager.items[0]['allowed'])
            self.assertEqual(preserve, manager.items[0]['offline_blocked'])
            self.assertEqual(preserve, manager.unity['preserve_offline'])

    def test_scan_option_types_and_idle_state(self):
        manager = app.Analyzer()
        for bad in ('false', 0, 1, None, [], {}):
            self.assertFalse(manager.start_scan('unity', bad)[0])
        with patch.object(manager, 'list_drives', return_value=[]):
            state = manager.state()
            self.assertEqual([], state['unity']['items'])
            self.assertTrue(state['preserve_offline'])
            self.assertIn('unity', manager.report())
            self.assertIn('Unity 专项诊断', app.csv_bytes(manager.report()).decode('utf-8-sig'))

    def test_guarded_paths_classified_as_protected(self):
        for path in (r'C:\Users\me\AppData\Local\Unity\licenses\UnityEntitlementLicense.xml',
                     r'D:\VRDOS\Assets\scene.unity', r'D:\VRDOS\ProjectSettings\settings.asset',
                     r'D:\Unity\Editor\Data\PlaybackEngines\AndroidPlayer\SDK\file.bin'):
            self.assertEqual('gray', app.classify_large_file(path)[0])


if __name__ == '__main__':
    unittest.main()
