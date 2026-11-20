"""Opt-in network metadata index: temporary owned folders, no real mapped drive."""
from __future__ import annotations
import os
import sqlite3
from contextlib import closing
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import Network_Index as idx
import Advanced_Disk_Studio as app
import Drive_Inspector as drives


class NetworkIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cscan-test-index-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'share'
        self.root.mkdir()
        self.db = Path(self.temp.name)/'db'
        (self.root/'docs').mkdir()
        (self.root/'docs'/'Fab 报告.txt').write_text('SENSITIVE-CONTENT', encoding='utf-8')
        (self.root/'docs'/'tiny.txt').touch()
        (self.root/'file.pdf').write_bytes(b'data')

    def scan(self, **kwargs):
        return idx.scan('O:', 'D:', threading.Event(), test_root=self.root,
                        test_folder=self.db, identity='synthetic', **kwargs)

    def find(self, name=''):
        return idx.lookup('O:', 'D:', name, test_folder=self.db, identity='synthetic')

    def test_uninitialized_status_does_not_create_storage(self):
        info = idx.status('O:', 'D:', test_folder=self.db, identity='synthetic')
        self.assertEqual('missing', info['state'])
        self.assertFalse(self.db.exists())

    def test_build_and_read_cached_filename_without_file_content(self):
        info = self.scan()
        self.assertEqual('complete', info['state'])
        self.assertEqual(3, info['files'])
        rows, _ = self.find('fab')
        self.assertEqual(1, len(rows))
        self.assertIn('Fab 报告.txt', rows[0][0])
        # Ensure a search does not open remote file contents.
        with mock.patch('builtins.open', side_effect=AssertionError('remote content opened')):
            results, _ = self.find('报告')
        self.assertEqual(len(results), 1)
        with closing(sqlite3.connect(info['index_path'])) as conn:
            names = ' '.join(x[0] for x in conn.execute('SELECT path FROM files'))
            self.assertNotIn('SENSITIVE-CONTENT', names)

    def test_resumable_budget_preserves_first_batch(self):
        info = self.scan(max_entries=1)
        self.assertEqual('partial', info['state'])
        self.assertGreater(info['pending'], 0)
        for _ in range(10):
            info = self.scan(max_entries=1)
            if info['state'] == 'complete': break
        self.assertEqual('complete', info['state'])
        self.assertEqual(3, info['files'])

    def test_partial_rebuild_keeps_stale_files_until_completed(self):
        self.scan()
        (self.root/'file.pdf').unlink()
        partial = self.scan(max_entries=1)
        self.assertEqual('partial', partial['state'])
        self.assertTrue(any('file.pdf' in x[0] for x in self.find()[0]))
        for _ in range(20):
            info = self.scan(max_entries=2)
            if info['state'] == 'complete': break
        self.assertEqual('complete', info['state'])
        self.assertFalse(any('file.pdf' in x[0] for x in self.find()[0]))

    def test_cancel_does_not_purge_previous_snapshot(self):
        self.scan()
        cancel = threading.Event()
        cancel.set()
        result = idx.scan('O:', 'D:', cancel, test_root=self.root, test_folder=self.db, identity='synthetic')
        self.assertFalse(result['complete'])
        self.assertEqual(3, result['files'])

    def test_skip_symlink(self):
        private = Path(self.temp.name)/'private.txt'
        private.write_text('private')
        link = self.root/'leak.txt'
        try: link.symlink_to(private)
        except (OSError, NotImplementedError): self.skipTest('symlink unavailable')
        self.scan()
        self.assertFalse(any('leak' in x[0] for x in self.find()[0]))

    def test_database_symlink_is_refused(self):
        self.db.mkdir()
        outside = Path(self.temp.name) / 'external.sqlite3'
        outside.write_text('DO NOT MODIFY')
        link = self.db / 'O_synthetic.sqlite3'
        try: link.symlink_to(outside)
        except (OSError, NotImplementedError): self.skipTest('symlink unavailable')
        with self.assertRaises(ValueError): self.scan()
        self.assertEqual('DO NOT MODIFY', outside.read_text())

    def test_invalid_target_drive_disallowed(self):
        for bad in ('C:', '../', r'\\server\share', 'O:\\secret', 'Z:relative'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                idx.status(bad, 'D:', test_folder=self.db)

    def test_limits_are_enforced(self):
        with self.assertRaises(ValueError): self.scan(max_seconds=0)
        with self.assertRaises(ValueError): self.scan(max_entries=999999)
        with self.assertRaises(ValueError): self.find('bad\x00name')
        with self.assertRaises(ValueError): idx.lookup('O:', 'D:', limit=500, test_folder=self.db)

    def test_ambiguous_mapping_never_creates_or_reads_shared_identity_database(self):
        with mock.patch.object(idx, 'local_storage_drives', return_value=['D:']), \
             mock.patch.object(idx, '_mapping_identity', return_value='identity-unavailable'):
            for action in (idx.status, idx.lookup):
                with self.subTest(action=action.__name__), self.assertRaises(ValueError):
                    action('O:', 'D:')
            self.assertFalse(self.db.exists())

    def test_network_mapping_storage_validator_rejects_c_and_remote(self):
        with mock.patch.object(idx, 'local_storage_drives', return_value=['D:']):
            for candidate in ('C:', 'O:', r'\\server\share'):
                with self.assertRaises(ValueError): idx.status('O:', candidate)

    def test_analyzer_requires_explicit_confirmation(self):
        manager = app.Analyzer()
        with mock.patch.object(idx, 'local_storage_drives', return_value=['D:']), \
             mock.patch.object(drives, 'available_network_drives', return_value=[{'id':'O:', 'path':'O:\\', 'type':'映射网络盘'}]), \
             mock.patch.object(manager, '_start', return_value=(True, 'ok')) as start:
            self.assertFalse(manager.start_network_index('O:', 'D:', '')[0])
            self.assertFalse(manager.start_network_index('O:', 'C:', 'INDEX_METADATA_READ_ONLY')[0])
            self.assertTrue(manager.start_network_index('O:', 'D:', 'INDEX_METADATA_READ_ONLY')[0])
        self.assertEqual(start.call_count, 1)

    def test_existing_es_is_still_primary(self):
        with mock.patch.object(app.vendor, 'local_cli_if_verified', return_value=r'C:\Trusted\es.exe'):
            manager=app.Analyzer()
        with mock.patch.object(drives, 'available_network_drives', return_value=[{'id':'O:', 'path':'O:\\', 'type':'映射网络盘'}]), \
             mock.patch.object(idx, 'lookup', side_effect=AssertionError('should not use SQLite')), \
             mock.patch.object(app, 'list_large_everything', return_value=([(r'O:\\share\\found.txt', 8, 0)], 'Everything 索引')), \
             mock.patch.object(app.vendor, 'local_cli_if_verified', return_value=r'C:\Trusted\es.exe'), \
             mock.patch.object(idx, 'local_storage_drives', return_value=['D:']), \
             mock.patch.object(manager, '_auto_report'):
            manager._large(0, 'O:', False, '', 'D:')
        self.assertEqual(1, len(manager.large_files))

    def test_sqlite_fallback_without_implicit_network_walk(self):
        self.scan()
        with mock.patch.object(app.vendor, 'local_cli_if_verified', return_value=None):
            manager = app.Analyzer()
        original_lookup = idx.lookup
        with mock.patch.object(drives, 'available_network_drives', return_value=[{'id':'O:', 'path':'O:\\', 'type':'映射网络盘'}]), \
             mock.patch.object(idx, 'lookup', side_effect=lambda d, s, n:original_lookup(d,s,n,test_folder=self.db,identity='synthetic')), \
             mock.patch.object(app, 'list_large_bounded', side_effect=AssertionError('network walk')), \
             mock.patch.object(manager, '_auto_report'):
            manager._large(0, 'O:', False, 'Fab', 'D:')
        self.assertEqual('local_snapshot', manager.large_info['index_status'])
        self.assertEqual(1, len(manager.large_files))
        self.assertFalse(manager.large_info['complete'])

if __name__ == '__main__': unittest.main()
