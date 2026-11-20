"""CoractiveFileFinder v1.21-inspired regression tests for C-Scan network index.

Only synthetic local directories and local SQLite are touched, never real O:/SMB.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import ntpath
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import Network_Index as net


class FullIndexRegression(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cscan-coractive-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name, 'share')
        self.root.mkdir()
        self.db = Path(self.tmp.name, 'index')
        self.docs = self.root / 'docs'
        self.docs.mkdir()
        (self.root / 'old.txt').write_text('content deliberately never indexed')
        for name in ('Fab project.txt', 'Fab [2026]*?.pdf', '中国研究.pdf', 'Straße.txt'):
            (self.docs / name).write_bytes(b'content')

    def scan(self, event=None, **kw):
        return net.scan('O:', 'D:', event or threading.Event(),
                        test_root=self.root, test_folder=self.db, identity='synthetic', **kw)

    def lookup(self, key=''):
        return net.lookup('O:', 'D:', key, test_folder=self.db, identity='synthetic')

    def names(self, key=''):
        return [ntpath.basename(p.replace("/", "\\")) for p, _, _ in self.lookup(key)[0]]

    def test_published_snapshot_unmodified_during_incomplete_refresh(self):
        self.assertEqual('complete', self.scan()['state'])
        (self.root/'old.txt').unlink()
        (self.root/'new.txt').touch()
        partial=self.scan(max_entries=1)
        self.assertEqual('partial', partial['state'])
        self.assertGreater(partial['staged'], 0)
        self.assertIn('old.txt', self.names())
        self.assertNotIn('new.txt', self.names())
        while partial['pending']:
            partial=self.scan(max_entries=1)
        self.assertTrue(partial['complete'])
        self.assertIn('new.txt', self.names())
        self.assertNotIn('old.txt', self.names())
        self.assertEqual(0, partial['staged'])

    def test_interrupt_middle_of_directory_retries_whole_directory(self):
        self.scan()
        (self.docs/'brand new.txt').write_bytes(b'x')
        evt=threading.Event()
        orig=net.os.scandir
        class CutOnSecond:
            def __init__(self, path): self.delegate=orig(path); self.count=0
            def __enter__(self): self.delegate.__enter__(); return self
            def __exit__(self, *args): return self.delegate.__exit__(*args)
            def __iter__(self): return self
            def __next__(self):
                item=next(self.delegate)
                self.count+=1
                if self.count==2: evt.set()
                return item
        def scandir(path):
            if str(path)==str(self.docs): return CutOnSecond(path)
            return orig(path)
        with mock.patch.object(net.os,'scandir', side_effect=scandir):
            incomplete=self.scan(evt,max_entries=1)
            # The first directory completes, the second is partially read but
            # never committed. Old published snapshot is still searchable.
        self.assertEqual('partial',incomplete['state'])
        self.assertNotIn('brand new.txt',self.names())
        self.assertGreater(incomplete['pending'],0)
        done=self.scan()
        self.assertTrue(done['complete'])
        self.assertIn('brand new.txt',self.names())

    def test_failed_directory_remains_pending_for_retry(self):
        self.scan()
        orig=net.os.scandir
        fired=[False]
        def fail_once(path):
            if str(path)==str(self.docs) and not fired[0]:
                fired[0]=True
                raise ConnectionResetError('simulated SMB disconnect')
            return orig(path)
        with mock.patch.object(net.os,'scandir',side_effect=fail_once):
            res=self.scan(max_entries=1)
            # root is committed; docs is still queued due soft batch boundary
            res=self.scan()
        self.assertTrue(fired[0])
        self.assertEqual('partial',res['state'])
        self.assertGreater(res['pending'],0)
        recovered=self.scan()
        self.assertTrue(recovered['complete'])
        self.assertEqual(0,recovered['errors'])

    def test_acl_blocked_subfolder_publishes_partial_coverage_not_full(self):
        # A directory denied by ACL is a documented gap, not a reason to
        # discard all accessible files elsewhere in the share.
        orig=net.os.scandir
        def deny(path):
            if str(path)==str(self.docs): raise PermissionError('synthetic ACL denied')
            return orig(path)
        with mock.patch.object(net.os,'scandir',side_effect=deny):
            state=self.scan()
        self.assertEqual('partial_coverage',state['state'])
        self.assertFalse(state['complete'])
        self.assertEqual(1,state['coverage_errors'])
        self.assertEqual(0,state['pending'])
        self.assertIn('old.txt',self.names())
        self.assertNotIn('Fab project.txt',self.names())
        # With updated permissions, a new manually authorized pass recovers.
        self.assertTrue(self.scan()['complete'])
        self.assertIn('Fab project.txt',self.names())

    def test_one_huge_directory_reports_error_without_publishing_partial(self):
        self.scan()
        (self.root/'new.txt').touch()
        with mock.patch.object(net,'MAX_DIRECTORY_ENTRIES',1):
            state=self.scan()
        self.assertEqual('partial',state['state'])
        self.assertGreater(state['pending'],0)
        self.assertNotIn('new.txt',self.names())
        self.assertTrue(self.scan()['complete'])
        self.assertIn('new.txt',self.names())

    def test_many_files_fts_and_literal_query_respects_result_cap(self):
        for i in range(2200):
            (self.docs/f'Fab_文件_{i:05}.dat').touch()
        status=self.scan()
        self.assertTrue(status['complete'])
        self.assertEqual(2205,status['files'])
        rows,_=self.lookup('文件')
        self.assertEqual(180,len(rows))
        self.assertTrue(all('文件_' in name for name in self.names('文件')))
        # No arbitrary 500k-file GLOBAL limit: the only safety threshold is
        # for a single directory's staging memory, not index total size.
        self.assertFalse(hasattr(net,'MAX_ROWS'))

    def test_unicode_and_literal_wildcards_through_trigram_or_fallback(self):
        self.scan()
        self.assertEqual(['Fab [2026]*?.pdf'], self.names('[2026]*?'))
        self.assertEqual(['Fab project.txt', 'Fab [2026]*?.pdf'], sorted(self.names('Fab'),reverse=True))
        self.assertEqual(['中国研究.pdf'], self.names('研究'))
        self.assertEqual(['Straße.txt'], self.names('strasse'))
        self.assertEqual(0, len(self.lookup('does-not-exist')[0]))
        database=Path(self.scan()['index_path'])
        with closing(sqlite3.connect(database)) as conn:
            conn.executescript('''
                DROP TRIGGER IF EXISTS files_fts_insert;
                DROP TRIGGER IF EXISTS files_fts_delete;
                DROP TRIGGER IF EXISTS files_fts_update;
                DROP TABLE IF EXISTS files_fts;
            ''')
        self.assertEqual(['中国研究.pdf'], self.names('研究'))
        self.assertEqual(['Fab [2026]*?.pdf'], self.names('[2026]*?'))

    def test_v1_database_migration_preserves_published_rows_and_restarts_offsets(self):
        self.db.mkdir()
        db=self.db/'O_synthetic.sqlite3'
        with closing(sqlite3.connect(db)) as conn:
            conn.executescript('''
                CREATE TABLE files(path TEXT PRIMARY KEY COLLATE NOCASE,
                                   name_fold TEXT,size INTEGER,mtime REAL,seen INTEGER);
                CREATE TABLE pending(path TEXT PRIMARY KEY COLLATE NOCASE,offset INTEGER);
                CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT);
                INSERT INTO meta VALUES('schema','1');
                INSERT INTO meta VALUES('state','partial');
                INSERT INTO meta VALUES('generation','1');
                INSERT INTO meta VALUES('root','stale-root');
                INSERT INTO pending VALUES('stale-directory',200);
                INSERT INTO files VALUES('O:\\legacy.txt','legacy.txt',7,0,1);
            ''')
        self.assertEqual(['legacy.txt'], self.names())
        partial=self.scan(max_entries=1)
        self.assertEqual('partial', partial['state'])
        self.assertEqual(['legacy.txt'], self.names())
        self.assertGreater(partial['pending'],0)
        self.assertNotIn('stale-directory', str(partial))
        complete=self.scan()
        self.assertTrue(complete['complete'])
        self.assertNotIn('legacy.txt', self.names())

    def test_crash_safe_atomic_publish_via_sqlite_transaction(self):
        first=self.scan()
        self.assertTrue(first['complete'])
        (self.root/'old.txt').unlink()
        (self.root/'new.txt').touch()
        orig=net._set_meta
        def fail_at_publish(conn,k,v):
            if k=='state' and v=='complete':
                raise sqlite3.OperationalError('simulated disk-full at publish')
            return orig(conn,k,v)
        with mock.patch.object(net,'_set_meta',side_effect=fail_at_publish):
            with self.assertRaises(sqlite3.OperationalError):
                self.scan()
        # All deletes/inserts rolled back; old index still contains old.txt.
        self.assertIn('old.txt',self.names())
        self.assertNotIn('new.txt',self.names())
        self.assertTrue(self.scan()['complete'])
        self.assertIn('new.txt',self.names())

    def test_reparse_symlink_skipped_without_false_full_coverage(self):
        extra=Path(self.tmp.name,'outside-secret.txt')
        extra.write_text('secret')
        try: (self.docs/'outlink.txt').symlink_to(extra)
        except (OSError,NotImplementedError): self.skipTest('no symlink privileges')
        result=self.scan()
        self.assertFalse(result['complete'])
        self.assertEqual('partial_coverage',result['state'])
        self.assertGreater(result['skipped'],0)
        self.assertNotIn('outlink.txt',self.names())

    def test_read_only_query_does_not_open_source_or_create_missing_database(self):
        import builtins
        result=self.scan()
        db=Path(result['index_path'])
        with mock.patch.object(builtins,'open',side_effect=AssertionError('file opened')):
            self.assertTrue(self.lookup('fab')[0])
        db.unlink()
        self.assertFalse(self.lookup('fab')[0])
        self.assertFalse(db.exists())

    def test_no_global_half_million_row_cap(self):
        self.assertFalse(hasattr(net, 'MAX_ROWS'))
        self.assertGreater(net.MAX_DIRECTORY_ENTRIES, net.DEFAULT_ENTRIES)


if __name__=='__main__': unittest.main()
