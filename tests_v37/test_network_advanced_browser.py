"""Coractive v1.21-inspired folder + advanced filter + pagination regression.

All shares are synthetic temporary local directories. No real mapped Windows
share, network credentials, filesystem cleanup, remote writes or background scan.
"""
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import Network_Index as idx
import Network_Browser as browser


class BrowserRegression(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cscan-folder-page-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'share'
        self.root.mkdir()
        self.db = Path(self.tmp.name) / 'db'
        for folder in ('docs/2026', 'docs/archives', 'empty', 'Audit reports', 'Projets/Team Alpha'):
            (self.root / folder).mkdir(parents=True)
        self.make('docs/2026/Fab 2026.pdf', b'2026')
        self.make('docs/2026/Fab Notes.txt', b'notes')
        self.make('docs/archives/Fab report.pdf', b'archived')
        self.make('docs/archives/private.txt', b'private')
        self.make('Audit reports/audit Fab.pdf', b'audit')
        self.make('Projets/Team Alpha/中国研究.pdf', b'research')
        self.make('Projets/Team Alpha/Straße.txt', b'German')
        self.make('README.txt', b'root')
        self.assertEqual('complete', self.scan()['state'])

    def make(self, rel, data=b''):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def scan(self, **kwargs):
        return idx.scan('O:', 'D:', threading.Event(), test_root=self.root,
                        test_folder=self.db, identity='synthetic', **kwargs)

    def search(self, q='', **kwargs):
        return browser.search('O:', 'D:', q, test_folder=self.db,
                              identity='synthetic', **kwargs)

    def folders(self, rel='', q='', **kwargs):
        return browser.folder_children('O:', 'D:', rel, q, test_folder=self.db,
                                       identity='synthetic', **kwargs)

    def folder_files(self, rel='', q='', **kwargs):
        return browser.folder_files('O:', 'D:', rel, q, test_folder=self.db,
                                    identity='synthetic', **kwargs)

    def names(self, page):
        return {x['name'] for x in page['rows']}

    def test_root_includes_empty_folders_and_correct_counts(self):
        root = self.folders()
        self.assertTrue(root['folder_ready'])
        self.assertEqual(4, root['total'])
        self.assertEqual({'docs', 'empty', 'Audit reports', 'Projets'}, self.names(root))
        docs = next(x for x in root['rows'] if x['name'] == 'docs')
        self.assertEqual(4, docs['indexed_files'])
        self.assertEqual(0, docs['direct_files'])
        self.assertEqual(4, docs['nested_files'])
        empty = next(x for x in root['rows'] if x['name'] == 'empty')
        self.assertEqual((0, 0), (empty['indexed_files'], empty['nested_files']))
        deeper = self.folders('docs')
        self.assertEqual({'2026', 'archives'}, self.names(deeper))
        self.assertEqual(0, self.folders('empty')['total'])

    def test_folder_pages_and_direct_vs_recursive_files(self):
        page1=self.folders(limit=2)
        page2=self.folders(offset=2,limit=2)
        self.assertEqual(4,page1['total'])
        self.assertTrue(page1['has_more'])
        self.assertFalse(page2['has_more'])
        self.assertFalse(self.names(page1)&self.names(page2))
        self.assertEqual(0,self.folder_files('docs',recursive=False)['total'])
        self.assertEqual(4,self.folder_files('docs',recursive=True)['total'])
        direct=self.folder_files('docs/archives',recursive=False)
        self.assertEqual({'Fab report.pdf','private.txt'},self.names(direct))
        self.assertEqual(2,self.folder_files('docs','ext:pdf')['total'])

    def test_advanced_filters_use_exact_total_and_literals(self):
        self.assertEqual(4,self.search('Fab')['total'])
        self.assertEqual(3,self.search('Fab ext:pdf')['total'])
        self.assertEqual(2,self.search('Fab ext:pdf -audit')['total'])
        self.assertEqual(3,self.search('Fab path:docs')['total'])  # docs contains two pdf and one txt
        self.assertEqual(1,self.search('name:"Fab 2026" ext:pdf')['total'])
        self.assertEqual(1,self.search('"中国研究"')['total'])
        self.assertEqual(1,self.search('strasse')['total'])
        self.assertEqual(0,self.search('Fab*')['total'])
        self.assertEqual(0,self.search('Fab?')['total'])
        self.assertEqual(2,self.search('path:"Team Alpha"')['total'])
        self.assertEqual(1,self.search('ext:txt -private -fab -readme')['total'])
        self.assertEqual(1,self.folder_files('docs/2026', 'name:Fab ext:pdf')['total'])

    def test_exact_pagination_over_180_results_without_pretruncation(self):
        # Use a single scan with >600 candidates, then traverse every page.
        for n in range(620):
            self.make(f'docs/2026/Fab_{n:04d}.pdf', b'x')
        report=self.scan(max_entries=60000)
        self.assertTrue(report['complete'])
        search=self.search('Fab', limit=100)
        self.assertEqual(624, search['total'])
        names=[]
        for off in range(0,624,100):
            page=self.search('Fab',offset=off,limit=100)
            names.extend(x['path'] for x in page['rows'])
            self.assertEqual(624,page['total'])
            self.assertEqual(off+len(page['rows'])<624,page['has_more'])
        self.assertEqual(624,len(names))
        self.assertEqual(624,len(set(names)))
        self.assertEqual([], self.search('Fab',offset=1000)['rows'])

    def test_incomplete_refresh_keeps_old_folder_catalog_and_pages(self):
        first=self.folders('docs')
        (self.root/'docs/archives/Fab report.pdf').unlink()
        (self.root/'docs/2026/new.txt').touch()
        partial=self.scan(max_entries=1)
        self.assertEqual('partial',partial['state'])
        self.assertEqual(first['rows'],self.folders('docs')['rows'])
        self.assertIn('Fab report.pdf',self.names(self.folder_files('docs')))
        self.assertNotIn('new.txt',self.names(self.folder_files('docs')))
        while partial['pending']:
            partial=self.scan(max_entries=1)
        self.assertTrue(partial['complete'])
        self.assertIn('new.txt',self.names(self.folder_files('docs')))
        self.assertNotIn('Fab report.pdf',self.names(self.folder_files('docs')))

    def test_invalid_folder_and_query_rejected_before_any_disk_access(self):
        for folder in ('../', 'docs/../private', '/tmp', r'\\server\share', 'O:/Windows', 'docs//2026', 'docs\\2026'):
            with self.subTest(folder=folder),self.assertRaises(ValueError):
                self.folders(folder)
        with self.assertRaises(ValueError):self.folders('fake-folder')
        for query in ('name:', 'ext:', 'type:folder type:file', '"unterminated', 'A'*451):
            with self.subTest(query=query),self.assertRaises(ValueError):
                self.search(query)
        with self.assertRaises(ValueError):self.search(offset=-1)
        with self.assertRaises(ValueError):self.search(offset=1_000_001)
        with self.assertRaises(ValueError):self.search(limit=201)
        with self.assertRaises(ValueError):self.search('type:folder')
        with self.assertRaises(ValueError):self.folder_files('docs',recursive='true')

    def test_lookup_is_readonly_and_never_enumerates_share(self):
        with mock.patch.object(idx.os,'scandir',side_effect=AssertionError('live share crawl')):
            self.assertGreater(self.search('Fab')['total'],0)
            self.assertGreater(self.folders()['total'],0)
            self.assertGreater(self.folder_files('docs')['total'],0)
        missing_dir=Path(self.tmp.name)/'missing-db'
        r=browser.search('O:', 'D:', 'fab',test_folder=missing_dir,identity='synthetic')
        self.assertEqual('missing',r['state'])
        self.assertFalse(missing_dir.exists())

    def test_failed_publish_rolls_back_both_files_and_folder_catalog(self):
        before=self.folders()
        (self.root/'docs/new-folder').mkdir()
        self.make('docs/new-folder/new-report.txt',b'x')
        with mock.patch.object(idx,'_publish_folder_catalog',side_effect=sqlite3.OperationalError('disk full')):
            with self.assertRaises(sqlite3.OperationalError):
                self.scan()
        self.assertEqual(before['rows'],self.folders()['rows'])
        self.assertEqual(0,self.search('new-report')['total'])
        self.assertTrue(self.scan()['complete'])
        self.assertEqual(1,self.search('new-report')['total'])

    def test_partial_coverage_propagates_warning(self):
        secret=Path(self.tmp.name)/'secret';secret.write_bytes(b'X')
        link=self.root/'outside-link'
        try:link.symlink_to(secret)
        except (OSError,NotImplementedError):self.skipTest('no symlink privileges')
        report=self.scan()
        self.assertEqual('partial_coverage',report['state'])
        self.assertTrue(self.search()['partial'])
        self.assertTrue(self.folders()['partial'])
        self.assertFalse('outside-link' in self.names(self.search()))


if __name__ == '__main__':
    unittest.main()
