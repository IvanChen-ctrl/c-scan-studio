"""Stress regressions for bounded, read-only C-Scan multi-drive operations.

All filesystem fixtures are newly created inside TemporaryDirectory; no real
Windows drive is enumerated, scanned, mutated, or cleaned by these tests.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
import http.client
from pathlib import Path
import hashlib
import os
import tempfile
import threading
import zipfile
import unittest
import sys

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import Advanced_Disk_Studio as app
import Drive_Inspector as inspector


class CountingList(list):
    """Measure actual source-rows visited by paginated queries, not wall time."""
    def __init__(self, rows):
        super().__init__(rows)
        self.visits = 0

    def __iter__(self):
        for row in super().__iter__():
            self.visits += 1
            yield row


def catalog(size=40_000):
    return CountingList({
        'path': f'D:/CScanSynthetic/file_{i:06d}.png',
        'size': 100 + i % 64,
        'category': 'images',
        'subtype': 'raster' if i % 2 == 0 else 'design',
        'volume': 'D:' if i % 4 < 2 else 'E:',
        'mtime': '2026-01-01', 'confidence': '高', 'reason': 'synthetic extension'
    } for i in range(size))


def manager_with_catalog(rows):
    manager = app.Analyzer()
    manager.inventory['classified_files'] = rows
    manager.inventory['categories'] = [{'id': 'images', 'label': '图片/设计素材'}]
    manager.inventory['inventory_complete'] = True
    manager.inventory['hierarchy'] = [{
        'id': 'media', 'label': '影像与创意素材',
        'categories': [{
            'id': 'images', 'label': '图片/设计素材',
            'subtypes': [{
                'id': kind, 'label': kind,
                'drives': [{'id': 'D:'}, {'id': 'E:'}]
            } for kind in ('raster', 'design')]
        }]
    }]
    return manager


class ReleaseVersionTests(unittest.TestCase):
    def test_runtime_frontend_and_release_versions_agree(self):
        from scripts import build_release
        self.assertEqual(app.VERSION, '3.6.0-beta.3')
        self.assertEqual(build_release.VERSION, '3.6.0-beta.3')
        html = (BASE / 'ui/dashboard.html').read_text('utf-8')
        self.assertIn('C-Scan Studio v3.6.0-beta.3', html)
        ci = (BASE / '.github/workflows/ci.yml').read_text('utf-8')
        release = (BASE / '.github/workflows/release.yml').read_text('utf-8')
        self.assertIn('tests_v363', ci)
        self.assertIn('tests_v363', release)
        self.assertIn('EXPECTED_TAG: v3.6.0-beta.3', release)
        self.assertIn('tests_v363', build_release.SOURCE_DIRS)
        self.assertIn('python scripts/verify_source_manifest.py', ci)
        self.assertIn('python scripts/verify_source_manifest.py', release)
        self.assertIn('identical_source_archives:', ci)
        attrs = (BASE / '.gitattributes').read_text('utf-8')
        self.assertIn('* text=auto eol=lf', attrs)
        self.assertIn('*.bat text eol=crlf', attrs)
        self.assertIn('*.cmd text eol=crlf', attrs)
        self.assertIn("'.gitattributes'", (BASE / 'scripts/build_release.py').read_text('utf-8'))

class DeterministicZipTests(unittest.TestCase):
    def test_zip_entries_have_platform_independent_bytes(self):
        from scripts import build_release
        with tempfile.TemporaryDirectory(prefix='cscan_zip_regression_') as temp:
            destination = Path(temp) / 'proof.zip'
            build_release.make_zip([('sample.txt', b'non-destructive synthetic content')],
                                   b'Path,SHA256\\n', destination)
            with zipfile.ZipFile(destination) as archive:
                self.assertIsNone(archive.testzip())
                for entry in archive.infolist():
                    self.assertEqual(entry.create_system, 3)
                    self.assertEqual(entry.compress_type, zipfile.ZIP_STORED)
                    self.assertEqual(entry.extra, b'')
                    self.assertEqual(entry.date_time, build_release.DATE)

class PaginationLoadTests(unittest.TestCase):
    def test_40k_file_catalog_400_pages_do_not_repeat_16m_row_scans(self):
        rows = catalog()
        manager = manager_with_catalog(rows)
        for i in range(400):
            kind = ('raster', 'design')[i % 2]
            drive = ('D:', 'E:')[(i // 2) % 2]
            offset = (i % 150) * 50
            ok, message, page = manager.classified_files_page(
                'images', offset=offset, limit=50, subtype=kind, drive=drive)
            self.assertTrue(ok, message)
            self.assertEqual(page['total'], 10_000)
            self.assertEqual(len(page['files']), 50)
            self.assertTrue(all(x['subtype'] == kind and x['volume'] == drive
                                for x in page['files']))
            self.assertEqual(page['next_offset'], offset + 50)
        # Index once from immutable snapshot. Refiltering all 40k rows per
        # page is O(16 million) even before HTTP serialization.
        self.assertLessEqual(rows.visits, len(rows) * 2)

    def test_snapshot_replacement_invalidates_page_index(self):
        rows = catalog(160)
        manager = manager_with_catalog(rows)
        self.assertTrue(manager.classified_files_page('images', 0, 25, 'raster', 'D:')[0])
        new_rows = [{'path': 'E:/new_only.png', 'size': 9,
                     'category': 'images', 'subtype': 'raster', 'volume': 'E:'}]
        with manager.lock:
            manager.inventory['classified_files'] = new_rows
        ok, msg, page = manager.classified_files_page('images', 0, 10, 'raster', 'E:')
        self.assertTrue(ok, msg)
        self.assertEqual(page['total'], 1)
        self.assertEqual([x['path'] for x in page['files']], ['E:/new_only.png'])
        ok, _, page = manager.classified_files_page('images', 0, 10, 'raster', 'D:')
        self.assertTrue(ok)
        self.assertEqual(page['files'], [])

    def test_parallel_readers_see_consistent_bounded_pages(self):
        rows = catalog(12_000)
        manager = manager_with_catalog(rows)
        def read(i):
            subtype = ('raster', 'design')[i % 2]
            drive = ('D:', 'E:')[(i // 2) % 2]
            ok, msg, page = manager.classified_files_page(
                'images', (i % 20) * 25, 25, subtype, drive)
            assert ok, msg
            assert page['total'] == 3000
            assert len(page['files']) == 25
            return True
        with ThreadPoolExecutor(max_workers=12) as pool:
            self.assertEqual(sum(pool.map(read, range(240))), 240)
        self.assertLessEqual(rows.visits, len(rows) * 2)
        # State must not leak all local file paths to the browser.
        self.assertNotIn('classified_files', manager.state()['inventory'])

    def test_rejects_invalid_pagination_and_drive_in_large_snapshot(self):
        manager = manager_with_catalog(catalog(5000))
        for subtype, drive, offset, limit in [
            ('raster', 'C:', 0, 50),
            ('../../secret', 'D:', 0, 50),
            ('raster', r'\\server\share', 0, 50),
            ('raster', 'D:', -1, 50),
            ('raster', 'D:', 0, 101),
        ]:
            self.assertFalse(manager.classified_files_page(
                'images', offset, limit, subtype, drive)[0])


class RejectedPostStress(unittest.TestCase):
    def test_rejected_cross_origin_posts_return_403_without_tcp_resets(self):
        manager = app.Analyzer()
        server = ThreadingHTTPServer(('127.0.0.1', 0), app.LocalHandler)
        server.session_token = 't' * 40
        server.analyzer = manager
        server.toolbox = app.Toolbox(log=manager._record)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            def attempt(i):
                connection = http.client.HTTPConnection(
                    '127.0.0.1', server.server_port, timeout=4)
                try:
                    content = b'{}' if i % 2 else b'{' + b' ' * 2048 + b'}'
                    connection.request('POST', '/api/clean', body=content, headers={
                        'Origin': 'https://untrusted.invalid',
                        'X-CSCAN-Token': server.session_token,
                        'Content-Type': 'application/json'})
                    response = connection.getresponse()
                    body = response.read()
                    self.assertEqual(response.status, 403)
                    self.assertIn(b'403', str(response.status).encode())
                    self.assertTrue(body)
                    return response.status
                finally:
                    connection.close()
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(list(pool.map(attempt, range(56))), [403] * 56)
            self.assertEqual(manager.phase, 'idle')
            self.assertIsNone(manager.cleanup_preview)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=4)


class ReadOnlyDiskStress(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cscan_regression_')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stop = threading.Event()

    def test_sample_budget_exact_bytes_for_128k_to_256k_files(self):
        # Existing implementation budgets 2*BLOCK for every file bigger
        # than BLOCK, although the tail may contain only a few bytes.
        path = self.root / 'boundary.mp4'
        data = b'A' * inspector.BLOCK + b'B' * 113
        path.write_bytes(data)
        st = os.lstat(path)
        entry = {
            'path': str(path),
            'identity': (st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino)
        }
        digest, used = inspector.file_digest(
            entry, self.stop, deadline=float('inf'), bytes_left=len(data), sample=True)
        self.assertEqual(used, len(data))
        self.assertEqual(len(digest), 64)
        self.assertEqual(path.read_bytes(), data)

    def test_150_folder_progress_is_throttled_not_spammed(self):
        for i in range(150):
            folder = self.root / f'synthetic_{i:04d}'
            folder.mkdir()
            (folder / 'file.txt').write_bytes(bytes([i % 251]))
        updates = []
        result = inspector.inspect_roots(
            [self.root], self.stop, min_duplicate_bytes=10**6, progress=updates.append)
        self.assertTrue(result['inventory_complete'])
        self.assertEqual(result['files_seen'], 150)
        self.assertLessEqual(len(updates), 12, 'Excessive progress updates for tiny folders')

    def test_file_count_limit_is_conservative_and_non_destructive(self):
        for i in range(220):
            (self.root / f'file_{i:04d}.png').write_bytes(b'fixture')
        report = inspector.inspect_roots(
            [self.root], self.stop, min_duplicate_bytes=1,
            max_files=73, max_hash_bytes=64 * 1024)
        self.assertEqual(report['files_seen'], 73)
        self.assertFalse(report['inventory_complete'])
        self.assertFalse(report['complete'])
        self.assertIn('未完整', report['warning'])
        self.assertEqual(len(list(self.root.glob('*.png'))), 220)
        self.assertFalse(report['cancelled'])

    def test_duplicate_group_after_many_small_files(self):
        for i in range(96):
            payload = bytes([i % 8]) * (800 + (i % 3))
            (self.root / f'file_{i:04d}.png').write_bytes(payload)
        report = inspector.inspect_roots(
            [self.root], self.stop, min_duplicate_bytes=1,
            max_hash_bytes=8 * 1024 * 1024)
        self.assertTrue(report['hash_complete'], report['warning'])
        self.assertEqual(report['files_seen'], 96)
        self.assertEqual(report['total_duplicate_groups'], 24)
        self.assertTrue(all(g['manual_only'] for g in report['duplicate_groups']))
        self.assertEqual(len(list(self.root.iterdir())), 96)

    def test_cancelled_scan_reports_partial_without_mutating_files(self):
        paths = []
        for i in range(80):
            p = self.root / f'item_{i:04d}.pdf'
            p.write_bytes(b'fixture')
            paths.append(p)
        self.stop.set()
        report = inspector.inspect_roots([self.root], self.stop, min_duplicate_bytes=1)
        self.assertTrue(report['cancelled'])
        self.assertFalse(report['complete'])
        self.assertEqual(report['total_duplicate_groups'], 0)
        self.assertEqual(len(list(self.root.glob('item_*.pdf'))), 80)
        self.assertTrue(all(p.read_bytes() == b'fixture' for p in paths))


if __name__ == '__main__':
    unittest.main()
