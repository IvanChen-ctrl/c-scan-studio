"""Mapped-drive ES diagnostics: mocked IPC only. No network or deletion."""
import types
import unittest
from pathlib import Path
from unittest import mock
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import Advanced_Disk_Studio as app
import Drive_Inspector as drives

O = {'id': 'O:', 'path': 'O:\\', 'type': '映射网络盘'}


class IndexCountTests(unittest.TestCase):
    def test_read_only_count_without_traversal(self):
        response = types.SimpleNamespace(returncode=0, stdout=b'123\n', stderr=b'')
        with mock.patch.object(app.subprocess, 'run', return_value=response) as call:
            number, description = app.count_everything_index('verified-es.exe', 'O:\\')
        self.assertEqual(123, number)
        self.assertIn('只读', description)
        args = call.call_args.args[0]
        self.assertEqual('O:\\', args[args.index('-path') + 1])
        self.assertIn('-get-result-count', args)
        self.assertIn('-a-d', args)
        self.assertNotIn('-n', args)
        self.assertFalse(call.call_args.kwargs.get('shell', False))

    def test_literal_keyword_not_regex_injection(self):
        response = types.SimpleNamespace(returncode=0, stdout=b'0\n', stderr=b'')
        with mock.patch.object(app.subprocess, 'run', return_value=response) as run:
            number, _ = app.count_everything_index('verified-es.exe', 'O:\\', 'Fab (2026).pdf')
        self.assertEqual(0, number)
        args = run.call_args.args[0]
        self.assertEqual(r'Fab\ \(2026\)\.pdf', args[args.index('-regex') + 1])

    def test_invalid_roots_and_names_never_execute(self):
        with mock.patch.object(app.subprocess, 'run', side_effect=AssertionError('executed')):
            for path in ('O:relative', 'O:\\..\\', r'\\server\share', 'C:\\'):
                self.assertIsNone(app.count_everything_index('es.exe', path)[0])
            self.assertIsNone(app.count_everything_index('es.exe', 'O:\\', 'one/two')[0])

    def test_broken_ipc_and_bad_counter_are_not_zero(self):
        for response in (
            types.SimpleNamespace(returncode=8, stdout=b'', stderr=b''),
            types.SimpleNamespace(returncode=0, stdout=b'not-a-count', stderr=b'')
        ):
            with mock.patch.object(app.subprocess, 'run', return_value=response):
                self.assertIsNone(app.count_everything_index('es.exe', 'O:\\')[0])


class NetworkResultDiagnosisTests(unittest.TestCase):
    def search(self, counts, filename='Fab', lookup=None, verified=True):
        es = r'C:\Trusted\es.exe' if verified else None
        with mock.patch.object(app.vendor, 'local_cli_if_verified', return_value=es):
            mgr = app.Analyzer()
        answer = ([], 'Everything 索引（只读）') if lookup is None else lookup
        with mock.patch.object(drives, 'available_network_drives', return_value=[O]), \
             mock.patch.object(app.vendor, 'local_cli_if_verified', return_value=es), \
             mock.patch.object(app, 'list_large_everything', return_value=answer), \
             mock.patch.object(app, 'count_everything_index',
                               side_effect=[(n, '合成计数') for n in counts]) as cnt, \
             mock.patch.object(app, 'list_large_bounded',
                               side_effect=AssertionError('network traversal')), \
             mock.patch.object(mgr, '_auto_report'):
            mgr._large(0, 'O:', False, filename)
        return mgr.large_info, cnt.call_count

    def test_fab_miss_is_not_missing_index(self):
        result, n = self.search([345, 0])
        self.assertEqual(2, n)
        self.assertEqual('no_keyword_match', result['index_status'])
        self.assertEqual(345, result['index_total'])
        self.assertEqual(0, result['index_matching'])
        self.assertIn('关键词无匹配', result['source'])
        self.assertFalse(result['complete'])

    def test_zero_count_does_not_prove_empty_share(self):
        result, n = self.search([0], '')
        self.assertEqual(1, n)
        self.assertEqual('empty_or_missing', result['index_status'])
        self.assertIn('确实为空', result['warning'])

    def test_matching_but_unreadable(self):
        result, n = self.search([345, 3])
        self.assertEqual(2, n)
        self.assertEqual('matches_unreadable', result['index_status'])
        self.assertEqual(3, result['index_matching'])

    def test_no_keyword_but_unreadable(self):
        result, n = self.search([21], '')
        self.assertEqual(1, n)
        self.assertEqual('entries_unreadable', result['index_status'])

    def test_index_count_failed_is_unknown_not_empty(self):
        result, n = self.search([None])
        self.assertEqual(1, n)
        self.assertEqual('unknown', result['index_status'])
        self.assertIn('无法核实', result['source'])

    def test_verified_es_missing_not_restored_from_path(self):
        result, n = self.search([], lookup=(None, ''), verified=False)
        self.assertEqual(0, n)
        self.assertEqual('verified_cli_missing', result['index_status'])

    def test_ipc_failure_is_not_keyword_miss(self):
        result, n = self.search([], lookup=(None, 'Everything IPC 返回 8'))
        self.assertEqual(0, n)
        self.assertEqual('query_failed', result['index_status'])


if __name__ == '__main__':
    unittest.main()
