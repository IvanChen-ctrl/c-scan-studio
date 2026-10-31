# -*- coding: utf-8 -*-
"""v3.4: all test data is synthetic. No real C: disk operations."""
from __future__ import annotations
import secrets
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import Advanced_Disk_Studio as app


class MandatoryPreviewTests(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(app.vendor, 'local_cli_if_verified', return_value=None):
            self.manager = app.Analyzer()
        self.manager.items = [
            {"id":"one", "name":"synthetic green", "path":r"C:\Fake\green", "risk":"green",
             "priority":"P1", "size":12, "count":2, "age_days":14, "allowed":True},
            {"id":"two", "name":"synthetic amber", "path":r"C:\Fake\amber", "risk":"amber",
             "priority":"P2", "size":7, "count":1, "age_days":30, "allowed":True},
            {"id":"red", "name":"synthetic red", "path":r"C:\Fake\system", "risk":"red",
             "priority":"P4", "size":1, "count":1, "age_days":30, "allowed":False},
        ]
        self.manager.targets = {'one': object(), 'two': object(), 'red': object()}
        self.manager.snapshots = {
            'one': [app.Snapshot(r'C:\Fake\green\a.tmp', 5, 10), app.Snapshot(r'C:\Fake\green\b.tmp', 7, 10)],
            'two': [app.Snapshot(r'C:\Fake\amber\c.cache', 7, 10)],
            'red': [app.Snapshot(r'C:\Fake\system\x', 1, 10)],
        }

    def test_preview_is_readonly_and_complete(self):
        ok,msg,p = self.manager.preview_clean(['one','two'])
        self.assertTrue(ok,msg)
        self.assertEqual(3,p['total_files'])
        self.assertEqual(19,p['total_bytes'])
        self.assertEqual(2,len(p['categories']))
        self.assertEqual(3,len(p['sample_paths']))
        self.assertIsNone(self.manager.thread)
        self.assertEqual('idle',self.manager.phase)
        self.assertEqual(app.CLEAN_PREVIEW_TTL,p['expires_in_seconds'])
        self.assertGreater(len(p['ticket']),20)

    def test_unpreviewed_delete_rejected_even_with_delete_keyword(self):
        ok,msg=self.manager.start_clean(['one'],'DELETE')
        self.assertFalse(ok)
        self.assertIn('预览',msg)

    def test_wrong_confirmation_rejected_even_after_preview(self):
        _,_,p=self.manager.preview_clean(['one'])
        ok,msg=self.manager.start_clean(['one'],'CONFIRM',p['ticket'])
        self.assertFalse(ok)
        self.assertIn('DELETE',msg)

    def test_preview_token_for_other_selection_rejected(self):
        _,_,p=self.manager.preview_clean(['one'])
        ok,msg=self.manager.start_clean(['two'],'DELETE',p['ticket'])
        self.assertFalse(ok)
        self.assertIn('预览',msg)

    def test_expired_preview_rejected(self):
        _,_,p=self.manager.preview_clean(['one'])
        self.manager.cleanup_preview['expires']=time.monotonic()-1
        ok,msg=self.manager.start_clean(['one'],'DELETE',p['ticket'])
        self.assertFalse(ok)
        self.assertIn('过期',msg)

    def test_new_preview_revokes_old_token(self):
        _,_,old=self.manager.preview_clean(['one'])
        _,_,current=self.manager.preview_clean(['two'])
        self.assertNotEqual(old['ticket'],current['ticket'])
        ok,_=self.manager.start_clean(['one'],'DELETE',old['ticket'])
        self.assertFalse(ok)

    def test_preview_red_forbidden(self):
        ok,msg,data=self.manager.preview_clean(['red'])
        self.assertFalse(ok)
        self.assertIsNone(data)
        self.assertIn('不允许',msg)

    def test_arbitrary_path_and_duplicate_ids_rejected(self):
        for ids in [['C:/Windows/System32'],['one','one'],['one',7],[]]:
            ok,_,data=self.manager.preview_clean(ids)
            self.assertFalse(ok)
            self.assertIsNone(data)

    def test_preview_rejected_when_counts_changed(self):
        self.manager.snapshots['one'].pop()
        ok,msg,_=self.manager.preview_clean(['one'])
        self.assertFalse(ok)
        self.assertIn('不一致',msg)

    def test_delete_ticket_consumed_once(self):
        _,_,p=self.manager.preview_clean(['one'])
        with mock.patch.object(app.threading,'Thread') as thread:
            thread.return_value.start.return_value=None
            ok,msg=self.manager.start_clean(['one'],'DELETE',p['ticket'])
        self.assertTrue(ok,msg)
        self.assertIsNone(self.manager.cleanup_preview)
        ok,_=self.manager.start_clean(['one'],'DELETE',p['ticket'])
        self.assertFalse(ok)

    def test_new_task_invalidates_preview(self):
        _,_,p=self.manager.preview_clean(['one'])
        with mock.patch.object(app.threading,'Thread') as thread:
            ok,_=self.manager._start('large','test',lambda:None)
        self.assertTrue(ok)
        self.assertIsNone(self.manager.cleanup_preview)
        self.assertFalse(self.manager.start_clean(['one'],'DELETE',p['ticket'])[0])

    def test_only_verified_vendor_cli_auto_accepted(self):
        with mock.patch.object(app.vendor,'local_cli_if_verified',return_value=None), \
             mock.patch.object(app,'detect_es_exe',side_effect=AssertionError('External exe must not auto-run')):
            a=app.Analyzer()
        self.assertIsNone(a.es_exe)
        self.assertIn('不会运行',a.state()['es_status'])

    def test_cancel_revokes_single_use_ticket(self):
        _,_,p=self.manager.preview_clean(['one'])
        ok,_=self.manager.discard_preview()
        self.assertTrue(ok)
        self.assertIsNone(self.manager.cleanup_preview)
        self.assertFalse(self.manager.start_clean(['one'],'DELETE',p['ticket'])[0])

    def test_replaced_es_binary_cannot_be_launched(self):
        self.manager.es_exe=r'C:\Fake\Everything\es.exe'
        with mock.patch.object(app.vendor,'local_cli_if_verified',return_value=None), \
             mock.patch.object(app,'list_large_everything',side_effect=AssertionError('Unverified EXE ran!')), \
             mock.patch.object(app,'list_large_bounded',return_value=([],{'source':'bounded','complete':True,'scanned_entries':0})), \
             mock.patch.object(app.Path,'is_dir',return_value=False), \
             mock.patch.object(self.manager,'_auto_report',return_value=None):
            self.manager._large(512)
        self.assertIsNone(self.manager.es_exe)
        self.assertIn('无法访问',self.manager.large_info['source'])

    def test_frontend_opt_in_and_modal_are_present(self):
        html=(ROOT/'ui/dashboard.html').read_text(encoding='utf-8')
        self.assertIn('默认零勾选',html)
        self.assertIn('id="clean-preview-dialog"',html)
        self.assertIn("post('/api/preview-clean'",html)
        self.assertIn('ticket:p.ticket',html)
        self.assertNotIn('selected=new Set(rows.filter',html)
        self.assertIn("E('clean-preview-dialog').showModal()",html)

    def test_api_endpoint_enforces_server_preview_ticket(self):
        source=(ROOT/'Advanced_Disk_Studio.py').read_text(encoding='utf-8')
        self.assertIn('elif parsed.path == "/api/preview-clean":',source)
        self.assertIn('manager.start_clean(body.get("ids", []), body.get("confirm", ""),',source)
        self.assertIn('secrets.compare_digest(ticket, pending["ticket"])',source)
        self.assertIn('still_safe_snapshot(target, item, age_days)',source)


if __name__=='__main__':
    unittest.main(verbosity=2)
