# -*- coding: utf-8 -*-
"""Isolated v3 tests. NEVER scans or changes a real C: drive."""
import contextlib
import http.client
import io
import os
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock
from http.server import ThreadingHTTPServer

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import Advanced_Disk_Studio as app


class RiskTests(unittest.TestCase):
    def test_ver(self):
        self.assertEqual(app.VERSION, "3.5.2-beta.1")

    def test_four_risk_colours(self):
        for value in ("green", "amber", "orange", "red", "gray"):
            self.assertIn(value, app.RISK_TEXT)

    def test_all_core_groups_classified(self):
        for value in app.engine.GROUPS:
            self.assertIn(value, app.POLICY)

    def test_protected_groups_not_auto_clean(self):
        for value in ("ide", "crash", "system-temp", "system-wer"):
            self.assertNotIn(app.POLICY[value][0], app.AUTOCLEAN_RISKS)

    def test_priority_green_large(self):
        self.assertEqual("P1", app.compute_priority("green", 400 * app.MIB))

    def test_priority_green_small(self):
        self.assertEqual("P2", app.compute_priority("green", 5 * app.MIB))

    def test_priority_amber_large(self):
        self.assertEqual("P2", app.compute_priority("amber", 200 * app.MIB))

    def test_priority_amber_small(self):
        self.assertEqual("P3", app.compute_priority("amber", 5 * app.MIB))

    def test_priority_red(self):
        self.assertEqual("P4", app.compute_priority("red", 20 * app.GIB))

    def test_priority_model_gray(self):
        self.assertEqual("P4", app.compute_priority("gray", 200 * app.GIB))

    def test_model_weight_protected(self):
        self.assertEqual("gray", app.classify_large_file(r"C:\Users\x\.cache\huggingface\model.safetensors")[0])

    def test_conda_protected(self):
        self.assertEqual("gray", app.classify_large_file(r"C:\miniconda3\pkgs\huge.bin")[0])

    def test_iso_not_auto_clean(self):
        self.assertEqual("red", app.classify_large_file(r"C:\data\game.iso")[0])

    def test_vhdx_not_auto_clean(self):
        self.assertEqual("red", app.classify_large_file(r"C:\Users\x\ext4.vhdx")[0])

    def test_windows_protected(self):
        self.assertEqual("red", app.classify_large_file(r"C:\Windows\System32\data.sys")[0])

    def test_personal_downloads(self):
        self.assertEqual("red", app.classify_large_file(r"C:\Users\x\Downloads\a.7z")[0])

    def test_unknown_not_green(self):
        self.assertNotIn(app.classify_large_file(r"C:\custom\rare.bin")[0], app.AUTOCLEAN_RISKS)

    def test_advisories_not_deletable(self):
        self.assertEqual(6, len(app.ADVISORIES))
        self.assertTrue(all(x['risk'] not in app.AUTOCLEAN_RISKS for x in app.ADVISORIES))

    def test_json_size_limit(self):
        self.assertLessEqual(app.MAX_JSON, 65536)

    def test_embedded_frontend_exists(self):
        text = (BASE/'ui'/'dashboard.html').read_text(encoding='utf-8')
        self.assertIn('清理勾选项目', text)
        self.assertIn('风险', text)
        self.assertIn('Everything', text)
        self.assertNotIn('https://fonts.googleapis.com', text)


class FilesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_bounded_large_scan_orders_files(self):
        (self.root/'a').write_bytes(b'abc')
        (self.root/'b').write_bytes(b'abcdefghijk')
        (self.root/'c').write_bytes(b'abcdef')
        rows, meta=app.list_large_bounded(self.root, 4, threading.Event(),
                                          max_seconds=4, max_entries=100, limit=2)
        self.assertEqual([11,6], [x[1] for x in rows])
        self.assertTrue(meta['complete'])

    def test_large_scan_skips_symlink(self):
        (self.root/'real').write_bytes(b'abcde')
        try:
            (self.root/'fake').symlink_to(self.root/'real')
        except (OSError, NotImplementedError):
            self.skipTest('symlinks not available')
        rows,_ = app.list_large_bounded(self.root,1,threading.Event(),max_seconds=3)
        self.assertEqual(1,len(rows))
        self.assertEqual('real',Path(rows[0][0]).name)

    def test_bounded_large_scan_cancel(self):
        cancel=threading.Event();cancel.set()
        rows,meta=app.list_large_bounded(self.root,1,cancel)
        self.assertEqual([],rows)
        self.assertFalse(meta['complete'])
        self.assertTrue(meta['stopped'])

    def test_no_arbitrary_paths_for_gui_cleanup(self):
        manager=app.Analyzer()
        manager.items=[]
        accepted,why=manager.start_clean(['C:/Windows/System32'], 'DELETE')
        self.assertFalse(accepted)

    def test_cleanup_confirmation_is_mandatory(self):
        manager=app.Analyzer()
        accepted,_=manager.start_clean(['anything'], 'clean')
        self.assertFalse(accepted)

    def test_cleanup_unsupported_duplicate_ids(self):
        manager=app.Analyzer()
        accepted,_=manager.start_clean(['x','x'], 'DELETE')
        self.assertFalse(accepted)

    def test_clean_blocked_for_risk_red(self):
        manager=app.Analyzer()
        entry={"id":"x","allowed":True,"risk":"red","name":"protected","count":1}
        manager.items=[entry]
        manager.targets={'x':object()}
        accepted,_=manager.start_clean(['x'], 'DELETE')
        self.assertFalse(accepted)

    def test_exact_snapshot_cleaning_and_change_detection(self):
        folder=self.root/'cache';folder.mkdir()
        f=folder/'dispose.bin';f.write_bytes(b'cached')
        target=app.engine.Target('pip','demo',folder,self.root)
        original_valid=app.engine.Target.valid
        def within(child,parent):
            a=Path(child).absolute();b=Path(parent).absolute()
            return b in a.parents and a != b
        with mock.patch.object(app.engine.Target,'valid',lambda x:True), \
             mock.patch.object(app.engine,'strictly_within',within), \
             mock.patch.object(app.engine,'ancestors_clear',lambda x:True):
            result,shots=app.safe_scan_target(target,0,threading.Event(),time.monotonic()+4)
            self.assertEqual(1,result['count'])
            self.assertEqual(1,len(shots))
            self.assertTrue(app.still_safe_snapshot(target,shots[0],0))
            f.write_bytes(b'modified!')
            self.assertFalse(app.still_safe_snapshot(target,shots[0],0))
            removed=app.clean_snapshot_target(target,shots,0,threading.Event(),set())
            self.assertEqual(0,removed['deleted'])
            self.assertTrue(f.exists())

    def test_snapshot_cleaning_only_scanned_file(self):
        folder=self.root/'cache';folder.mkdir()
        f=folder/'old.cache';f.write_bytes(b'old file')
        g=folder/'unscanned.cache';g.write_bytes(b'keep')
        target=app.engine.Target('pip','test',folder,self.root)
        def within(child,parent):
            a=Path(child).absolute();b=Path(parent).absolute()
            return b in a.parents and a != b
        st=f.stat(); snapshot=app.Snapshot(str(f),int(st.st_size),int(st.st_mtime_ns))
        with mock.patch.object(app.engine.Target,'valid',lambda x:True), \
             mock.patch.object(app.engine,'strictly_within',within), \
             mock.patch.object(app.engine,'ancestors_clear',lambda x:True):
            res=app.clean_snapshot_target(target,[snapshot],0,threading.Event(),set())
        self.assertEqual(1,res['deleted'])
        self.assertFalse(f.exists())
        self.assertTrue(g.exists())

    def test_cached_process_blocks_deletion(self):
        folder=self.root/'cache';folder.mkdir()
        f=folder/'cachefile';f.write_bytes(b'data')
        target=app.engine.Target('browser','Cache',folder,self.root,'chrome.exe')
        res=app.clean_snapshot_target(target,[],0,threading.Event(),{'chrome.exe'})
        self.assertIn('跳过',res['state'])
        self.assertTrue(f.exists())

    def test_csv_contains_risk_and_priority(self):
        manager=app.Analyzer()
        data=app.csv_bytes(manager.report()).decode('utf-8-sig')
        self.assertIn('优先级', data)
        self.assertIn('风险颜色', data)

    def test_additional_temp_exe_whl_conda_protected(self):
        target=app.engine.Target('user-temp','test',self.root,self.root.parent)
        for ext in ('.exe','.msi','.whl','.conda','.vmdk'):
            self.assertTrue(app.protected_temp_extra(target,self.root/('test'+ext)))

    def test_csv_formula_injection_escaped(self):
        item={'name':'=SUM(1,1)','priority':'P2','risk':'amber','size':3,
              'count':1,'complete':True,'allowed':True,'path':'C:\\Cache','reason':'test'}
        report={'cache_items':[item], 'large_files':[{'priority':'P4','risk':'red','size':500,
                  'mtime':'2026-01-01','path':'C:\\file.bin','reason':'test'}]}
        text=app.csv_bytes(report).decode('utf-8-sig')
        self.assertIn("'=SUM",text)
        self.assertIn('大文件',text)

    def test_everything_cli_command_uses_no_shell(self):
        output=b'C:\\data\\big.bin\r\n'
        fake_result=types.SimpleNamespace(returncode=0,stdout=output,stderr=b'')
        fake_stat=os.stat_result((0o100644,0,0,0,0,0,2048,0,0,0))
        with mock.patch.object(app.subprocess,'run',return_value=fake_result) as run, \
             mock.patch.object(app.os,'lstat',return_value=fake_stat):
            rows,source=app.list_large_everything('es.exe',1024,threading.Event())
        self.assertEqual(1,len(rows))
        self.assertIn('Everything',source)
        self.assertFalse(run.call_args.kwargs.get('shell',False))
        self.assertEqual('-path',run.call_args.args[0][1])
        self.assertIn('size:>1024b',run.call_args.args[0])

    def test_everything_ipc_missing_returns_none(self):
        fake_result=types.SimpleNamespace(returncode=8,stdout=b'',stderr=b'')
        with mock.patch.object(app.subprocess,'run',return_value=fake_result):
            rows,msg=app.list_large_everything('es.exe',1024)
        self.assertIsNone(rows)
        self.assertIn('8',msg)

    def test_exe_detection_disallows_reparse(self):
        tools=self.root/'Tools';tools.mkdir()
        exe=tools/'es.exe';exe.write_bytes(b'fake')
        with mock.patch.object(app.engine,'is_reparse_or_link',return_value=False):
            result=app.detect_es_exe(self.root,environ={})
        self.assertEqual(result,str(exe))


class SecurityServerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer=app.Analyzer()
        self.http=ThreadingHTTPServer(('127.0.0.1',0),app.LocalHandler)
        self.http.session_token='a'*40
        self.http.analyzer=self.analyzer
        self.http.toolbox=app.Toolbox(log=self.analyzer._record)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.finish)

    def finish(self):
        self.http.shutdown();self.http.server_close();self.thread.join(timeout=3)

    def request(self,method,path,body=None,header=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.http.server_port,timeout=4)
        headers={'Host':'127.0.0.1:'+str(self.http.server_port)}
        if header:headers.update(header)
        connection.request(method,path,body=body,headers=headers)
        res=connection.getresponse();data=res.read();status=res.status;connection.close()
        return status,data

    def test_wrong_token_403(self):
        status,_=self.request('GET','/?t=invalid')
        self.assertEqual(403,status)

    def test_auth_state_200(self):
        status,data=self.request('GET','/api/state?t='+self.http.session_token)
        self.assertEqual(200,status)
        self.assertIn(b'"version":"3.5.2-beta.1"',data)

    def test_main_page_200(self):
        status,data=self.request('GET','/?t='+self.http.session_token)
        self.assertEqual(200,status)
        self.assertIn(b'C-Scan Studio',data)

    def test_post_without_origin_forbidden(self):
        status,_=self.request('POST','/api/clean',b'{}',{
            'X-CSCAN-Token':self.http.session_token,
            'Content-Type':'application/json'
        })
        self.assertEqual(403,status)

    def test_post_without_header_forbidden(self):
        status,_=self.request('POST','/api/clean',b'{}',{'Origin':f'http://127.0.0.1:{self.http.server_port}',
                                                      'Content-Type':'application/json'})
        self.assertEqual(403,status)

    def test_post_wrong_origin_forbidden(self):
        status,_=self.request('POST','/api/clean',b'{}',{'Origin':'https://example.com',
                                                      'X-CSCAN-Token':self.http.session_token,
                                                      'Content-Type':'application/json'})
        self.assertEqual(403,status)

    def test_authorized_unconfirmed_clean_blocked(self):
        status,data=self.request('POST','/api/clean',b'{"ids":["any"]}',{
            'Origin':f'http://127.0.0.1:{self.http.server_port}',
            'X-CSCAN-Token':self.http.session_token, 'Content-Type':'application/json'
        })
        self.assertEqual(409,status)
        self.assertIn('DELETE'.encode(),data)

    def test_report_json(self):
        status,data=self.request('GET','/api/export?t='+self.http.session_token)
        self.assertEqual(200,status)
        self.assertIn(b'"cache_items"',data)

    def test_report_csv(self):
        status,data=self.request('GET','/api/export?type=csv&t='+self.http.session_token)
        self.assertEqual(200,status)
        self.assertTrue(data.startswith(b'\xef\xbb\xbf'))

    def test_no_unlisted_path(self):
        status,_=self.request('GET','/tmp/unknown?t='+self.http.session_token)
        self.assertEqual(404,status)


if __name__ == '__main__':
    unittest.main(verbosity=2)
