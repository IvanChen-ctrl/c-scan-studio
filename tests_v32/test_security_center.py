# -*- coding: utf-8 -*-
"""No actual Windows disk scanning or files outside isolated test roots."""
import csv
import hashlib
import http.client
import json
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import Security_Audit as audit
import Advanced_Disk_Studio as app


def write_manifest(root, paths):
    with (root/audit.MANIFEST).open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f);w.writerow(['Path','SHA256'])
        for name, data in paths:
            w.writerow((name,hashlib.sha256(data).hexdigest()))


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.ctx=tempfile.TemporaryDirectory()
        self.addCleanup(self.ctx.cleanup)
        self.root=Path(self.ctx.name)

    def test_successful_match(self):
        (self.root/'demo.py').write_bytes(b'print(42)\n')
        write_manifest(self.root,[('demo.py',b'print(42)\n')])
        result=audit.audit(self.root)
        self.assertEqual('matched',result['status'])
        self.assertEqual(result['matching'],1)
        self.assertFalse(result['scanned_for_malware'])
        self.assertEqual(0,result['network_requests'])

    def test_tampered_file_fails(self):
        (self.root/'main.py').write_bytes(b'harmless')
        write_manifest(self.root,[('main.py',b'original')])
        result=audit.audit(self.root)
        self.assertEqual('mismatch',result['status'])
        self.assertEqual(['main.py'],result['changed'])

    def test_missing_file_fails(self):
        write_manifest(self.root,[('missing.py',b'original')])
        result=audit.audit(self.root)
        self.assertEqual(['missing.py'],result['missing'])
        self.assertNotEqual('matched',result['status'])

    def test_reject_parent_traversal(self):
        write_manifest(self.root,[('../outside.py',b'anything')])
        result=audit.audit(self.root)
        self.assertEqual('mismatch',result['status'])
        self.assertIn('../outside.py',result['unsafe_paths'])

    def test_reject_absolute_and_drive_paths(self):
        for bad in ('/Windows/System32/drivers.sys',r'C:\Windows\file', 'a//b', 'a/../b', 'a:b'):
            self.assertFalse(audit.valid_relpath(bad))

    def test_symlink_never_followed(self):
        (self.root/'actual.bin').write_bytes(b'payload')
        try:
            (self.root/'alias.bin').symlink_to(self.root/'actual.bin')
        except (OSError, NotImplementedError):
            self.skipTest('symlinks unsupported')
        write_manifest(self.root,[('alias.bin',b'payload')])
        result=audit.audit(self.root)
        self.assertEqual('mismatch',result['status'])
        self.assertEqual(['alias.bin'],result['unsafe_paths'])

    def test_manifest_missing_no_claim(self):
        result=audit.audit(self.root)
        self.assertEqual('error',result['status'])
        self.assertFalse(result['scanned_for_malware'])

    def test_no_online_verdicts_fabricated(self):
        result=audit.audit(self.root)
        self.assertNotIn('virus_free',result)
        self.assertNotIn('antivirus_score',result)
        self.assertIn('不是无毒认证',result['title'])


class WebTests(unittest.TestCase):
    def setUp(self):
        self.http=ThreadingHTTPServer(('127.0.0.1',0),app.LocalHandler)
        self.http.analyzer=app.Analyzer()
        self.http.toolbox=app.Toolbox()
        self.http.session_token='testtoken'*5
        self.worker=threading.Thread(target=self.http.serve_forever,daemon=True)
        self.worker.start()
        self.addCleanup(self.close)

    def close(self):
        self.http.shutdown();self.http.server_close();self.worker.join(timeout=3)

    def call(self,path):
        client=http.client.HTTPConnection('127.0.0.1',self.http.server_port,timeout=5)
        client.request('GET',path,headers={'Host':'127.0.0.1:'+str(self.http.server_port)})
        response=client.getresponse();out=(response.status,response.read(),response.getheader('Content-Disposition'))
        client.close();return out

    def test_security_endpoint_denies_bad_token(self):
        status,body,_=self.call('/api/security?t=bad')
        self.assertEqual(403,status)

    def test_security_endpoint_reports_only_local_hashes(self):
        with mock.patch.object(app.security_audit,'audit',return_value={'status':'unverified','network_requests':0,'scanned_for_malware':False}):
            status,body,_=self.call('/api/security?t='+self.http.session_token)
        self.assertEqual(200,status)
        self.assertFalse(json.loads(body)['scanned_for_malware'])

    def test_security_report_download(self):
        status,body,cd=self.call('/api/security/export?t='+self.http.session_token)
        self.assertEqual(200,status)
        self.assertIn('attachment',cd)
        self.assertIn(b'"network_requests": 0',body)

    def test_security_tab_manual_links_and_privacy(self):
        html=(ROOT/'ui'/'dashboard.html').read_text(encoding='utf-8')
        for name in ('page-security','nav-security','btn-security-check','hash-lookup'):
            self.assertIn(name,html)
        for url in ('https://www.virustotal.com/gui/home/upload',
                    'https://metadefender.opswat.com/', 'https://virusscan.jotti.org/zh-cn'):
            self.assertIn(url,html)
        self.assertIn('不会替你上传文件',html)
        self.assertIn('rel="noopener noreferrer"',html)

    def test_security_mode_is_in_unified_dashboard(self):
        html=(ROOT/'ui'/'dashboard.html').read_text(encoding='utf-8')
        self.assertIn('page-security',html)
        self.assertIn('/api/security',html)
        self.assertEqual(1,len(list(ROOT.glob('*.bat'))))


if __name__=='__main__':
    unittest.main(verbosity=2)
