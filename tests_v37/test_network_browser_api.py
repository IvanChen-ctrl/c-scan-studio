"""Real local HTTP smoke tests for read-only network index pagination routes.

The localhost server is synthetic and no mapped drive is accessed. It verifies
session tokens, query validation, and that new GET endpoints cannot run cleanup.
"""
from http.server import ThreadingHTTPServer
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
import unittest
from pathlib import Path
from unittest import mock
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import Advanced_Disk_Studio as app
import Network_Browser as browser
import Network_Index as index


class HTTPIndexBrowserTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1',0),app.LocalHandler)
        self.server.session_token = 'regression-secret'
        with mock.patch.object(app.vendor,'local_cli_if_verified',return_value=None):
            self.server.analyzer = app.Analyzer()
        self.server.toolbox = None
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.finish)

    def finish(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=4)

    def get(self, endpoint, **params):
        args=urllib.parse.urlencode(params)
        url=f'http://127.0.0.1:{self.server.server_port}{endpoint}'
        return urllib.request.urlopen(url+('?' + args if args else ''),timeout=4)

    @staticmethod
    def parse(response):
        with response:return json.load(response)

    def test_authenticated_search_is_readonly_and_preserves_unicode(self):
        sample={'total':1200,'offset':100,'limit':100,'has_more':True,
                'rows':[{'name':'中国报告.pdf','path':'O:\\共享\\中国报告.pdf','size':0}],
                'state':'complete','partial':False}
        with mock.patch.object(self.server.analyzer,'list_network_drives',return_value=[{'id':'O:'}]),\
             mock.patch.object(index,'local_storage_drives',return_value=['D:']),\
             mock.patch.object(browser,'search',return_value=sample) as search:
            result=self.parse(self.get('/api/network-index/search',t='regression-secret',
                                       drive='O:',storage='D:',q='name:"中国 报告" ext:pdf',
                                       offset=100,limit=100))
        self.assertTrue(result['ok'])
        self.assertEqual(1200,result['page']['total'])
        self.assertEqual('中国报告.pdf',result['page']['rows'][0]['name'])
        search.assert_called_once_with('O:','D:','name:"中国 报告" ext:pdf',100,100)

    def test_missing_token_and_duplicate_query_are_rejected(self):
        for values in ({'drive':'O:','storage':'D:'},
                       {'t':'wrong','drive':'O:','storage':'D:'}):
            with self.assertRaises(urllib.error.HTTPError) as err:
                self.get('/api/network-index/search',**values)
            self.assertEqual(403,err.exception.code)
        url=f'http://127.0.0.1:{self.server.server_port}/api/network-index/search?t=regression-secret&drive=O%3A&storage=D%3A&q=one&q=two'
        with self.assertRaises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(url,timeout=3)
        self.assertEqual(400,err.exception.code)

    def test_bad_page_and_outside_mapping_rejected(self):
        cases=[dict(offset=-1),dict(offset=1000001),dict(limit=201),
               dict(offset='nan'),dict(recursive='yes')]
        for overrides in cases:
            params={'t':'regression-secret','drive':'O:','storage':'D:',**overrides}
            with self.subTest(params=overrides),self.assertRaises(urllib.error.HTTPError) as err:
                self.get('/api/network-index/search',**params)
            self.assertEqual(400,err.exception.code)
        with self.assertRaises(urllib.error.HTTPError) as err:
            self.get('/api/network-index/folders',t='regression-secret',drive='O:',storage='D:')
        self.assertEqual(400,err.exception.code)

    def test_folder_and_file_routes_forward_parameters_without_post(self):
        response={'total':0,'rows':[],'offset':0,'limit':100,'has_more':False}
        with mock.patch.object(self.server.analyzer,'list_network_drives',return_value=[{'id':'O:'}]),\
             mock.patch.object(index,'local_storage_drives',return_value=['D:']),\
             mock.patch.object(browser,'folder_children',return_value=response) as dirs,\
             mock.patch.object(browser,'folder_files',return_value=response) as files:
            self.assertTrue(self.parse(self.get('/api/network-index/folders',
                     t='regression-secret',drive='O:',storage='D:',folder='docs',q='2026'))['ok'])
            self.assertTrue(self.parse(self.get('/api/network-index/folder-files',
                     t='regression-secret',drive='O:',storage='D:',folder='docs',
                     recursive='false',q='ext:pdf'))['ok'])
        dirs.assert_called_once_with('O:','D:','docs','2026',0,100)
        files.assert_called_once_with('O:','D:','docs','ext:pdf',0,100,False)


if __name__=='__main__':unittest.main()
