"""Cross-platform tests for read-only, hierarchy-aware recommendations."""
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import Drive_Inspector as inspector
import Advanced_Disk_Studio as app


class SubtypeRulesTests(unittest.TestCase):
    def test_known_extension_groups_are_explainable(self):
        cases = [
            ('images','photo.jpg','raster'),('images','design.psd','design'),
            ('images','camera.dng','camera'),('documents','sheet.xlsx','office'),
            ('documents','report.pdf','pdf'),('models','weight.gguf','weights'),
            ('virtual_disks','vm.vhdx','volumes'),('code','main.py','source'),
            ('code','scene.unity','project'),('databases','my.db','database'),
            ('other','blob.qwerty','unclassified')]
        for cat, path, expected in cases:
            with self.subTest(cat=cat,path=path):
                sub,label = inspector.subtype_of(cat,path)
                self.assertEqual(sub,expected)
                self.assertTrue(label)

    def test_no_inferred_semantics(self):
        for file in ['portrait.mp4', 'portrait.pdf', 'portrait.py']:
            with self.subTest(file=file):
                cat=inspector.classification(file)['id']
                sub,label=inspector.subtype_of(cat,file)
                self.assertTrue(sub)
                self.assertNotIn('AI',label)


class HierarchyAggregateTests(unittest.TestCase):
    def setUp(self):
        self.data = [
            {'path':'D:/photos/x.jpg','size':100,'category':'images','volume':'D:',
             'subtype':'raster','subtype_label':'常见图片格式'},
            {'path':'E:/photos/y.jpg','size':120,'category':'images','volume':'E:',
             'subtype':'raster','subtype_label':'常见图片格式'},
            {'path':'D:/design/main.psd','size':800,'category':'images','volume':'D:',
             'subtype':'design','subtype_label':'设计与矢量格式'},
            {'path':'E:/model/m.gguf','size':6000,'category':'models','volume':'E:',
             'subtype':'weights','subtype_label':'AI 模型与推理权重'},
        ]

    def test_family_category_subtype_drive_sums(self):
        hierarchy = inspector.classification_hierarchy(self.data)
        self.assertEqual(sum(x['count'] for x in hierarchy), 4)
        self.assertEqual(sum(x['bytes'] for x in hierarchy), 7020)
        media = next(x for x in hierarchy if x['id']=='media')
        self.assertEqual(media['count'],3)
        self.assertEqual(media['bytes'],1020)
        images = media['categories'][0]
        self.assertEqual(images['id'],'images')
        self.assertEqual(images['count'],3)
        raster=next(x for x in images['subtypes'] if x['id']=='raster')
        self.assertEqual(raster['count'],2)
        self.assertEqual({x['id']:x['bytes'] for x in raster['drives']},{'D:':100,'E:':120})

    def test_hierarchy_does_not_expose_private_file_path(self):
        hierarchy = inspector.classification_hierarchy(self.data)
        self.assertNotIn('/photos/',str(hierarchy))
        self.assertNotIn('main.psd',str(hierarchy))

    def test_empty_hierarchy(self):
        self.assertEqual(inspector.classification_hierarchy([]),[])

    def test_aggregated_families_stable(self):
        a=inspector.classification_hierarchy(self.data)
        b=inspector.classification_hierarchy(list(reversed(self.data)))
        self.assertEqual(a,b)


class ScannerSnapshotTests(unittest.TestCase):
    def test_files_get_volume_subtype_and_hierarchy(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)
            (folder/'photo.jpg').write_bytes(b'a'*2050)
            (folder/'file.psd').write_bytes(b'b'*2070)
            (folder/'other.gguf').write_bytes(b'c'*2090)
            report=inspector.inspect_roots([folder],threading.Event(),min_duplicate_bytes=1)
            self.assertTrue(report['inventory_complete'])
            self.assertEqual(report['files_seen'],3)
            self.assertEqual(len(report['hierarchy']),2)
            self.assertEqual({x['subtype'] for x in report['classified_files']},
                             {'raster','design','weights'})
            self.assertEqual(len({x['volume'] for x in report['classified_files']}), 1)
            self.assertTrue(all(os.path.samefile(x['volume'], folder)
                                for x in report['classified_files']))
            self.assertEqual((folder/'file.psd').read_bytes(),b'b'*2070)

    def test_bounded_filtered_file_pagination(self):
        mgr=app.Analyzer()
        hierarchy=inspector.classification_hierarchy([
            {'path':'D:/first.jpg','size':50,'category':'images','volume':'D:','subtype':'raster','subtype_label':'常见图片格式'},
            {'path':'E:/second.jpg','size':50,'category':'images','volume':'E:','subtype':'raster','subtype_label':'常见图片格式'},
            {'path':'E:/third.psd','size':70,'category':'images','volume':'E:','subtype':'design','subtype_label':'设计与矢量格式'},
        ])
        mgr.inventory['categories']=[{'id':'images','label':'图片/设计素材'}]
        mgr.inventory['hierarchy']=hierarchy
        mgr.inventory['classified_files']=[
            {'path':'D:/first.jpg','size':50,'category':'images','subtype':'raster','volume':'D:'},
            {'path':'E:/second.jpg','size':50,'category':'images','subtype':'raster','volume':'E:'},
            {'path':'E:/third.psd','size':70,'category':'images','subtype':'design','volume':'E:'},
        ]
        ok,_,page=mgr.classified_files_page('images',0,50,'raster','D:')
        self.assertTrue(ok)
        self.assertEqual([x['path'] for x in page['files']],['D:/first.jpg'])
        self.assertEqual(page['total'],1)
        ok,_,page=mgr.classified_files_page('images',0,1,'raster')
        self.assertTrue(ok)
        self.assertEqual(page['total'],2)
        self.assertEqual(page['next_offset'],1)
        for subtype,drive in [('not_existing','D:'),('raster','C:'),('design','D:'),
                              ('raster','D:/folder'),('../source',None),('raster','\\\\server\\share')]:
            with self.subTest(subtype=subtype,drive=drive):
                ok,_,page=mgr.classified_files_page('images',0,50,subtype,drive)
                self.assertFalse(ok)
                self.assertIsNone(page)
        self.assertFalse(mgr.classified_files_page('images',0,50,[],None)[0])
        self.assertNotIn('classified_files',mgr.state()['inventory'])
        self.assertEqual(mgr.state()['inventory']['hierarchy'],hierarchy)

    def test_no_hierarchy_cannot_claim_filter(self):
        mgr=app.Analyzer()
        mgr.inventory['categories']=[{'id':'images'}]
        mgr.inventory['classified_files']=[{'category':'images','path':'D:/hello.jpg'}]
        self.assertFalse(mgr.classified_files_page('images',0,50,'raster','D:')[0])


class InterfaceSafetyTests(unittest.TestCase):
    def test_js_declares_goal_hierarchy_and_no_duplicate_deletion(self):
        js=(ROOT/'ui/dashboard.html').read_text('utf-8')
        for fragment in ('id="goal-select"','id="advice-tree"','function goalModel()',
                         'function renderCategoryTree(',"body.get('subtype'), body.get('drive')"):
            with self.subTest(fragment=fragment):
                if fragment.startswith('body.'):
                    self.assertIn(fragment,(ROOT/'Advanced_Disk_Studio.py').read_text('utf-8'))
                else:
                    self.assertIn(fragment,js)
        self.assertNotIn("post('/api/inspect-delete'",js)
        self.assertNotIn("post('/api/inspect-move'",js)
        self.assertIn("function renderAdvice()",js)


if __name__=='__main__':
    unittest.main()
