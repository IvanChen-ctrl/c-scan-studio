import csv
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import Share_Offline_Bundle as share


class ShareSafetyTests(unittest.TestCase):
    def test_only_allowlisted_source_and_exact_vendor_zip_are_packaged(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'src'
            root.mkdir()
            src=root/'clean.py'
            src.write_text('safe-source',encoding='utf-8')
            (root/'secret_report.json').write_text('private data',encoding='utf-8')
            (root/'bad.exe').write_bytes(b'malware-simulation')
            with (root/'FILE_INTEGRITY_SHA256.csv').open('w',newline='',encoding='utf-8-sig') as f:
                out=csv.DictWriter(f,fieldnames=['Path','SHA256']);out.writeheader()
                out.writerow({'Path':'clean.py','SHA256':hashlib.sha256(src.read_bytes()).hexdigest()})
            folder=root/'Tools'/'Official_Offline'
            folder.mkdir(parents=True)
            specs=[]
            for kind,name,exe in [('everything','e.zip','Everything.exe'),('es','s.zip','es.exe')]:
                with zipfile.ZipFile(folder/name,'w') as z:
                    z.writestr(exe,b'MZ-fake-for-TEST-only')
                specs.append({'kind':kind,'name':name,'sha256':hashlib.sha256((folder/name).read_bytes()).hexdigest()})
            dest=Path(t)/'friends.zip'
            with patch.object(share.vendor,'files_for_arch',return_value=specs):
                share.prepare_share(root,dest)
            with zipfile.ZipFile(dest) as z:
                names=z.namelist()
                self.assertTrue(any(n.endswith('clean.py') for n in names))
                self.assertFalse(any('secret' in n or 'bad.exe' in n for n in names))
                self.assertTrue(any(n.endswith('e.zip') for n in names))
                self.assertTrue(any(n.endswith('s.zip') for n in names))

if __name__=='__main__':
    unittest.main()
