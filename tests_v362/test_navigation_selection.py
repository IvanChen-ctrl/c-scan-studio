"""Read-only UI regression checks for beta.2."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
HTML=(ROOT/'ui/dashboard.html').read_text('utf-8')
class Beta2Tests(unittest.TestCase):
 def test_quicknav_is_accessible(self):
  for x in ('id="btn-quicknav"','aria-keyshortcuts="Control+K"','id="quicknav-dialog"','aria-modal="true"','function renderQuickNav()','quickNavPreviousFocus.focus()'):self.assertIn(x,HTML)
 def test_navigation_has_no_file_operations(self):
  code=HTML.split('const QUICK_NAV_KEYWORDS=',1)[1].split('function updateConnectionStatus()',1)[0]
  self.assertIn('switchPage(key)',code)
  for x in ('post(', 'startScan(', 'cleanSelected(', 'approvePreview('):self.assertNotIn(x,code)
 def test_selection_and_disconnect_fail_closed(self):
  for x in ('id="selection-review-strip"','id="clear-selection"',"connectionHealth='offline'","E('preview-approve').disabled=true","connectionHealth!=='online'","confirm:'DELETE'"):self.assertIn(x,HTML)
  self.assertNotIn("post('/api/inspect-delete'",HTML)
  self.assertNotIn("post('/api/inspect-move'",HTML)
  for value in ("previewRequestInFlight=true","cleanSubmitInFlight=true","selectionRevision!==revision","previewPageValidated=false","执行结果未能确认"):
   self.assertIn(value,HTML)
 def test_node_behavior_runner_is_wired(self):
  self.assertTrue((ROOT/'tests_v362/browser_behavior.cjs').is_file())
  ci=(ROOT/'.github/workflows/ci.yml').read_text('utf-8')
  release=(ROOT/'.github/workflows/release.yml').read_text('utf-8')
  self.assertIn('node tests_v362/browser_behavior.cjs',ci)
  self.assertIn('node tests_v362/browser_behavior.cjs',release)
 def test_js_syntax_when_node_installed(self):
  node=shutil.which('node')
  if not node:self.skipTest('Node unavailable')
  js=re.search(r'<script>(.*?)</script>',HTML,re.S)
  self.assertIsNotNone(js)
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp)/'ui.cjs';p.write_text(js.group(1),'utf-8')
   r=subprocess.run([node,'--check',str(p)],capture_output=True,text=True,timeout=20)
   self.assertEqual(r.returncode,0,r.stderr)
 def test_release_is_independent(self):
  import sys
  sys.path.insert(0,str(ROOT/'scripts'))
  import build_release
  self.assertEqual(build_release.VERSION,'3.6.0-beta.2')
  self.assertIn('tests_v362',build_release.SOURCE_DIRS)
  self.assertIn('v3.6.0-beta.2',(ROOT/'.github/workflows/release.yml').read_text('utf-8'))
if __name__=='__main__':unittest.main()
