"""Structural guardrails for C-Scan Studio 3.6 ergonomic, safety-first UI."""
from pathlib import Path
import re
import unittest

BASE=Path(__file__).resolve().parents[1]
HTML=(BASE/'ui/dashboard.html').read_text('utf-8')

class ErgonomicUiTests(unittest.TestCase):
    def test_single_focus_and_priority_queue(self):
        for name in ['focus-action','priority-queue','queue-row','focus-button','id="action-cards"','function renderDecisionHub()']:
            self.assertIn(name,HTML)

    def test_main_navigation_gives_context(self):
        for text in ['id="page-breadcrumb"','PAGE_BREADCRUMB','aria-current','id="density-toggle"', 'function toggleDensity()', 'data-view="cache"']:
            self.assertIn(text,HTML)

    def test_safe_controls_remain_explicit(self):
        self.assertIn("id=\"clean-preview-dialog\"",HTML)
        self.assertIn("id=\"btn-clean\" disabled",HTML)
        self.assertIn("'DELETE'",HTML)
        self.assertIn("post('/api/cancel-preview'",HTML)
        self.assertNotIn("post('/api/inspect-delete'",HTML)
        self.assertNotIn("post('/api/inspect-move'",HTML)

    def test_mobile_scan_uses_cards_not_inert_table(self):
        for name in ['cache-mobile-cards','renderMobileCache(list)','data-mobile-check','data-mobile-detail','E(\'cache-mobile-cards\').addEventListener']:
            self.assertIn(name,HTML)
        self.assertIn('.cache-desktop-table{display:none!important}',HTML)

    def test_mobile_navigation_is_discoverable(self):
        self.assertIn('.sidebar .nav-text{display:inline!important',HTML)
        self.assertIn('.sidebar .nav-btn{display:flex!important',HTML)
        self.assertIn('min-height:45px!important',HTML)

    def test_accessibility(self):
        self.assertIn('prefers-reduced-motion:reduce',HTML)
        self.assertIn(':focus-visible',HTML)
        self.assertIn('aria-label="多盘分析步骤"',HTML)
        self.assertIn('aria-label="切换舒适或紧凑显示密度"',HTML)

    def test_real_section_jumps(self):
        for id in ['inspect-config','inspect-classify','inspect-duplicates-section']:
            self.assertIn(f'id="{id}"',HTML)
        self.assertIn('function scrollToInspect(',HTML)

    def test_source_release_name_and_ci(self):
        from sys import path
        path.insert(0,str(BASE/'scripts'))
        import build_release
        self.assertEqual(build_release.VERSION,'3.6.0-beta.2')
        self.assertIn('tests_v36',build_release.SOURCE_DIRS)
        workflow=(BASE/'.github/workflows/ci.yml').read_text('utf-8')
        self.assertIn('python -m unittest discover -s tests_v36',workflow)
        release=(BASE/'.github/workflows/release.yml').read_text('utf-8')
        self.assertIn('EXPECTED_TAG: v3.6.0-beta.2',release)
        self.assertIn('CodeQL',release)

    def test_illustrations_are_labeled_demo(self):
        for name in ['v3.6_overview_desktop_DEMO.png','v3.6_mobile_cards_DEMO.png','v3.6_guidance_desktop_DEMO.png']:
            self.assertTrue((BASE/'docs/screenshots'/name).is_file())
        self.assertIn('模拟数据',(BASE/'README.md').read_text('utf-8'))

if __name__=='__main__': unittest.main()
