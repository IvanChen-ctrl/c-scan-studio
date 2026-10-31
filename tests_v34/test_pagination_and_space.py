# -*- coding: utf-8 -*-
"""Beta 2 safety tests. No real C: scan, read, or unlink occurs."""
import http.client
import json
import sys
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import Advanced_Disk_Studio as app


class PreviewPages(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(app.vendor, "local_cli_if_verified", return_value=None):
            self.manager = app.Analyzer()
        self.manager.items = [
            {"id": "a", "name": "safe A", "path": r"C:\Fake\A", "risk": "green",
             "priority": "P1", "size": 6, "count": 3, "age_days": 14, "allowed": True},
            {"id": "b", "name": "safe B", "path": r"C:\Fake\B", "risk": "amber",
             "priority": "P2", "size": 9, "count": 2, "age_days": 30, "allowed": True},
            {"id": "blocked", "name": "important", "path": r"C:\important", "risk": "red",
             "priority": "P4", "size": 1000, "count": 1, "age_days": 20, "allowed": False},
        ]
        self.manager.targets = {
            k: SimpleNamespace(name=k, path=Path(r"C:\Fake"), group="user-temp", process_name=None)
            for k in ("a", "b", "blocked")
        }
        self.manager.snapshots = {
            "a": [app.Snapshot(rf"C:\Fake\A\{x}.tmp", x, x * 10) for x in (1, 2, 3)],
            "b": [app.Snapshot(rf"C:\Fake\B\{x}.cache", x+2, x * 10) for x in (4, 5)],
            "blocked": [app.Snapshot(r"C:\important\key", 1000, 10)],
        }

    def test_all_pages_are_complete_and_match_selected_categories(self):
        ok, _, preview = self.manager.preview_clean(["a", "b"])
        self.assertTrue(ok)
        names, offsets, total = [], [], 0
        next_offset = 0
        while next_offset is not None:
            ok, _, page = self.manager.preview_files(preview["ticket"], next_offset, 2)
            self.assertTrue(ok)
            offsets.append(page["offset"])
            names.extend(row["path"] for row in page["files"])
            total = page["total"]
            next_offset = page["next_offset"]
        self.assertEqual([0, 2, 4], offsets)
        self.assertEqual([r"C:\Fake\A\1.tmp", r"C:\Fake\A\2.tmp", r"C:\Fake\A\3.tmp",
                          r"C:\Fake\B\4.cache", r"C:\Fake\B\5.cache"], names)
        self.assertEqual(5, total)
        self.assertFalse(any("important" in x for x in names))
        self.assertIsNone(self.manager.thread)

    def test_only_selected_category_visible(self):
        ok, _, p = self.manager.preview_clean(["b"])
        self.assertTrue(ok)
        ok, _, data = self.manager.preview_files(p["ticket"], 0, 50)
        self.assertTrue(ok)
        self.assertEqual(2, data["total"])
        self.assertEqual(["b", "b"], [x["category"] for x in data["files"]])

    def test_bogus_ticket_cannot_list_files(self):
        self.manager.preview_clean(["a"])
        for ticket in ["not-the-ticket", "", None, 123]:
            ok, _, page = self.manager.preview_files(ticket, 0, 10)
            self.assertFalse(ok)
            self.assertIsNone(page)

    def test_missing_ticket_cannot_list_files(self):
        self.assertFalse(self.manager.preview_files("any", 0, 50)[0])

    def test_expired_ticket_cannot_list_files(self):
        _, _, p = self.manager.preview_clean(["a"])
        self.manager.cleanup_preview["expires"] = time.monotonic() - 1
        self.assertFalse(self.manager.preview_files(p["ticket"], 0, 10)[0])
        self.assertIsNone(self.manager.cleanup_preview)

    def test_bad_pagination_rejected(self):
        _, _, p = self.manager.preview_clean(["a"])
        for bad_offset, bad_limit in [(-1, 50), (0, 0), (0, 101), (0, -1),
                                       ("0", 50), (0, "50"), (False, 50), (0, True), (5, 50)]:
            self.assertFalse(self.manager.preview_files(p["ticket"], bad_offset, bad_limit)[0])

    def test_stale_window_cannot_revoke_new_ticket(self):
        _, _, old = self.manager.preview_clean(["a"])
        _, _, new = self.manager.preview_clean(["b"])
        ok, _ = self.manager.discard_preview(old["ticket"])
        self.assertFalse(ok)
        self.assertEqual(new["ticket"], self.manager.cleanup_preview["ticket"])
        self.assertTrue(self.manager.preview_files(new["ticket"])[0])
        self.assertTrue(self.manager.discard_preview(new["ticket"])[0])

    def test_new_scan_revokes_list_access(self):
        _, _, old = self.manager.preview_clean(["a"])
        with mock.patch.object(app.threading, "Thread"):
            self.manager._start("large", "fake", lambda: None)
        self.assertFalse(self.manager.preview_files(old["ticket"])[0])

    def test_mismatch_target_counts_rejects_pagination(self):
        _, _, old = self.manager.preview_clean(["a"])
        self.manager.snapshots["a"].pop()
        ok, _, page = self.manager.preview_files(old["ticket"])
        self.assertFalse(ok)
        self.assertIsNone(page)

    def test_pagination_does_not_delete_or_stat_files(self):
        _, _, p = self.manager.preview_clean(["a", "b"])
        with mock.patch.object(app.os, "unlink", side_effect=AssertionError("unlink called")), \
             mock.patch.object(app.os, "lstat", side_effect=AssertionError("lstat called")):
            self.assertTrue(self.manager.preview_files(p["ticket"], 0, 100)[0])


class SpaceComparison(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(app.vendor, "local_cli_if_verified", return_value=None):
            self.manager = app.Analyzer()
        self.target = SimpleNamespace(name="temporary", path=Path(r"C:\Fake"),
                                      group="user-temp", process_name=None)

    def run_simulated(self, before, after, outcome=None):
        result = outcome or {"deleted": 2, "bytes": 128, "errors": 0, "skipped": 1, "state": "完成"}
        with mock.patch.object(self.manager, "_disk", side_effect=[before, after]), \
             mock.patch.object(app.engine, "active_processes", return_value=set()), \
             mock.patch.object(app, "clean_snapshot_target", return_value=result), \
             mock.patch.object(self.manager, "_auto_report"):
            self.manager._clean([("id", self.target, [], 14)])
        return self.manager.last_cleanup

    def test_positive_net_change_is_not_confused_with_logical_bytes(self):
        x = self.run_simulated({"total": 1000, "free": 100, "used": 900},
                               {"total": 1000, "free": 180, "used": 820})
        self.assertEqual(128, x["totals"]["bytes"])
        self.assertEqual(80, x["disk_comparison"]["net_free_change"])
        self.assertTrue(x["disk_comparison"]["available"])
        self.assertEqual(2, x["totals"]["deleted"])
        self.assertIn("同期其他程序", x["disk_comparison"]["disclaimer"])

    def test_negative_net_change_is_preserved(self):
        x = self.run_simulated({"total": 1000, "free": 180, "used": 820},
                               {"total": 1000, "free": 100, "used": 900})
        self.assertEqual(-80, x["disk_comparison"]["net_free_change"])
        self.assertEqual(128, x["totals"]["bytes"])

    def test_unavailable_disk_usage_is_explicitly_unknown(self):
        x = self.run_simulated({"total": 0, "free": 0, "used": 0},
                               {"total": 0, "free": 0, "used": 0})
        self.assertIsNone(x["disk_comparison"]["net_free_change"])
        self.assertIsNone(x["disk_comparison"]["before_free"])
        self.assertFalse(x["disk_comparison"]["available"])

    def test_different_disk_totals_decline_comparison(self):
        x = self.run_simulated({"total": 1000, "free": 100, "used": 900},
                               {"total": 1100, "free": 180, "used": 920})
        self.assertFalse(x["disk_comparison"]["available"])

    def test_canceled_worker_still_reports_measurement(self):
        self.manager.cancel.set()
        x = self.run_simulated({"total": 1000, "free": 100, "used": 900},
                               {"total": 1000, "free": 100, "used": 900})
        self.assertTrue(x["aborted"])
        self.assertEqual(0, x["totals"]["deleted"])
        self.assertEqual(0, x["disk_comparison"]["net_free_change"])


class PreviewHTTP(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(app.vendor, "local_cli_if_verified", return_value=None):
            self.manager = app.Analyzer()
        self.manager.items = [{"id": "known", "name": "safe", "path": r"C:\Fake", "risk": "green",
                               "priority": "P1", "size": 1, "count": 1, "age_days": 14, "allowed": True}]
        self.manager.targets = {"known": SimpleNamespace(name="safe")}
        self.manager.snapshots = {"known": [app.Snapshot(r"C:\Fake\item.tmp", 1, 10)]}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), app.LocalHandler)
        self.server.session_token = "k" * 48
        self.server.analyzer = self.manager
        self.server.toolbox = app.Toolbox(log=self.manager._record)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.shutdown)

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)

    def post(self, payload, valid_origin=True, valid_token=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {"Content-Type": "application/json",
                   "Host": f"127.0.0.1:{self.server.server_port}",
                   "Origin": f"http://127.0.0.1:{self.server.server_port}" if valid_origin else "https://evil.example",
                   "X-CSCAN-Token": self.server.session_token if valid_token else "invalid"}
        conn.request("POST", "/api/preview-files", json.dumps(payload).encode("utf-8"), headers=headers)
        r = conn.getresponse()
        status, data = r.status, json.loads(r.read().decode("utf-8"))
        conn.close()
        return status, data

    def test_valid_ticket_returns_selected_snapshot_only(self):
        _, _, p = self.manager.preview_clean(["known"])
        status, data = self.post({"ticket": p["ticket"], "offset": 0, "limit": 50})
        self.assertEqual(200, status)
        self.assertEqual(r"C:\Fake\item.tmp", data["page"]["files"][0]["path"])

    def test_wrong_token_and_origin_blocked(self):
        _, _, p = self.manager.preview_clean(["known"])
        payload={"ticket": p["ticket"], "offset": 0, "limit": 50}
        self.assertEqual(403, self.post(payload, valid_token=False)[0])
        self.assertEqual(403, self.post(payload, valid_origin=False)[0])

    def test_no_ticket_denied_by_api(self):
        self.assertEqual(409, self.post({"offset": 0, "limit": 50})[0])


if __name__ == "__main__":
    unittest.main()
