"""v3.6.0-beta.4: synthetic stress and fail-closed preview snapshot regressions.

No test enumerates a Windows volume or permits disk deletion. Snapshot pages
use in-memory immutable synthetic file records; directory tests use temp roots.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock
import os
import threading
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import Advanced_Disk_Studio as app
import Drive_Inspector as inspector


class CountingSnapshots(list):
    """Count full-list iterations, which turn paginated reads into O(N*pages)."""
    def __init__(self, values):
        super().__init__(values)
        self.visits = 0

    def __iter__(self):
        for entry in super().__iter__():
            self.visits += 1
            yield entry


def manager_with_snapshots(count=100):
    with mock.patch.object(app.vendor, "local_cli_if_verified", return_value=None):
        manager = app.Analyzer()
    manager.items = [{
        "id": "safe", "name": "Synthetic user temp", "path": r"C:\FAKE\Cache",
        "risk": "green", "priority": "P1", "size": count * 512,
        "count": count, "age_days": 30, "allowed": True
    }]
    manager.targets = {
        "safe": SimpleNamespace(name="synthetic", path=Path(r"C:\FAKE\Cache"),
                                group="user-temp", process_name=None)
    }
    manager.snapshots = {
        "safe": CountingSnapshots(
            app.Snapshot(fr"C:\FAKE\Cache\file_{i:07d}.tmp", 512, 1000000000 + i)
            for i in range(count))
    }
    return manager


class LargePreviewPagination(unittest.TestCase):
    def test_80000_snapshots_320_pages_are_bounded(self):
        mgr = manager_with_snapshots(80_000)
        ok, _, preview = mgr.preview_clean(["safe"])
        self.assertTrue(ok)
        snapshots = mgr.snapshots["safe"]
        snapshots.visits = 0
        for i in range(320):
            offset = (i * 137) % (80_000 - 100)
            ok, msg, page = mgr.preview_files(preview["ticket"], offset, 100)
            self.assertTrue(ok, msg)
            self.assertEqual(page["total"], 80_000)
            self.assertEqual(len(page["files"]), 100)
            self.assertEqual(page["files"][0]["number"], offset + 1)
            self.assertEqual(page["next_offset"], offset + 100)
        # Unoptimized code copies the 80k-item list on every page = 25.6M
        # source reads. Page requests should never enumerate entire snapshots.
        self.assertLessEqual(snapshots.visits, 160_000)

    def test_16_parallel_preview_readers_are_consistent(self):
        mgr = manager_with_snapshots(25_000)
        ok, _, preview = mgr.preview_clean(["safe"])
        self.assertTrue(ok)
        snapshots = mgr.snapshots["safe"]
        snapshots.visits = 0

        def query(index):
            offset = (index * 73) % 24_900
            ok, msg, page = mgr.preview_files(preview["ticket"], offset, 100)
            self.assertTrue(ok, msg)
            self.assertEqual(page["total"], 25_000)
            self.assertEqual(page["files"][0]["number"], offset + 1)
            return len(page["files"])

        with ThreadPoolExecutor(max_workers=16) as pool:
            self.assertEqual(sum(pool.map(query, range(400))), 40_000)
        self.assertLessEqual(snapshots.visits, 50_000)

    def test_changed_path_same_count_revokes_preview_pagination(self):
        mgr = manager_with_snapshots(10)
        ok, _, preview = mgr.preview_clean(["safe"])
        self.assertTrue(ok)
        mgr.snapshots["safe"][0] = app.Snapshot(
            r"C:\FAKE\Cache\UNPREVIEWED_SECRET.tmp", 512, 1000000000)
        ok, _, page = mgr.preview_files(preview["ticket"], 0, 10)
        self.assertFalse(ok, "Ticket must not expose a new unpreviewed path")
        self.assertIsNone(page)
        self.assertIsNone(mgr.cleanup_preview)

    def test_changed_path_same_count_never_authorizes_clean(self):
        mgr = manager_with_snapshots(10)
        ok, _, preview = mgr.preview_clean(["safe"])
        self.assertTrue(ok)
        mgr.snapshots["safe"][-1] = app.Snapshot(
            r"C:\FAKE\Cache\NOT_IN_PREVIEW.tmp", 512, 1000000009)
        with mock.patch.object(app.threading, "Thread") as worker:
            started, _ = mgr.start_clean(["safe"], "DELETE", preview["ticket"])
        self.assertFalse(started, "Changed snapshots must block DELETE")
        self.assertFalse(worker.called)
        self.assertEqual(mgr.phase, "idle")
        self.assertIsNone(mgr.cleanup_preview)

    def test_unchanged_preview_can_be_approved_once_without_real_thread(self):
        mgr = manager_with_snapshots(6)
        ok, _, preview = mgr.preview_clean(["safe"])
        self.assertTrue(ok)
        with mock.patch.object(app.threading, "Thread") as worker:
            started, _ = mgr.start_clean(["safe"], "DELETE", preview["ticket"])
        self.assertTrue(started)
        self.assertTrue(worker.called)
        self.assertIsNone(mgr.cleanup_preview)
        self.assertFalse(mgr.start_clean(["safe"], "DELETE", preview["ticket"])[0])


class ReadOnlyDirectoryRaces(unittest.TestCase):
    def test_queued_directory_replaced_with_symlink_never_scans_outside(self):
        with TemporaryDirectory(prefix="cscan_owned_") as owned, \
             TemporaryDirectory(prefix="cscan_outside_") as elsewhere:
            root = Path(owned)
            safe = root / "safe"
            safe.mkdir()
            (Path(elsewhere) / "outside_only.txt").write_bytes(b"SYNTHETIC")
            # Skip platforms where unprivileged directory symlinks are disabled.
            probe = root / "symlink_probe"
            try:
                probe.symlink_to(elsewhere, target_is_directory=True)
                probe.unlink()
            except (OSError, NotImplementedError):
                self.skipTest("Directory symlinks unavailable")

            clock = [0.]
            injected = [False]

            def monotonic():
                clock[0] += 0.65
                return clock[0]

            def swap_after_root_scan(_):
                if not injected[0]:
                    injected[0] = True
                    safe.rename(root / "original_safe")
                    safe.symlink_to(elsewhere, target_is_directory=True)

            with mock.patch.object(inspector.time, "monotonic", side_effect=monotonic):
                report = inspector.inspect_roots(
                    [root], threading.Event(), min_duplicate_bytes=1000000,
                    max_scan_seconds=1e6, max_hash_seconds=1e6,
                    progress=swap_after_root_scan)
            self.assertTrue(injected[0])
            self.assertEqual(report["files_seen"], 0,
                             "The queued directory must not traverse a swapped symlink")
            self.assertGreaterEqual(report["permission_errors"], 1)
            self.assertFalse(report["inventory_complete"])

    def test_disappearing_folder_reports_incomplete_without_scanning_outside(self):
        with TemporaryDirectory(prefix="cscan_disconnected_") as owned:
            root = Path(owned)
            lost = root / "lost"
            lost.mkdir()
            (lost / "a.txt").write_text("synthetic", encoding="utf-8")
            original = inspector.os.scandir

            def flaky_scandir(path):
                if Path(path) == lost:
                    raise FileNotFoundError("Synthetic USB disconnect")
                return original(path)

            with mock.patch.object(inspector.os, "scandir", side_effect=flaky_scandir):
                report = inspector.inspect_roots(
                    [root], threading.Event(), min_duplicate_bytes=1000000)
            self.assertEqual(report["files_seen"], 0)
            self.assertGreaterEqual(report["permission_errors"], 1)
            self.assertFalse(report["inventory_complete"])
            self.assertFalse(report["complete"])
            self.assertIn("未完整", report["warning"])


if __name__ == "__main__":
    unittest.main()
