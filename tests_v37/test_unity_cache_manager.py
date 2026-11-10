# -*- coding: utf-8 -*-
"""Unity diagnostics regressions; all filesystem fixtures are temporary."""
import builtins
import json
import ntpath
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import Unity_Cache_Manager as unity


class CleanupAllowlistTests(unittest.TestCase):
    def specs(self):
        profile = Path(r"C:\Users\tester")
        return unity.cleanup_specs(profile, profile / "AppData" / "Local", None)

    def test_canonical_gi_path_and_precise_cache_subfolders(self):
        rows = self.specs()
        paths = [ntpath.normpath(str(r["path"])) for r in rows]
        self.assertIn(r"C:\Users\tester\AppData\LocalLow\Unity\Caches\GiCache", paths)
        self.assertIn(r"C:\Users\tester\AppData\Local\Unity\cache\upm", paths)
        self.assertNotIn(r"C:\Users\tester\AppData\Local\Unity\cache", paths)
        self.assertNotIn(r"C:\Users\tester\AppData\Local\Unity", paths)

    def test_custom_cache_environment_cannot_authorize_deletion(self):
        expected = self.specs()
        with patch.dict(os.environ, {"UPM_CACHE_ROOT": r"C:\Documents", "ASSETSTORE_CACHE_PATH": r"D:\Assets"}):
            self.assertEqual(self.specs(), expected)

    def test_missing_user_roots_do_not_create_relative_targets(self):
        self.assertEqual(unity.cleanup_specs(None, Path("relative")), [])
        self.assertEqual(unity.cleanup_specs(Path("relative"), None), [])

    def test_logs_are_exact_names_and_age_bound(self):
        logs = [r for r in self.specs() if r["group"] == "unity-logs"]
        self.assertEqual(len(logs), 1)
        self.assertEqual(set(logs[0]["file_names"]), {"Editor.log", "Editor-prev.log", "upm.log", "upm-prev.log"})
        self.assertGreaterEqual(unity.UNITY_GROUPS["unity-logs"][1], 14)

    def test_no_assets_bee_gradle_sdk_or_licenses_in_allowlist(self):
        for row in self.specs():
            self.assertNotIn(row["group"], {"unity-assets", "unity-bee", "unity-gradle", "unity-sdk"})
            self.assertIn("unity.exe", row["process_names"])
            self.assertIn("unity hub.exe", row["process_names"])
            self.assertIn("unitypackagemanager.exe", row["process_names"])
        self.assertIn("unity-upm", unity.OFFLINE_GROUPS)


class PathValidationTests(unittest.TestCase):
    def test_local_absolute_cache_path_is_accepted(self):
        value, error = unity._validated_path(r"D:\UnityCache\UPM", r"C:\Users\tester")
        self.assertEqual(value, r"D:\UnityCache\UPM")
        self.assertFalse(error)

    def test_root_network_device_relative_ads_and_traversal_are_rejected(self):
        for value in ("C:\\", "D:", r"D:relative", r"\\server\share\cache", r"\\?\C:\cache",
                      r"D:\cache\..\Users", r"D:\cache:stream", r"%LOCALAPPDATA%\Unity\cache",
                      r"C:\Windows\System32", "D:\\cache\x00x", r"D:\cache\x.", r"D:\cache\*"):
            with self.subTest(value=value):
                self.assertIsNone(unity._validated_path(value)[0])

    def test_broad_user_directories_are_not_cache_locations(self):
        profile = r"C:\Users\tester"
        for path in (profile, profile + r"\AppData", profile + r"\AppData\Local", profile + r"\Documents",
                     profile + r"\Desktop", profile + r"\Downloads", r"C:\Users", r"C:\Program Files"):
            with self.subTest(path=path):
                self.assertIsNone(unity._validated_path(path, profile)[0])

    def test_invalid_profile_stops_audit_without_measurement(self):
        with patch.object(unity, "WINDOWS", True), patch.object(unity, "measure_directory") as scan:
            for profile in ("", r"C:\Windows", r"C:\Users", r"\\server\profile", r"D:relative"):
                report = unity.audit({"USERPROFILE": profile})
                self.assertEqual(report["items"], [])
                self.assertFalse(report["complete"])
            scan.assert_not_called()


class ReadOnlyWalkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "cache"
        self.root.mkdir()

    def put(self, relative, data=b"cache bytes"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def scan(self, **kwargs):
        return unity.measure_directory(self.root, **kwargs)

    def test_measurement_does_not_open_file_contents_or_modify_files(self):
        first = self.put("first.dat", b"abcd")
        second = self.put("nested/second.dat", b"abcdef")
        with patch.object(builtins, "open", side_effect=AssertionError("must not read file data")):
            report = self.scan()
        self.assertTrue(report["complete"])
        self.assertEqual((report["bytes"], report["count"]), (10, 2))
        self.assertEqual(first.read_bytes(), b"abcd")
        self.assertEqual(second.read_bytes(), b"abcdef")

    def test_missing_is_explicit_and_not_an_error(self):
        report = unity.measure_directory(self.base / "missing")
        self.assertFalse(report["exists"])
        self.assertEqual(report["state"], "未找到")
        self.assertTrue(report["complete"])

    def test_log_filter_never_traverses_nested_directories(self):
        self.put("Editor.log", b"yes")
        self.put("secret.json", b"do not count")
        self.put("nested/Editor.log", b"do not count")
        report = self.scan(file_names=unity.EDITOR_LOG_NAMES)
        self.assertEqual((report["bytes"], report["count"]), (3, 1))

    def test_file_count_limit_marks_partial(self):
        for i in range(30):
            self.put(str(i) + ".bin", b"x")
        report = self.scan(max_entries=7)
        self.assertEqual(report["checked"], 7)
        self.assertEqual(report["count"], 7)
        self.assertFalse(report["complete"])

    def test_zero_budget_does_not_enumerate_directory(self):
        self.put("some.dat")
        with patch.object(unity.os, "scandir", side_effect=AssertionError("budget exhausted")):
            report = self.scan(max_entries=0)
        self.assertFalse(report["complete"])
        self.assertEqual(report["bytes"], 0)

    def test_cancelled_scan_preserves_all_files(self):
        file = self.put("some.dat")
        stop = threading.Event()
        stop.set()
        report = self.scan(stop=stop)
        self.assertFalse(report["complete"])
        self.assertEqual(report["count"], 0)
        self.assertTrue(file.exists())

    def test_expired_deadline_is_partial_not_zero_occupancy(self):
        self.put("some.dat")
        report = self.scan(deadline=time.monotonic() - 1)
        self.assertFalse(report["complete"])
        self.assertIn("限额", report["state"])

    def test_permission_error_is_partial(self):
        self.put("some.dat")
        with patch.object(unity.os, "scandir", side_effect=PermissionError("fixture")):
            report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual(report["errors"], 1)

    def test_root_metadata_permission_error_does_not_claim_missing(self):
        with patch.object(unity.os, "lstat", side_effect=PermissionError("fixture")):
            report = self.scan()
        self.assertIsNone(report["exists"])
        self.assertFalse(report["complete"])
        self.assertEqual(report["errors"], 1)
        self.assertIn("尚未确认", report["state"])

    def test_hardlinks_and_overlapping_roots_are_counted_once(self):
        first = self.put("nested/first.dat", b"123456")
        try:
            os.link(first, self.root / "second.dat")
        except OSError:
            self.skipTest("hardlinks unavailable on fixture filesystem")
        seen = set()
        first_report = self.scan(seen_files=seen)
        second_report = unity.measure_directory(self.root / "nested", seen_files=seen)
        self.assertEqual(first_report["bytes"], 6)
        self.assertEqual(first_report["count"], 1)
        self.assertEqual(first_report["duplicate_files"], 1)
        self.assertEqual(second_report["bytes"], 0)
        self.assertEqual(second_report["duplicate_files"], 1)
        self.assertIn("已计入其他位置", second_report["state"])

    def test_windows_zero_direntry_identities_use_fresh_lstat(self):
        first = self.put("nested/first.dat", b"123456")
        self.put("separate.dat", b"789")
        try:
            os.link(first, self.root / "second.dat")
        except OSError:
            self.skipTest("hardlinks unavailable on fixture filesystem")
        actual_scandir = os.scandir

        class ZeroIdentityEntry:
            def __init__(self, entry):
                self.path, self.name = entry.path, entry.name

            def stat(self, **kwargs):
                info = os.lstat(self.path)
                return SimpleNamespace(st_dev=0, st_ino=0, st_mode=info.st_mode,
                                       st_size=info.st_size, st_file_attributes=0)

        class WindowsStyleScan:
            def __init__(self, path):
                self.scan = actual_scandir(path)

            def __enter__(self):
                return (ZeroIdentityEntry(entry) for entry in self.scan.__enter__())

            def __exit__(self, *args):
                return self.scan.__exit__(*args)

        with patch.object(unity, "WINDOWS", True), patch.object(unity.os, "scandir", side_effect=WindowsStyleScan):
            report = self.scan()
        self.assertTrue(report["complete"])
        self.assertEqual((report["bytes"], report["count"]), (9, 2))
        self.assertEqual(report["duplicate_files"], 1)

    def test_symlink_target_is_not_followed(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "private.txt").write_bytes(b"must not count")
        try:
            (self.root / "linked").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlinks unavailable without Windows privilege")
        report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual(report["count"], 0)
        self.assertGreater(report["skipped"], 0)

    def test_root_symlink_is_not_followed(self):
        self.put("private.dat")
        alias = self.base / "alias"
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except OSError:
            self.skipTest("symlinks unavailable without Windows privilege")
        report = unity.measure_directory(alias)
        self.assertFalse(report["complete"])
        self.assertEqual(report["bytes"], 0)

    def test_queued_directory_replacement_is_not_followed(self):
        queued = self.root / "queued"
        queued.mkdir()
        self.put("queued/original.dat", b"old")
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "private.dat").write_bytes(b"must not count")
        probe = self.base / "probe"
        try:
            probe.symlink_to(outside, target_is_directory=True)
            probe.unlink()
        except OSError:
            self.skipTest("symlinks unavailable without Windows privilege")
        actual_scandir = os.scandir

        class SwapAfterIteration:
            def __init__(self):
                self.scan = actual_scandir(self_outer.root)

            def __enter__(self):
                return self.scan.__enter__()

            def __exit__(self, *args):
                value = self.scan.__exit__(*args)
                queued.rename(self_outer.base / "original-folder")
                queued.symlink_to(outside, target_is_directory=True)
                return value

        self_outer = self

        def changed_scan(path):
            return SwapAfterIteration() if Path(path) == self.root else actual_scandir(path)

        with patch.object(unity.os, "scandir", side_effect=changed_scan):
            report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual(report["count"], 0)
        self.assertTrue((outside / "private.dat").exists())


class UpmConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / ".upmconfig.toml"

    def test_only_root_cache_path_is_exposed(self):
        self.config.write_text("cacheRoot = 'D:\\UnityCache\\UPM' # comment\n[scopedRegistries]\n"
                               "token = 'PRIVATE-TOKEN-DO-NOT-EXPOSE'\ncacheRoot = 'E:\\ignored'\n", encoding="utf-8")
        result = unity.read_upm_cache_root(self.root)
        self.assertTrue(result["valid"])
        self.assertEqual(result["value"], r"D:\UnityCache\UPM")
        self.assertNotIn("PRIVATE-TOKEN", json.dumps(result))
        self.assertNotIn("ignored", json.dumps(result))

    def test_double_quoted_escaped_windows_path(self):
        self.config.write_text('cacheRoot = "D:\\\\UnityCache\\\\UPM"\n', encoding="utf-8")
        result = unity.read_upm_cache_root(self.root)
        self.assertTrue(result["valid"])
        self.assertEqual(result["value"], r"D:\UnityCache\UPM")

    def test_duplicate_root_key_is_not_trusted(self):
        self.config.write_text("cacheRoot = 'D:\\first'\ncacheRoot = 'D:\\second'\n", encoding="utf-8")
        result = unity.read_upm_cache_root(self.root)
        self.assertFalse(result["valid"])
        self.assertEqual(result["value"], "")

    def test_large_config_is_not_opened(self):
        self.config.write_bytes(b"x" * (unity.MAX_CONFIG_BYTES + 1))
        with patch.object(builtins, "open", side_effect=AssertionError("too large")):
            result = unity.read_upm_cache_root(self.root)
        self.assertFalse(result["valid"])

    def test_config_link_is_ignored(self):
        target = self.root / "secret-config"
        target.write_text("cacheRoot = 'D:\\should-not-be-read'", encoding="utf-8")
        try:
            self.config.symlink_to(target)
        except OSError:
            self.skipTest("symlinks unavailable without Windows privilege")
        result = unity.read_upm_cache_root(self.root)
        self.assertFalse(result["valid"])
        self.assertEqual(result["value"], "")

    def test_config_replaced_between_lstat_and_open_is_rejected(self):
        self.config.write_text("cacheRoot = 'D:\\old'", encoding="utf-8")
        replacement = self.root / "replacement"
        replacement.write_text("cacheRoot = 'D:\\new'", encoding="utf-8")
        real_open = builtins.open

        def raced_open(*args, **kwargs):
            replacement.replace(self.config)
            return real_open(*args, **kwargs)

        with patch.object(builtins, "open", side_effect=raced_open):
            result = unity.read_upm_cache_root(self.root)
        self.assertFalse(result["valid"])
        self.assertEqual(result["value"], "")


class AuditContractTests(unittest.TestCase):
    def setUp(self):
        self.env = {"USERPROFILE": r"C:\Users\tester"}
        self.config = {"name": "cacheRoot", "value": "", "source": "fixture", "valid": False, "note": "missing"}

    @staticmethod
    def measurement(*args, **kwargs):
        return dict(bytes=10, count=1, checked=1, errors=0, skipped=0, duplicate_files=0,
                    complete=True, exists=True, state="fixture")

    def run_audit(self, extra=None):
        with patch.object(unity, "WINDOWS", True), patch.object(unity, "read_upm_cache_root", return_value=self.config), \
                patch.object(unity, "measure_directory", side_effect=self.measurement):
            return unity.audit(dict(self.env, **(extra or {})))

    def test_non_windows_never_scans_real_home(self):
        with patch.object(unity, "WINDOWS", False), patch.object(unity, "measure_directory") as scan:
            report = unity.audit({"HOME": str(Path.home()), "USERPROFILE": str(Path.home())})
        scan.assert_not_called()
        self.assertFalse(report["supported"])
        self.assertFalse(report["complete"])

    def test_c_and_d_bytes_are_reported_separately(self):
        report = self.run_audit({"UPM_CACHE_ROOT": r"D:\UnityCache\UPM"})
        self.assertEqual(report["totals_by_drive"]["D:"]["bytes"], 10)
        self.assertEqual(report["summary"]["other_drive_bytes"], 10)
        self.assertEqual(report["summary"]["c_drive_bytes"], report["totals_by_drive"]["C:"]["bytes"])
        self.assertEqual(report["summary"]["logical_bytes"], report["summary"]["c_drive_bytes"] + 10)

    def test_duplicate_default_and_environment_paths_are_merged(self):
        report = self.run_audit({"UPM_CACHE_ROOT": r"C:\Users\tester\AppData\Local\Unity\cache\upm"})
        upm = [row for row in report["items"] if row["path"].endswith(r"cache\upm")]
        self.assertEqual(len(upm), 1)
        self.assertEqual(len(upm[0]["aliases"]), 1)

    def test_asset_store_parent_gets_exact_suffix_but_upm_root_does_not(self):
        report = self.run_audit({"UPM_CACHE_ROOT": r"D:\MyUPM", "ASSETSTORE_CACHE_PATH": r"D:\AssetDownloads"})
        paths = {row["path"] for row in report["items"]}
        self.assertIn(r"D:\MyUPM", paths)
        self.assertNotIn(r"D:\MyUPM\upm", paths)
        self.assertIn(r"D:\AssetDownloads\Asset Store-5.x", paths)

    def test_gradle_scans_only_cache_subdirectories(self):
        report = self.run_audit({"GRADLE_USER_HOME": r"D:\GradleData"})
        paths = {row["path"] for row in report["items"]}
        self.assertIn(r"D:\GradleData\caches", paths)
        self.assertIn(r"D:\GradleData\wrapper\dists", paths)
        self.assertNotIn(r"D:\GradleData", paths)

    def test_invalid_custom_paths_are_reported_not_scanned(self):
        report = self.run_audit({"UPM_CACHE_ROOT": "C:\\", "ANDROID_HOME": r"\\server\sdk",
                                 "GI_CACHE_FOLDER": r"D:\UnverifiedGI"})
        paths = {row["path"] for row in report["items"]}
        self.assertNotIn("C:\\", paths)
        self.assertNotIn(r"\\server\sdk", paths)
        self.assertNotIn(r"D:\UnverifiedGI", paths)
        settings = {row["name"]: row for row in report["settings"]}
        self.assertFalse(settings["UPM_CACHE_ROOT"]["valid"])
        self.assertFalse(settings["GI_CACHE_FOLDER"]["valid"])

    def test_partial_measurement_propagates_to_volume_and_summary(self):
        def partial(*args, **kwargs):
            return dict(self.measurement(), complete=False, errors=1)

        with patch.object(unity, "WINDOWS", True), patch.object(unity, "read_upm_cache_root", return_value=self.config), \
                patch.object(unity, "measure_directory", side_effect=partial):
            report = unity.audit(self.env)
        self.assertFalse(report["complete"])
        self.assertFalse(report["summary"]["complete"])
        self.assertFalse(report["totals_by_drive"]["C:"]["complete"])

    def test_config_override_is_visible_without_adding_cleanup_authority(self):
        self.config.update(value=r"D:\ConfigUPM", valid=True)
        report = self.run_audit({"UPM_CACHE_ROOT": r"E:\ProcessUPM"})
        paths = {row["path"] for row in report["items"]}
        self.assertIn(r"D:\ConfigUPM", paths)
        self.assertIn(r"E:\ProcessUPM", paths)
        self.assertTrue(all(row["action"] == "只读诊断" for row in report["items"]))
        self.assertIn("未读取注册表", report["settings_scope"])


if __name__ == "__main__":
    unittest.main()
