# -*- coding: utf-8 -*-
"""Isolated safety tests: no real system file is scanned or deleted."""
import datetime as dt
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import C_Drive_Cleanup as app


class PathGuardTests(unittest.TestCase):
    def test_only_absolute_c_drive(self):
        self.assertTrue(app.is_c_drive(r"C:\Users\user\AppData\Local\Temp"))
        for unsafe in (r"D:\Temp", r"C:relative", r"\\server\share", "", "C"):
            self.assertFalse(app.is_c_drive(unsafe))

    def test_lexical_boundary_prevents_sibling(self):
        self.assertTrue(app.strictly_within(r"C:\Users\alice\Temp", r"C:\Users\alice"))
        self.assertFalse(app.strictly_within(r"C:\Users\alice2\Temp", r"C:\Users\alice"))
        self.assertFalse(app.strictly_within(r"C:\Users\alice", r"C:\Users\alice"))
        self.assertFalse(app.strictly_within(r"D:\Users\alice\Temp", r"C:\Users\alice"))

    def test_groups_whitelist(self):
        self.assertEqual(app.parse_groups("pip,uv,pip"), ["pip", "uv"])
        self.assertEqual(set(app.parse_groups("all")), set(app.GROUPS))
        with self.assertRaises(ValueError):
            app.parse_groups("all,user-temp")
        with self.assertRaises(ValueError):
            app.parse_groups("destructive-everything")

    def test_one_click_never_includes_system_crash_or_conda_directories(self):
        self.assertTrue(set(app.ONE_CLICK_GROUPS).issubset(app.GROUPS))
        self.assertFalse(set(app.ONE_CLICK_GROUPS).intersection(
            {"crash", "system-temp", "system-wer"}))
        self.assertNotIn("conda", app.ONE_CLICK_GROUPS)
        self.assertNotIn("conda-pkgs", app.ONE_CLICK_GROUPS)

    def test_one_click_preserves_recent_user_temp(self):
        self.assertGreaterEqual(app.GROUPS["user-temp"][1], 14)
        self.assertGreaterEqual(app.GROUPS["wer"][1], 14)


class CleaningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.cache = self.base / "AppData" / "Local" / "Temp"
        self.cache.mkdir(parents=True)
        self.target = app.Target("user-temp", "Mock User Temp", self.cache, self.base)
        # Windows C:\ path checks are tested separately above. This mock allows
        # safe file-operation testing on a temporary Linux filesystem.
        patcher = patch.object(app.Target, "valid", lambda self: True)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def old(path, days=20, data=b"sample"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        mark = time.time() - days * 86400
        os.utime(path, (mark, mark))

    def test_scan_is_read_only_and_clean_respects_age(self):
        old = self.cache / "old-cache.dat"
        young = self.cache / "recent.dat"
        self.old(old, days=20, data=b"older bytes")
        young.write_bytes(b"recent")
        scan = app.scan_target(self.target, 7)
        self.assertEqual(scan.metrics.candidates, 1)
        self.assertEqual(scan.metrics.bytes, len(b"older bytes"))
        self.assertTrue(old.exists())
        self.assertTrue(young.exists())

        clean = app.clean_target(self.target, 7, set())
        self.assertEqual(clean.metrics.deleted_files, 1)
        self.assertFalse(old.exists())
        self.assertTrue(young.exists())
        self.assertTrue(self.cache.exists())

    def test_valuable_temp_subdirectories_are_protected(self):
        important = self.cache / ".venv" / "important_model.bin"
        safe = self.cache / "cache-subdir" / "expired.bin"
        self.old(important, 45)
        self.old(safe, 45)
        scan = app.scan_target(self.target, 7)
        self.assertEqual(scan.metrics.candidates, 1)
        clean = app.clean_target(self.target, 7, set())
        self.assertEqual(clean.metrics.deleted_files, 1)
        self.assertTrue(important.exists())
        self.assertFalse(safe.exists())

    def test_project_directory_markers_prevent_deletion(self):
        project = self.cache / "strange-id-987"
        readme = project / "src" / "program.py"
        another = project / "src" / "temp.txt"
        self.old(readme, 40)
        self.old(another, 40)
        (project / "pyproject.toml").write_text("[project]\nname='keep-me'", encoding="utf-8")
        result = app.clean_target(self.target, 14, set())
        self.assertEqual(result.metrics.deleted_files, 0)
        self.assertTrue(readme.exists())
        self.assertTrue(another.exists())

    def test_important_file_extensions_in_temp_are_preserved(self):
        important = ("model.safetensors", "backup.zip", "source.py", "dataset.onnx",
                     "document.ipynb", "movie.mp4", "bootstrap.ps1", "photo.png",
                     "song.wav", "report.pdf", "diagnostics.txt")
        for name in important:
            self.old(self.cache / name, 45)
        self.old(self.cache / "clean-me.tmp", 45)
        result = app.clean_target(self.target, 14, set())
        self.assertEqual(result.metrics.deleted_files, 1)
        for name in important:
            self.assertTrue((self.cache / name).exists(), name)
        self.assertFalse((self.cache / "clean-me.tmp").exists())

    def test_toolkit_is_preserved_if_extracted_inside_temp(self):
        toolkit = self.cache / "cleanup-tool"
        package = toolkit / "my-data.tmp"
        self.old(package, 45)
        self.old(self.cache / "safe-old.tmp", 45)
        with patch.object(app, "TOOLKIT_DIR", toolkit):
            result = app.clean_target(self.target, 14, set())
        self.assertEqual(result.metrics.deleted_files, 1)
        self.assertTrue(package.exists())

    def test_non_project_cache_group_does_not_block_zip_files(self):
        package_cache = self.base / "npm-cache"
        zip_file = package_cache / "package.zip"
        self.old(zip_file, 45)
        npm_target = app.Target("npm", "Mock npm", package_cache, self.base)
        res = app.clean_target(npm_target, 0, set())
        self.assertEqual(res.metrics.deleted_files, 1)
        self.assertFalse(zip_file.exists())

    def test_symlink_to_other_folder_never_traversed(self):
        outside = self.base / "very-important-project" / "model.bin"
        self.old(outside, 50)
        link = self.cache / "outside-junction"
        link.symlink_to(outside.parent, target_is_directory=True)
        scan = app.scan_target(self.target, 7)
        self.assertEqual(scan.metrics.candidates, 0)
        clean = app.clean_target(self.target, 7, set())
        self.assertEqual(clean.metrics.deleted_files, 0)
        self.assertTrue(outside.exists())
        self.assertTrue(link.is_symlink())

    def test_symlink_file_never_unlinked(self):
        outside = self.base / "valuable-file.bin"
        self.old(outside, 60)
        link = self.cache / "alias-to-valuable.bin"
        link.symlink_to(outside)
        clean = app.clean_target(self.target, 7, set())
        self.assertEqual(clean.metrics.deleted_files, 0)
        self.assertTrue(link.is_symlink())
        self.assertTrue(outside.exists())

    def test_permission_error_keeps_file_and_continues(self):
        first = self.cache / "first-old.dat"
        self.old(first, 15)
        original_unlink = app.os.unlink
        def reject(path, *args, **kwargs):
            if Path(path) == first:
                raise PermissionError("file is locked")
            return original_unlink(path, *args, **kwargs)
        with patch.object(app.os, "unlink", side_effect=reject):
            result = app.clean_target(self.target, 7, set())
        self.assertEqual(result.metrics.deleted_files, 0)
        self.assertGreaterEqual(result.metrics.errors, 1)
        self.assertTrue(first.exists())

    def test_temp_empty_dirs_remain_for_running_apps(self):
        old = self.cache / "old.dat"
        recent_empty = self.cache / "running-app-empty-dir"
        recent_empty.mkdir()
        self.old(old, 20)
        result = app.clean_target(self.target, 7, set())
        self.assertEqual(result.metrics.deleted_files, 1)
        self.assertTrue(recent_empty.is_dir())

    def test_browser_process_guard(self):
        browser_cache = self.base / "browser-cache"
        old_file = browser_cache / "files" / "cached.bin"
        self.old(old_file, 40)
        browser = app.Target("browser", "Mock Firefox", browser_cache, self.base, "firefox.exe")
        active = app.clean_target(browser, 0, {"firefox.exe"})
        self.assertEqual(active.metrics.deleted_files, 0)
        self.assertIn("仍运行", active.status)
        fail_closed = app.clean_target(browser, 0, None)
        self.assertEqual(fail_closed.metrics.deleted_files, 0)
        self.assertTrue(old_file.exists())
        clean = app.clean_target(browser, 0, set())
        self.assertEqual(clean.metrics.deleted_files, 1)
        self.assertFalse(old_file.exists())
        self.assertTrue(browser_cache.exists())

    def test_reparse_ancestor_rejected(self):
        outside = self.base / "project"
        outside.mkdir()
        link = self.base / "redirected-temp"
        link.symlink_to(outside, target_is_directory=True)
        self.assertFalse(app.ancestors_clear(link / "subfolder"))

    def test_readonly_large_file_audit(self):
        root = self.base / "fake-drive"
        first = root / "Models" / "important.bin"
        second = root / "Cache" / "small.bin"
        self.old(first, 100, data=b"important-model-content")
        self.old(second, 50, data=b"cache-file")
        with patch.object(app, "report_directory", return_value=self.base):
            result = app.readonly_size_audit(1000, 5, root)
        self.assertEqual(result, 0)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())
        reports = list(self.base.glob("cleanup_*.json"))
        self.assertTrue(reports)
        summary = json.loads(reports[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["mode"], "readonly_size_audit")
        self.assertEqual(summary["files_seen"], 2)
        self.assertEqual(summary["top_level_bytes_scanned"]["Models"], len(b"important-model-content"))


class CondaCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conda_exe = Path(self.tmp.name) / "Miniconda3" / "Scripts" / "conda.exe"
        self.conda_exe.parent.mkdir(parents=True)
        self.conda_exe.write_text("mock", encoding="ascii")

    def test_conda_is_detectable_from_environment_without_path(self):
        with patch.object(app.shutil, "which", return_value=None):
            found = app.find_conda_exe({"CONDA_EXE": str(self.conda_exe)}, Path(self.tmp.name) / "python.exe")
        self.assertEqual(found, self.conda_exe)

    def test_conda_cache_guard_permits_c_only(self):
        out = SimpleNamespace(returncode=0,
                              stdout=json.dumps({"pkgs_dirs": [r"C:\Users\alice\.conda\pkgs",
                                                             r"C:\ProgramData\Miniconda3\pkgs"]}))
        with patch.object(app.subprocess, "run", return_value=out):
            valid, dirs = app.conda_pkgs_roots_c_only(self.conda_exe)
        self.assertTrue(valid)
        self.assertEqual(len(dirs), 2)

    def test_conda_cache_guard_blocks_other_volumes(self):
        out = SimpleNamespace(returncode=0,
                              stdout=json.dumps({"pkgs_dirs": [r"C:\conda\pkgs",
                                                             r"D:\conda\pkgs"]}))
        with patch.object(app.subprocess, "run", return_value=out):
            valid, _ = app.conda_pkgs_roots_c_only(self.conda_exe)
        self.assertFalse(valid)

    def test_conda_cache_guard_blocks_malformed_output(self):
        out = SimpleNamespace(returncode=0, stdout="not json")
        with patch.object(app.subprocess, "run", return_value=out):
            valid, dirs = app.conda_pkgs_roots_c_only(self.conda_exe)
        self.assertFalse(valid)
        self.assertEqual(dirs, [])

    def test_conda_cache_guard_blocks_unreported_cache(self):
        out = SimpleNamespace(returncode=0, stdout='{"pkgs_dirs": []}')
        with patch.object(app.subprocess, "run", return_value=out):
            valid, _ = app.conda_pkgs_roots_c_only(self.conda_exe)
        self.assertFalse(valid)

    def test_conda_preview_requires_explicit_keyword(self):
        with patch.object(app, "find_conda_exe", return_value=self.conda_exe), \
             patch.object(app, "conda_pkgs_roots_c_only", return_value=(True, [r"C:\conda\pkgs"])), \
             patch.object(app.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as preview, \
             patch("builtins.input", return_value="no") as confirm, \
             patch.object(app.subprocess, "call") as execute:
            result = app.run_conda_clean("index")
        self.assertEqual(result, 0)
        preview.assert_called_once()
        self.assertIn("--dry-run", preview.call_args.args[0])
        confirm.assert_called_once()
        execute.assert_not_called()

    def test_conda_approved_command_does_not_delete_installed_packages(self):
        with patch.object(app, "find_conda_exe", return_value=self.conda_exe), \
             patch.object(app, "conda_pkgs_roots_c_only", return_value=(True, [r"C:\conda\pkgs"])), \
             patch.object(app.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
             patch("builtins.input", return_value="CONDA_INDEX"), \
             patch.object(app.subprocess, "call", return_value=0) as execute:
            result = app.run_conda_clean("index")
        self.assertEqual(result, 0)
        args = execute.call_args.args[0]
        self.assertIn("--index-cache", args)
        self.assertIn("--logfiles", args)
        self.assertNotIn("--packages", args)
        self.assertNotIn("--all", args)
        self.assertNotIn("--force-pkgs-dirs", args)


class LaunchersContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.bat = (cls.root / "internal" / "Bootstrap.cmd").read_text(encoding="utf-8")
        cls.installer = (cls.root / "internal" / "Install_Full_Python_GUI_Optional.cmd").read_text(encoding="utf-8")

    def test_existing_python_discovery_covers_conda_path_py_registry_and_drives(self):
        for token in ('PYTHON_FOR_CLEANUP', 'CONDA_PREFIX', 'where python.exe',
                      'where python3.exe', 'py -3 -I -c', 'HKCU\\Software\\Python',
                      'anaconda*', 'miniconda*', 'miniforge*', 'Programs\\Python'):
            self.assertIn(token, self.bat)
        self.assertIn(r'if exist "%%D:\"', self.bat)
        self.assertIn(r'if not exist "%CURRENT_ROOT%\" exit /b 0', self.bat)
        self.assertNotIn('Join-Path', self.bat)

    def test_bootstrap_gui_only_and_isolated_execution(self):
        self.assertIn('set "CLEAN_MODE=gui"', self.bat)
        self.assertIn('Advanced_Disk_Studio.py', self.bat)
        self.assertIn('"%PYTHON_EXE%" -I "%CLEANER_PY%" %CLEAN_ARGS%', self.bat)
        self.assertNotIn('set "CLEAN_ARGS=--one-click"', self.bat)
        self.assertNotIn('rmdir /s', self.bat.lower())
        self.assertNotIn('del /', self.bat.lower())
        self.assertEqual(app.VERSION, '2.2.0')

    def test_download_uses_pinned_sha256_and_official_python_url(self):
        hashes = (
            '90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159',
            'bbe116bb1248820359cbf25127ac5c7794ea161869d83686cfbc9a45203ff836',
            '11a28e8c00a6d8f56b0a6164d52546133a9ed015a5b33e04536917e4fd6e306c',
        )
        for value in hashes:
            self.assertEqual(len(value), 64)
            self.assertIn(value, self.bat)
        self.assertIn('https://www.python.org/ftp/python/3.14.10/', self.bat)
        self.assertIn('Get-FileHash -LiteralPath $env:C_CLEANER_ZIP_PATH', self.bat)
        self.assertIn('Expand-Archive -LiteralPath $env:C_CLEANER_ZIP_PATH', self.bat)
        self.assertLess(self.bat.index('call :VerifyHash\nif errorlevel 1 (\n  echo [ERROR] Wrong SHA256'),
                        self.bat.index('Expand-Archive -LiteralPath'))

    def test_embedded_python_install_does_not_modify_machine_python(self):
        self.assertIn('set "RUNTIME_ROOT=%TOOL_DIR%_runtime"', self.bat)
        self.assertIn('set "C_CLEANER_BOOTSTRAP_SOURCE=private_new"', self.bat)
        self.assertIn('C_CLEANER_ALLOW_DOWNLOAD', self.bat)
        self.assertIn('Runtime_Offline', self.bat)
        self.assertNotIn('setx ', self.bat.lower())
        self.assertNotIn('InstallAllUsers', self.bat)
        self.assertNotIn('-ExecutionPolicy', self.bat)
        self.assertNotIn('.ps1', '\n'.join(line for line in self.bat.splitlines()
                                          if line.strip() and not line.lower().lstrip().startswith('rem')))

    def test_default_bootstraps_private_python_without_enabling_deletion(self):
        self.assertIn('call :BootstrapPrivatePython', self.bat)
        self.assertIn('set "CLEAN_MODE=gui"', self.bat)
        self.assertNotIn('set "CLEAN_ARGS=--one-click"', self.bat)

    def test_gui_install_requires_opt_in_and_official_signature(self):
        self.assertIn('Type INSTALL to download', self.installer)
        self.assertIn('if not "%ACK%"=="INSTALL"', self.installer)
        self.assertIn('Get-AuthenticodeSignature', self.installer)
        self.assertIn('Python Software Foundation', self.installer)
        self.assertIn('https://www.python.org/ftp/python/3.14.10/', self.installer)
        self.assertNotIn('/quiet', self.installer.lower())

    def test_single_user_facing_launcher_uses_internal_bootstrap(self):
        launchers = list(self.root.glob('*.bat'))
        self.assertEqual(1, len(launchers))
        body = launchers[0].read_text(encoding='ascii')
        self.assertIn('internal\\Bootstrap.cmd', body)
        self.assertNotIn('powershell.exe', body.lower())

    def test_no_python_system_wide_install_is_required(self):
        self.assertIn('private CPython', self.bat)
        self.assertTrue((self.root / 'Runtime_Offline').is_dir())


if __name__ == "__main__":
    unittest.main()
