"""Behavioral checks for portable startup, resource paths and bounded dispatch."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import CScan_Launcher as launcher
import build_windows_exe as packaging


class LauncherBehaviorTests(unittest.TestCase):
    def test_version_command_does_not_launch_app(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = launcher.main(["--version"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stream.getvalue())["version"], "3.7.0-beta.1")

    def test_arbitrary_interpreter_and_script_arguments_are_rejected(self):
        for args in (["-c", "raise SystemExit(91)"], ["-m", "http.server"],
                     ["random.py"], ["--self-test", "--delete"], ["-I"]):
            with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(launcher.main(args), 2)

    def test_same_filename_outside_bundle_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Security_Audit.py").write_text("raise RuntimeError('must not run')")
            with self.assertRaises(ValueError):
                launcher._legacy_target(root / "Security_Audit.py", ROOT)

    def test_path_traversal_cannot_select_an_external_script(self):
        with self.assertRaises((ValueError, FileNotFoundError)):
            launcher._legacy_target(ROOT / ".." / "Security_Audit.py", ROOT)

    def test_exact_bundled_helper_is_dispatched_without_eval(self):
        fake = mock.Mock()
        fake.main.return_value = 7
        with mock.patch.object(launcher.importlib, "import_module", return_value=fake) as imported:
            self.assertEqual(launcher._run_legacy([str(ROOT / "Security_Audit.py"), "--json"]), 7)
        imported.assert_called_once_with("Security_Audit")
        fake.main.assert_called_once_with(["--json"])

    def test_real_auxiliary_entry_points_support_read_only_commands(self):
        for name, arguments, marker in (
                ("C_Drive_Cleanup.py", ["--help"], "--scan"),
                ("Security_Audit.py", ["--help"], "--json"),
                ("Everything_Official_Manager.py", ["status"], "C-Scan verified Everything manager")):
            with self.subTest(helper=name):
                completed = subprocess.run([sys.executable, "-B", str(ROOT / "CScan_Launcher.py"),
                                            "-I", str(ROOT / name), *arguments],
                                           cwd=ROOT.parent, capture_output=True, text=True,
                                           encoding="utf-8", timeout=20, check=False)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn(marker, completed.stdout)

    def test_isolated_source_cleaner_imports_its_bundled_unity_module(self):
        with tempfile.TemporaryDirectory(prefix="cscan unrelated source cwd ") as temporary:
            # An unrelated cwd must not supply the cleaner's Unity dependency.
            (Path(temporary) / "Unity_Cache_Manager.py").write_text(
                "raise RuntimeError('cwd dependency must not run')\n", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(ROOT / "C_Drive_Cleanup.py"), "--help"],
                cwd=temporary, capture_output=True, text=True, encoding="utf-8",
                timeout=20, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("--scan", completed.stdout)

    def test_source_cleaner_help_handles_legacy_pipe_encoding_and_stringio(self):
        import C_Drive_Cleanup as engine
        raw_output = io.BytesIO()
        with io.TextIOWrapper(raw_output, encoding="cp1252", errors="strict") as output:
            with mock.patch.object(engine.sys, "stdout", output), \
                    mock.patch.object(engine.sys, "stderr", io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    engine.cli(["--help"])
            output.flush()
            decoded = raw_output.getvalue().decode("utf-8")
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("Windows C 盘缓存清理", decoded)
        self.assertIn("--scan", decoded)

        output = io.StringIO()
        with mock.patch.object(engine.sys, "stdout", output), \
                mock.patch.object(engine.sys, "stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as stopped:
                engine.cli(["--help"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("Windows C 盘缓存清理", output.getvalue())

    def test_share_helper_uses_its_real_entry_and_refuses_missing_inputs(self):
        import Share_Offline_Bundle as share
        with tempfile.TemporaryDirectory() as temporary:
            # Invoke the real preparation function on a deliberately incomplete
            # fixture; absence of its manifest must fail before any write.
            function = share.prepare_share
            with mock.patch.object(share, "prepare_share", side_effect=lambda: function(Path(temporary))):
                with contextlib.redirect_stdout(io.StringIO()) as stream:
                    self.assertEqual(launcher._run_legacy([str(ROOT / "Share_Offline_Bundle.py")]), 3)
            self.assertIn("Share preparation refused", stream.getvalue())
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_legacy_gui_entry_calls_its_real_main_without_starting_a_scan(self):
        import Advanced_Disk_Studio as studio
        import types
        # Run the real GUI entry point, keeping its environment check compatible
        # with Linux tests and replacing only browser/server lifetime effects.
        server = mock.Mock()
        server.server_port = 12345
        server.serve_forever.side_effect = KeyboardInterrupt
        with mock.patch.object(studio, "os", types.SimpleNamespace(name="nt")), \
                mock.patch.object(studio, "ThreadingHTTPServer", return_value=server), \
                mock.patch.object(studio.webbrowser, "open", return_value=True), \
                mock.patch.object(studio.Analyzer, "start_scan", side_effect=AssertionError("scan attempted")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(launcher._run_legacy([str(ROOT / "Advanced_Disk_Studio.py")]), 0)
        server.serve_forever.assert_called_once()
        server.server_close.assert_called_once()

    def test_elevation_preserves_source_and_adds_frozen_helper_dispatch(self):
        import C_Drive_Cleanup as engine
        import types
        shell_execute = mock.Mock(return_value=42)
        fake_api = types.SimpleNamespace(shell32=types.SimpleNamespace(ShellExecuteW=shell_execute))
        with mock.patch.object(engine.ctypes, "windll", fake_api, create=True), \
                contextlib.redirect_stdout(io.StringIO()):
            with mock.patch.object(engine.sys, "frozen", False, create=True):
                self.assertTrue(engine.elevate(["--dism"]))
            source_call = shell_execute.call_args.args
            with mock.patch.object(engine.sys, "frozen", True, create=True):
                self.assertTrue(engine.elevate(["--dism"]))
            frozen_call = shell_execute.call_args.args
        self.assertEqual(shell_execute.call_count, 2)
        self.assertEqual(source_call[:3], (None, "runas", sys.executable))
        self.assertEqual(frozen_call[:3], source_call[:3])
        self.assertFalse(source_call[3].startswith("-I "))
        self.assertIn("C_Drive_Cleanup.py", source_call[3])
        self.assertTrue(source_call[3].endswith("--dism --hold"))
        self.assertEqual(frozen_call[3], "-I " + source_call[3])

    def test_symlinked_helper_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "payload.py"
            original.write_text("pass")
            linked = root / "Security_Audit.py"
            try:
                linked.symlink_to(original)
            except OSError:
                self.skipTest("This Windows account cannot create symlinks.")
            with self.assertRaises(ValueError):
                launcher._legacy_target(linked, root)

    def test_source_smoke_uses_real_http_from_a_different_working_directory(self):
        with tempfile.TemporaryDirectory(prefix="cscan launcher cwd ") as temporary:
            completed = subprocess.run([sys.executable, "-B", str(ROOT / "CScan_Launcher.py"), "--self-test"],
                                       cwd=temporary, capture_output=True, text=True,
                                       encoding="utf-8", timeout=25, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        data = json.loads(completed.stdout)
        self.assertTrue(data["ok"])
        self.assertFalse(data["frozen"])
        self.assertFalse(data["physical_disk_scan_performed"])
        self.assertFalse(data["deletion_performed"])
        self.assertEqual(data["forbidden_attempts"], [])
        expected = {"dashboard", "state_version", "unity_idle_data", "session_token_required"}
        if os.name == "nt":
            expected.add("windows_process_guard")
            process_probe = next(item for item in data["probes"] if item["name"] == "windows_process_guard")
            self.assertTrue(process_probe["passed"])
            self.assertGreater(process_probe["process_count"], 0)
            self.assertEqual(set(process_probe), {"name", "passed", "process_count"})
        self.assertEqual({item["name"] for item in data["probes"]}, expected)


class PackageBoundaryTests(unittest.TestCase):
    def test_build_output_inside_source_is_rejected(self):
        with self.assertRaises(ValueError):
            packaging.output_location(ROOT, ROOT / "dist")
        with self.assertRaises(ValueError):
            packaging.output_location(ROOT, ROOT)

    def test_non_windows_build_is_explicitly_rejected(self):
        with mock.patch.object(packaging.sys, "platform", "linux"):
            with self.assertRaisesRegex(SystemExit, "Windows x64 runner"):
                packaging.main([])

    def test_stage_requires_current_manifest_before_copying(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            (root / "FILE_INTEGRITY_SHA256.csv").write_bytes(b"stale")
            files = [("CScan_Launcher.py", b"pass\n")]
            with mock.patch.object(packaging.build_release, "eligible", return_value=files):
                with self.assertRaisesRegex(RuntimeError, "manifest is stale"):
                    packaging.stage_sources(root, Path(temporary) / "stage")
            self.assertFalse((Path(temporary) / "stage").exists())

    def test_stage_retains_exact_reviewed_sources_and_no_unlisted_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            files = [(name, (name + "\n").encode("utf-8"))
                     for name in packaging.REQUIRED_RUNTIME_FILES if name != "FILE_INTEGRITY_SHA256.csv"]
            manifest = packaging.build_release.manifest_bytes(files)
            (root / "FILE_INTEGRITY_SHA256.csv").write_bytes(manifest)
            (root / "private.env").write_text("not distributed")
            destination = Path(temporary) / "stage"
            with mock.patch.object(packaging.build_release, "eligible", return_value=files):
                result = packaging.stage_sources(root, destination)
            self.assertEqual(result["file_count"], len(files))
            self.assertEqual((destination / "FILE_INTEGRITY_SHA256.csv").read_bytes(), manifest)
            self.assertFalse((destination / "private.env").exists())
            for name, data in files:
                self.assertEqual((destination / name).read_bytes(), data)

    def test_missing_unity_module_cannot_produce_a_partial_portable_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = [("CScan_Launcher.py", b"pass\n")]
            (root / "FILE_INTEGRITY_SHA256.csv").write_bytes(packaging.build_release.manifest_bytes(files))
            with mock.patch.object(packaging.build_release, "eligible", return_value=files):
                with self.assertRaisesRegex(RuntimeError, "Unity_Cache_Manager.py"):
                    packaging.stage_sources(root, root / "stage")

    def test_onedir_command_has_no_elevation_and_uses_staged_sources(self):
        command = packaging.pyinstaller_command(Path("stage with spaces"), Path("outside build"))
        self.assertIn("--onedir", command)
        self.assertNotIn("--onefile", command)
        self.assertNotIn("--uac-admin", command)
        self.assertEqual(command[-1], str(Path("stage with spaces") / "CScan_Launcher.py"))
        self.assertIn('level="asInvoker"', packaging.APP_MANIFEST)

    def test_portable_archive_has_one_root_and_keeps_internal_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            (bundle / "_internal" / "ui").mkdir(parents=True)
            (bundle / "CScanStudio.exe").write_bytes(b"MZ-test-fixture-not-executable")
            (bundle / "_internal" / "ui" / "dashboard.html").write_text("Unity test")
            archive = Path(temporary) / "portable.zip"
            packaging.write_zip(bundle, archive)
            with zipfile.ZipFile(archive) as opened:
                self.assertEqual(set(opened.namelist()), {
                    packaging.ARCHIVE_PREFIX + "/CScanStudio.exe",
                    packaging.ARCHIVE_PREFIX + "/_internal/ui/dashboard.html"})
                self.assertIsNone(opened.testzip())

    def test_a_non_executable_or_missing_resources_fails_before_smoke(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "CScanStudio.exe").write_bytes(b"not an exe")
            with mock.patch.object(packaging.subprocess, "run") as runner:
                with self.assertRaisesRegex(RuntimeError, "not produced"):
                    packaging.run_smoke(root, root / "cwd")
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
