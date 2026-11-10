#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build and execute a real Windows x64 onedir application, then archive it.

Run on Windows; this script refuses to label Linux output as a Windows EXE.
Only the reviewed source allowlist is staged. Build/output directories must be
outside the checkout. Publication is intentionally left to the repository owner.

Dependency versions were checked against their official PyPI release pages:
https://pypi.org/project/pyinstaller/6.22.3/
https://pypi.org/project/pyinstaller-hooks-contrib/2026.9/
https://pypi.org/project/altgraph/0.17.5/
https://pypi.org/project/packaging/25.0/
https://pypi.org/project/pefile/2023.2.7/
https://pypi.org/project/pywin32-ctypes/0.2.3/
https://pypi.org/project/setuptools/80.9.0/
Layout and executable semantics:
https://pyinstaller.org/en/stable/runtime-information.html
https://pyinstaller.org/en/stable/usage.html
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))
import build_release

VERSION = "3.7.0-beta.1"
APP_NAME = "CScanStudio"
ARCHIVE_PREFIX = f"C_Scan_Studio_v{VERSION}_Windows_x64"
BUILD_DEPENDENCIES = {
    "pyinstaller": "6.22.3",
    "pyinstaller-hooks-contrib": "2026.9",
    "altgraph": "0.17.5",
    "packaging": "25.0",
    # Reviewed fixed Windows PE parser; avoid an unpinned build dependency.
    "pefile": "2023.2.7",
    "pywin32-ctypes": "0.2.3",
    "setuptools": "80.9.0",
}
REQUIRED_RUNTIME_FILES = (
    "CScan_Launcher.py", "Advanced_Disk_Studio.py", "C_Drive_Cleanup.py",
    "Drive_Inspector.py", "Unity_Cache_Manager.py", "Unified_Tools.py",
    "Security_Audit.py", "Share_Offline_Bundle.py", "Everything_Official_Manager.py",
    "ui/dashboard.html", "internal/Install_Full_Python_GUI_Optional.cmd",
    "FILE_INTEGRITY_SHA256.csv", "LICENSE", "README.md",
)
HIDDEN_MODULES = (
    "Advanced_Disk_Studio", "C_Drive_Cleanup", "Drive_Inspector", "Unity_Cache_Manager",
    "Unified_Tools", "Security_Audit", "Share_Offline_Bundle", "Everything_Official_Manager",
)
APP_MANIFEST = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="CScan.Studio" version="3.7.0.1" processorArchitecture="amd64"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>
    <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
  </requestedPrivileges></security></trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application>
    <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
  </application></compatibility>
</assembly>
'''
WINDOWS_README = f'''C-Scan Studio {VERSION} — Windows x64 portable edition

1. Extract the entire ZIP into a writable folder, for example D:\\CScanStudio.
2. Double-click CScanStudio.exe. Keep the _internal folder beside it.
3. A console and your default browser open. Closing the console stops the service.

No Python installation or administrator rights are required for the dashboard.
The one-folder layout avoids repeatedly extracting the runtime to the C: Temp folder.
This is a local browser application. It binds only to 127.0.0.1 and starts without a scan.
Scan and cleanup remain separate explicit user actions; the first page deletes nothing.

Read-only startup test: CScanStudio.exe --self-test
Version: CScanStudio.exe --version
The EXE is an application, not a general Python interpreter.
The legacy -I entry accepts only exact bundled application helper paths.

The reviewed Python source, UI, documentation and licenses are inside _internal.
Optional Everything/ES downloads are still opt-in and verified by their existing manager.
The source-only friend-share action remains a source distribution; it is not an EXE repackager.
To share this portable build, share the original entire Windows ZIP and its SHA-256 file.

This build is not Authenticode-signed. SHA-256 identifies the bytes; it is not an antivirus verdict.
'''


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def output_location(root, output):
    root, output = Path(root).resolve(), Path(output).resolve()
    if root == output or root in output.parents or len(output.parts) < 3:
        raise ValueError("EXE output must be a dedicated directory outside the source checkout.")
    return output


def stage_sources(root, destination):
    files = build_release.eligible(Path(root))
    manifest = build_release.manifest_bytes(files)
    if (Path(root) / "FILE_INTEGRITY_SHA256.csv").read_bytes() != manifest:
        raise RuntimeError("The committed source manifest is stale. Verify it before building an EXE.")
    names = {name for name, _ in files}
    missing = [name for name in REQUIRED_RUNTIME_FILES
               if name != "FILE_INTEGRITY_SHA256.csv" and name not in names]
    if missing:
        raise RuntimeError("Required files are absent from the release allowlist: " + ", ".join(missing))
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in files:
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (destination / "FILE_INTEGRITY_SHA256.csv").write_bytes(manifest)
    return {"file_count": len(files), "manifest_sha256": hashlib.sha256(manifest).hexdigest()}


def require_dependencies(install=False):
    pins = [name + "==" + version for name, version in BUILD_DEPENDENCIES.items()]
    if install:
        subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
                        "--only-binary=:all:", "--no-deps", *pins], check=True)
    actual = {}
    for name, wanted in BUILD_DEPENDENCIES.items():
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeError("Install the pinned build tools with --install-build-deps.") from exc
        if version != wanted:
            raise RuntimeError(f"Build dependency mismatch: {name} expected {wanted}, found {version}.")
        actual[name] = version
    subprocess.run([sys.executable, "-m", "pip", "check"], check=True)
    return actual


def add_runtime_licenses(staged):
    output = Path(staged) / "LICENSES" / "Windows_Runtime"
    output.mkdir(parents=True, exist_ok=True)
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if not python_license.is_file():
        raise RuntimeError("The official CPython LICENSE.txt could not be found in this Windows runtime.")
    shutil.copyfile(python_license, output / "CPython_LICENSE.txt")
    distribution = importlib.metadata.distribution("pyinstaller")
    copied = False
    for relative in distribution.files or ():
        if relative.name.upper() not in ("COPYING.TXT", "COPYING", "LICENSE", "LICENSE.TXT"):
            continue
        path = Path(distribution.locate_file(relative))
        if path.is_file():
            shutil.copyfile(path, output / ("PyInstaller_" + path.name))
            copied = True
    if not copied:
        raise RuntimeError("PyInstaller's redistribution license was not found in its installed distribution.")


def pyinstaller_command(staged, work):
    staged, work = Path(staged), Path(work)
    args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
            "--console", "--noupx", "--name", APP_NAME, "--contents-directory", "_internal",
            "--paths", str(staged), "--distpath", str(work / "dist"),
            "--workpath", str(work / "work"), "--specpath", str(work / "spec"),
            "--manifest", str(work / "cscan.manifest"),
            "--add-data", str(staged) + os.pathsep + "."]
    for name in HIDDEN_MODULES:
        args.extend(("--hidden-import", name))
    args.append(str(staged / "CScan_Launcher.py"))
    return args


def isolated_child_environment():
    environment = dict(os.environ)
    for name in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONEXECUTABLE"):
        environment.pop(name, None)
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    # Prove startup does not use the runner's ambient python.exe from PATH.
    if os.name == "nt":
        system_root = Path(environment.get("SystemRoot", r"C:\Windows"))
        environment["PATH"] = os.pathsep.join((str(system_root / "System32"), str(system_root)))
    return environment


def run_smoke(bundle, working_directory):
    bundle = Path(bundle)
    executable = bundle / (APP_NAME + ".exe")
    if not executable.is_file() or executable.read_bytes()[:2] != b"MZ":
        raise RuntimeError("The Windows executable was not produced.")
    for name in REQUIRED_RUNTIME_FILES:
        if not (bundle / "_internal" / name).is_file():
            raise RuntimeError("Packaged resource missing: " + name)
    working_directory = Path(working_directory)
    working_directory.mkdir(parents=True, exist_ok=False)
    child_env = isolated_child_environment()
    completed = subprocess.run([str(executable), "--self-test"], cwd=working_directory,
                               env=child_env, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=60, check=False)
    try:
        report = json.loads(completed.stdout)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("EXE did not return smoke-test JSON: " + completed.stderr[-1200:]) from exc
    if completed.returncode != 0 or not report.get("ok") or not report.get("frozen") or report.get("version") != VERSION:
        raise RuntimeError("Packaged EXE smoke failed: " + json.dumps(report, ensure_ascii=True)[:1500])

    # Exercise the formerly dangerous sys.executable -I helper path in the real
    # frozen executable. This checks source/data path alignment and dispatch.
    helper = bundle / "_internal" / "Security_Audit.py"
    checked = subprocess.run([str(executable), "-I", str(helper), "--json"],
                             cwd=working_directory, env=child_env, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=60, check=False)
    try:
        integrity = json.loads(checked.stdout)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Packaged helper did not return JSON: " + checked.stderr[-1200:]) from exc
    if checked.returncode != 0 or integrity.get("status") != "matched":
        raise RuntimeError("Packaged source integrity/helper dispatch failed: " +
                           json.dumps(integrity, ensure_ascii=True)[:1500])
    helper_results = {}
    # Check each auxiliary entry point using its own real, non-mutating mode.
    # C_Drive_Cleanup exposes cli(), while the other two expose main().
    for name, arguments, marker in (
            ("C_Drive_Cleanup.py", ["--help"], "--scan"),
            ("Everything_Official_Manager.py", ["status"], "C-Scan verified Everything manager")):
        command = [str(executable), "-I", str(bundle / "_internal" / name), *arguments]
        probe = subprocess.run(command, cwd=working_directory, env=child_env, capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=30, check=False)
        if probe.returncode != 0 or marker not in probe.stdout:
            raise RuntimeError("Packaged helper entry failed: " + name + " " + probe.stderr[-600:])
        helper_results[name] = "passed (read-only help/status)"
    # Source archives deliberately exclude the separately downloaded vendor
    # ZIPs. Sharing must refuse that incomplete input without creating a ZIP.
    share_probe = subprocess.run([str(executable), "-I", str(bundle / "_internal" / "Share_Offline_Bundle.py")],
                                 cwd=working_directory, env=child_env, capture_output=True,
                                 text=True, encoding="utf-8", errors="replace", timeout=60, check=False)
    if share_probe.returncode != 3 or "Share preparation refused" not in share_probe.stdout:
        raise RuntimeError("Packaged share helper did not refuse missing vendor inputs as expected.")
    helper_results["Share_Offline_Bundle.py"] = "refused missing optional vendor ZIPs (no archive created)"
    rejected = subprocess.run([str(executable), "-c", "raise SystemExit(91)"],
                              cwd=working_directory, env=child_env, capture_output=True,
                              timeout=30, check=False)
    if rejected.returncode != 2:
        raise RuntimeError("The frozen application accepted an unsupported interpreter command.")
    report["bundled_source_integrity"] = {"status": integrity["status"], "checked": integrity["checked"]}
    report["legacy_bundled_helper_dispatch"] = "passed"
    report["auxiliary_entry_points"] = helper_results
    report["arbitrary_interpreter_command"] = "rejected"
    report["ambient_python_on_path"] = False
    return report


def write_zip(bundle, archive):
    bundle, archive = Path(bundle), Path(archive)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=7) as container:
        for path in sorted(bundle.rglob("*")):
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise RuntimeError("A linked file appeared in the Windows distribution.")
            if path.is_file():
                container.write(path, ARCHIVE_PREFIX + "/" + path.relative_to(bundle).as_posix())
    with zipfile.ZipFile(archive) as container:
        bad = container.testzip()
        if bad:
            raise RuntimeError("Portable ZIP CRC verification failed: " + bad)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=SCRIPT_ROOT.parent)
    parser.add_argument("--outdir", type=Path, default=SCRIPT_ROOT.parent.parent / "windows-exe-output")
    parser.add_argument("--install-build-deps", action="store_true",
                        help="Install the exact build-only PyPI versions into the selected build Python.")
    args = parser.parse_args(argv)
    if sys.platform != "win32" or struct.calcsize("P") != 8 or platform.machine().lower() not in ("amd64", "x86_64"):
        raise SystemExit("A Windows x64 runner is required. No executable was built or relabeled.")
    output = output_location(args.root, args.outdir)
    if build_release.VERSION != VERSION:
        raise SystemExit("Source and Windows package versions do not match.")
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (ARCHIVE_PREFIX + ".zip")
    if archive.exists():
        raise SystemExit("A Windows ZIP already exists; choose a fresh output directory.")
    dependencies = require_dependencies(args.install_build_deps)
    with tempfile.TemporaryDirectory(prefix="cscan-build-", dir=output) as temporary:
        work = Path(temporary)
        staged = work / "source"
        source = stage_sources(args.root, staged)
        add_runtime_licenses(staged)
        (work / "cscan.manifest").write_text(APP_MANIFEST, encoding="utf-8")
        (work / "spec").mkdir()
        subprocess.run(pyinstaller_command(staged, work), cwd=work, check=True)
        bundle = work / "dist" / APP_NAME
        smoke = run_smoke(bundle, work / "smoke cwd Chinese_中文")
        (bundle / "START_HERE.txt").write_text(WINDOWS_README, encoding="utf-8")
        (bundle / "LICENSE").write_bytes((staged / "LICENSE").read_bytes())
        build_info = {"product": "C-Scan Studio", "version": VERSION, "format": "PyInstaller onedir",
                      "os": "Windows", "architecture": "x64", "python": platform.python_version(),
                      "dependencies": dependencies, "source": source,
                      "commit": os.environ.get("GITHUB_SHA", "local-uncommitted-or-unknown"),
                      "workflow_run": os.environ.get("GITHUB_RUN_ID", "local"),
                      "executable_sha256": sha256(bundle / (APP_NAME + ".exe")),
                      "authenticode_signed": False,
                      "physical_disk_cleanup_tested": False, "smoke_test": smoke}
        (bundle / "BUILD_INFO.json").write_text(json.dumps(build_info, ensure_ascii=False, indent=2), encoding="utf-8")
        write_zip(bundle, archive)
    checksum = sha256(archive)
    archive.with_name(archive.name + ".sha256.txt").write_text(checksum + "  " + archive.name + "\n", encoding="ascii")
    (output / "windows-exe-smoke.json").write_text(json.dumps(smoke, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "windows-exe-build-info.json").write_text(json.dumps(build_info, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "archive": str(archive), "sha256": checksum,
                      "version": VERSION, "smoke": "passed", "published_release": False}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
