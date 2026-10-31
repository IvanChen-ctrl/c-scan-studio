#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C: drive cache/temporary-file cleaner for Windows 10/11 (Python 3.8+).

NO third-party libraries. Read-only scan by default. One-click mode only uses
an explicitly limited safe preset; advanced cleanup requires confirmation.
This is NOT a general-purpose directory deleter: targets are hard-coded,
path boundaries are validated, and symlinks/junctions/reparse points are skipped.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import datetime as dt
import json
import heapq
import ntpath
import os
from pathlib import Path, PureWindowsPath
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

VERSION = "2.2.0"
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
TOOLKIT_DIR = Path(__file__).resolve().parent
GROUPS = {
    "user-temp": ("用户临时文件", 14),
    "wer": ("已归档 Windows 错误报告", 14),
    "gpu": ("DirectX / NVIDIA 可再生图形缓存", 0),
    "browser": ("浏览器磁盘缓存（不含登录、书签）", 0),
    "pip": ("Python pip 下载/构建缓存", 0),
    "npm": ("Node.js npm 下载缓存", 0),
    "uv": ("uv Python 包缓存", 0),
    "poetry": ("Poetry Python 包下载缓存", 0),
    "yarn": ("Yarn Classic 下载缓存", 0),
    "nuget": ("NuGet HTTP 下载缓存（不含全局已安装包）", 0),
    "ide": ("VS Code / Cursor / JetBrains / Visual Studio 可再生缓存", 7),
    "crash": ("旧的应用/系统崩溃转储（用于排障，慎选）", 30),
    "system-temp": ("Windows 系统临时文件", 7),
    "system-wer": ("已归档系统错误报告", 7),
}
DEFAULT_GROUPS = ("user-temp", "wer")
# Never add system-temp, crash or conda package archives to this preset.
# One-click is destructive and therefore limited to discardable cache targets.
ONE_CLICK_GROUPS = (
    "user-temp", "wer", "gpu", "browser", "pip", "npm", "uv",
    "poetry", "yarn", "nuget", "ide",
)
SYSTEM_GROUPS = frozenset(("system-temp", "system-wer"))
# This is strictly a path-component guard for accidental project placement
# inside a temporary folder. Model environments are not registered as targets.
PRESERVE_TEMP_DIR_NAMES = frozenset(
    (".venv", "venv", "env", "models", "model", "checkpoints", "huggingface",
     "fingpt", "datasets", "dataset", "projects", "project", "workspace",
     "backup", "backups", "source", "sources", "src", "site-packages", "conda",
     "anaconda", "anaconda3", "miniconda", "miniconda3", "miniforge", "miniforge3",
     "mambaforge", "pytorch", "torch", "transformers", "stable-diffusion", "comfyui",
     "output", "outputs", ".git", ".svn")
)
PROJECT_MARKERS = frozenset((
    ".git", "pyproject.toml", "setup.py", "environment.yml", "environment.yaml",
    "requirements.txt", "conda-meta", "package.json", "CMakeLists.txt",
))
# A user's meaningful project/model files might be sitting in Temp.  Never
# silently delete them even when their containing temp directory is old.
PRESERVE_TEMP_SUFFIXES = frozenset((
    ".safetensors", ".ckpt", ".pt", ".pth", ".gguf", ".onnx",
    ".pkl", ".joblib", ".h5", ".hdf5", ".iso", ".vhd", ".vhdx",
    ".zip", ".7z", ".rar", ".tar", ".gz", ".py", ".ipynb",
    ".psd", ".blend", ".unity", ".unitypackage", ".mp4", ".mov",
    ".bat", ".cmd", ".ps1", ".db", ".sqlite", ".sqlite3",
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tiff",
    ".svg", ".exr", ".mp3", ".wav", ".flac", ".ogg", ".aac", ".m4a",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".csv", ".json", ".txt", ".md", ".xml", ".lrc", ".srt",
    ".ass", ".cpp", ".cs", ".h", ".js", ".ts", ".fbx", ".obj",
    ".glb", ".gltf", ".html", ".htm",
))
BROWSER_PROCESSES = {
    "chrome": "chrome.exe",
    "edge": "msedge.exe",
    "brave": "brave.exe",
    "chromium": "chrome.exe",
    "firefox": "firefox.exe",
    "opera": "opera.exe",
    "vivaldi": "vivaldi.exe",
}


def is_c_drive(path: Union[Path, str]) -> bool:
    value = ntpath.normpath(str(path))
    drive, rest = ntpath.splitdrive(value)
    return drive.casefold() == "c:" and rest.startswith("\\")


def same_path(a: Union[Path, str], b: Union[Path, str]) -> bool:
    return ntpath.normcase(ntpath.normpath(str(a))) == ntpath.normcase(ntpath.normpath(str(b)))


def strictly_within(child: Union[Path, str], parent: Union[Path, str]) -> bool:
    """Compare lexically, without resolving links (links are separately rejected)."""
    c = ntpath.normcase(ntpath.normpath(str(child)))
    p = ntpath.normcase(ntpath.normpath(str(parent)))
    try:
        return ntpath.commonpath((c, p)) == p and c != p
    except ValueError:
        return False


def is_reparse_or_link(path: Union[Path, str]) -> bool:
    """Windows junctions/mount points/symlinks must never be traversed."""
    try:
        info = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True  # Fail closed on inaccessible metadata
    return bool(stat.S_ISLNK(info.st_mode) or
                (getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT))


def ancestors_clear(path: Union[Path, str]) -> bool:
    """Reject a target reachable through any junction or symlink ancestor."""
    cursor = Path(path)
    while True:
        if is_reparse_or_link(cursor):
            return False
        if cursor.parent == cursor:
            return True
        cursor = cursor.parent


def format_bytes(num: int) -> str:
    num = max(0, int(num))
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    value = float(num)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{num} B"
        value /= 1024
    return str(num)


def safe_user_roots(env: Dict[str, str]) -> Tuple[Optional[Path], Optional[Path], Optional[Path]]:
    """Never trust arbitrary LOCALAPPDATA: insist on the canonical profile layout."""
    profile = Path(env.get("USERPROFILE", ""))
    if not is_c_drive(profile) or len(profile.parts) < 3:
        return None, None, None
    if same_path(profile, Path("C:\\")) or not ancestors_clear(profile):
        return None, None, None
    forbidden_roots = {"windows", "winnt", "programdata", "program files", "program files (x86)",
                       "recovery", "boot", "perflogs", "$recycle.bin"}
    if len(profile.parts) > 1 and profile.parts[1].casefold() in forbidden_roots:
        return None, None, None
    local = profile / "AppData" / "Local"
    roaming = profile / "AppData" / "Roaming"
    # If Windows redirects an AppData directory, don't follow the redirection.
    if not ancestors_clear(local):
        local = None
    if not ancestors_clear(roaming):
        roaming = None
    return profile, local, roaming


@dataclass(frozen=True)
class Target:
    group: str
    name: str
    path: Path
    boundary: Path
    process_name: str = ""

    def valid(self) -> bool:
        if not (is_c_drive(self.path) and is_c_drive(self.boundary)):
            return False
        if not strictly_within(self.path, self.boundary):
            return False
        if not ancestors_clear(self.path):
            return False
        return True


@dataclass
class Counters:
    candidates: int = 0
    bytes: int = 0
    skipped_recent: int = 0
    skipped_special: int = 0
    errors: int = 0
    deleted_files: int = 0
    deleted_bytes: int = 0
    deleted_folders: int = 0
    error_examples: List[str] = field(default_factory=list)

    def add_error(self, msg: str):
        self.errors += 1
        if len(self.error_examples) < 12:
            self.error_examples.append(msg[:360])


@dataclass
class Result:
    target: str
    group: str
    path: str
    age_days: int
    status: str
    metrics: Counters = field(default_factory=Counters)

    def as_dict(self) -> Dict:
        return {
            "target": self.target,
            "group": self.group,
            "path": self.path,
            "age_days": self.age_days,
            "status": self.status,
            "metrics": asdict(self.metrics),
        }


def add_unique(out: Dict[str, Target], group: str, name: str, path: Path,
               boundary: Path, process_name: str = "") -> None:
    candidate = Target(group, name, path, boundary, process_name)
    if not candidate.valid():
        return
    out.setdefault(ntpath.normcase(ntpath.normpath(str(path))), candidate)


def make_targets(env: Optional[Dict[str, str]] = None) -> List[Target]:
    env = dict(os.environ if env is None else env)
    out: Dict[str, Target] = {}
    profile, local, roaming = safe_user_roots(env)
    if profile and local:
        add_unique(out, "user-temp", "用户 Temp", local / "Temp", local)
        # Respect user-configured TEMP only when it stays inside their profile.
        custom_temp = env.get("TEMP", "")
        if custom_temp:
            ctemp = Path(custom_temp)
            if ctemp.name.casefold() in ("temp", "tmp") and strictly_within(ctemp, profile):
                add_unique(out, "user-temp", "自定义 TEMP", ctemp, profile)
        user_wer = local / "Microsoft" / "Windows" / "WER"
        add_unique(out, "wer", "用户已归档错误报告", user_wer / "ReportArchive", local)
        add_unique(out, "gpu", "Windows D3DShader 缓存", local / "D3DSCache", local)
        add_unique(out, "gpu", "NVIDIA DXCache", local / "NVIDIA" / "DXCache", local)
        add_unique(out, "gpu", "NVIDIA GLCache", local / "NVIDIA" / "GLCache", local)
        add_unique(out, "gpu", "NVIDIA NV_Cache", local / "NVIDIA Corporation" / "NV_Cache", local)
        add_unique(out, "pip", "pip 缓存", local / "pip" / "Cache", local)
        add_unique(out, "npm", "npm 缓存", local / "npm-cache", local, "node.exe")
        add_unique(out, "uv", "uv 缓存", local / "uv" / "cache", local, "uv.exe")
        add_unique(out, "poetry", "Poetry 缓存", local / "pypoetry" / "Cache", local)
        add_unique(out, "yarn", "Yarn Classic 缓存", local / "Yarn" / "Cache", local, "node.exe")
        add_unique(out, "nuget", "NuGet HTTP v3 缓存", local / "NuGet" / "v3-cache", local, "dotnet.exe")
        add_unique(out, "nuget", "NuGet 旧 HTTP 缓存", local / "NuGet" / "Cache", local, "dotnet.exe")
        add_unique(out, "crash", "应用 CrashDumps", local / "CrashDumps", local)

        for app_name, rel, process in (
                ("VS Code", "Code", "Code.exe"),
                ("VS Code Insiders", "Code - Insiders", "Code - Insiders.exe"),
                ("Cursor", "Cursor", "Cursor.exe")):
            base = local / rel
            # Never delete the entire IDE user-data directory or extensions.
            for cache in ("Cache", "CachedData", "Code Cache", "GPUCache", "DawnCache"):
                add_unique(out, "ide", f"{app_name} {cache}", base / cache,
                           local, process.lower())

        jetbrains = local / "JetBrains"
        if jetbrains.is_dir() and ancestors_clear(jetbrains):
            try:
                with os.scandir(jetbrains) as entries:
                    for entry in entries:
                        if not entry.is_dir(follow_symlinks=False) or is_reparse_or_link(entry.path):
                            continue
                        name = entry.name.casefold()
                        if not (name.startswith("pycharm") or name.startswith("intellijidea") or
                                name.startswith("webstorm")):
                            continue
                        proc = "pycharm64.exe" if name.startswith("pycharm") else (
                            "idea64.exe" if name.startswith("intellijidea") else "webstorm64.exe")
                        add_unique(out, "ide", f"JetBrains {entry.name} index cache",
                                   Path(entry.path) / "caches", local, proc)
            except OSError:
                pass

        vs = local / "Microsoft" / "VisualStudio"
        if vs.is_dir() and ancestors_clear(vs):
            try:
                with os.scandir(vs) as entries:
                    for entry in entries:
                        if entry.is_dir(follow_symlinks=False) and not is_reparse_or_link(entry.path):
                            add_unique(out, "ide", f"Visual Studio {entry.name} ComponentModelCache",
                                       Path(entry.path) / "ComponentModelCache", local, "devenv.exe")
            except OSError:
                pass

        chromium_roots = (
            ("Chrome", local / "Google" / "Chrome" / "User Data", "chrome"),
            ("Edge", local / "Microsoft" / "Edge" / "User Data", "edge"),
            ("Brave", local / "BraveSoftware" / "Brave-Browser" / "User Data", "brave"),
            ("Chromium", local / "Chromium" / "User Data", "chromium"),
            ("Vivaldi", local / "Vivaldi" / "User Data", "vivaldi"),
        )
        for product, base, browser_id in chromium_roots:
            if not base.is_dir() or not ancestors_clear(base):
                continue
            proc = BROWSER_PROCESSES[browser_id]
            # Shader cache at the user-data root. Never delete user-data root.
            for root_cache in ("ShaderCache", "GrShaderCache"):
                add_unique(out, "browser", f"{product} {root_cache}", base / root_cache, local, proc)
            try:
                with os.scandir(base) as entries:
                    profiles = [Path(x.path) for x in entries if x.is_dir(follow_symlinks=False)
                                and not is_reparse_or_link(x.path) and
                                (x.name == "Default" or x.name.startswith("Profile ")
                                 or x.name == "Guest Profile")]
            except OSError:
                profiles = []
            for folder in sorted(profiles):
                for sub in ("Cache", "Network/Cache", "Code Cache", "GPUCache", "DawnCache"):
                    add_unique(out, "browser", f"{product} {folder.name} {sub}",
                               folder.joinpath(*sub.split("/")), local, proc)

        fx_root = local / "Mozilla" / "Firefox" / "Profiles"
        if fx_root.is_dir() and ancestors_clear(fx_root):
            try:
                with os.scandir(fx_root) as entries:
                    for entry in entries:
                        if entry.is_dir(follow_symlinks=False) and not is_reparse_or_link(entry.path):
                            add_unique(out, "browser", f"Firefox {entry.name} cache2",
                                       Path(entry.path) / "cache2", local, "firefox.exe")
            except OSError:
                pass

        for product, base in (("Opera", local / "Opera Software"),):
            if base.is_dir() and ancestors_clear(base):
                for variant in ("Opera Stable", "Opera GX Stable"):
                    browser_dir = base / variant
                    for sub in ("Cache", "Code Cache", "GPUCache", "Network/Cache"):
                        add_unique(out, "browser", f"{product} {variant} {sub}",
                                   browser_dir.joinpath(*sub.split("/")), local, "opera.exe")

    if profile and roaming:
        for app_name, rel, process in (
                ("VS Code", "Code", "code.exe"),
                ("VS Code Insiders", "Code - Insiders", "code - insiders.exe"),
                ("Cursor", "Cursor", "cursor.exe")):
            base = roaming / rel
            for cache in ("Cache", "CachedData", "Code Cache", "GPUCache", "DawnCache"):
                add_unique(out, "ide", f"{app_name} {cache} (Roaming)",
                           base / cache, roaming, process)
        # A cache under the profile is eligible only when it is exactly the
        # documented per-user cache folder, never the whole ~/.cache tree.
        add_unique(out, "pip", "pip 缓存（用户配置目录）", profile / ".cache" / "pip", profile)
        add_unique(out, "poetry", "Poetry 缓存（用户配置目录）",
                   profile / ".cache" / "pypoetry", profile)
        # Some Opera editions place cache under Roaming.
        for variant in ("Opera Stable", "Opera GX Stable"):
            root = roaming / "Opera Software" / variant
            for sub in ("Cache", "Code Cache", "GPUCache", "Network/Cache"):
                add_unique(out, "browser", f"Opera {variant} {sub}",
                           root.joinpath(*sub.split("/")), roaming, "opera.exe")

    # Only Windows' own temp / error-report archives; never SoftwareDistribution,
    # WinSxS, installer cache, WindowsApps, driver store, or other OS directories.
    system_root = Path(env.get("SystemRoot", env.get("WINDIR", "C:\\Windows")))
    if is_c_drive(system_root) and system_root.name.casefold() in ("windows", "winnt"):
        add_unique(out, "system-temp", "Windows Temp", system_root / "Temp", system_root)
        add_unique(out, "crash", "旧 Windows Minidump", system_root / "Minidump", system_root)

    progdata = Path(env.get("PROGRAMDATA", "C:\\ProgramData"))
    if is_c_drive(progdata) and same_path(progdata, "C:\\ProgramData"):
        add_unique(out, "system-wer", "系统已归档错误报告",
                   progdata / "Microsoft" / "Windows" / "WER" / "ReportArchive", progdata)
    return list(out.values())


def active_processes() -> Optional[set[str]]:
    """Return None if process enumeration cannot be trusted (fail closed)."""
    try:
        proc = subprocess.run(["tasklist.exe", "/FO", "CSV", "/NH"],
                              capture_output=True, timeout=12, check=False)
        if proc.returncode != 0:
            return None
        # tasklist uses the local OEM code page; the process names are ASCII.
        text = proc.stdout.decode("mbcs" if os.name == "nt" else "utf-8", errors="replace")
        found = set()
        for line in csv.reader(text.splitlines()):
            if line:
                name = line[0].strip().lower()
                if name.endswith(".exe"):
                    found.add(name)
        return found
    except (OSError, subprocess.TimeoutExpired):
        return None


def is_preserved_temp_subtree(target: Target, folder_name: str) -> bool:
    return target.group in ("user-temp", "system-temp") and folder_name.casefold() in PRESERVE_TEMP_DIR_NAMES


def toolkit_contains_or_is_inside(path: Path) -> bool:
    """Refuse to clean the tool itself if extracted somewhere inside Temp."""
    current = TOOLKIT_DIR
    return same_path(path, current) or strictly_within(path, current)


def is_project_directory(path: Path) -> bool:
    """Project/conda environment marker check for user/system Temp subtrees."""
    try:
        return any((path / marker).exists() or (path / marker).is_symlink()
                   for marker in PROJECT_MARKERS)
    except OSError:
        return True  # fail closed


def protected_temp_file(target: Target, path: Path) -> bool:
    return (target.group in ("user-temp", "system-temp") and
            path.suffix.casefold() in PRESERVE_TEMP_SUFFIXES)


def iter_eligible_files(target: Target, cutoff: float, metrics: Counters,
                        rows: Optional[csv.writer] = None) -> Iterator[Tuple[Path, os.stat_result]]:
    """Iterative walk; never follow links/junctions and never leave a pinned target."""
    if not target.valid() or not target.path.is_dir():
        return
    dirs = [target.path]
    while dirs:
        folder = dirs.pop()
        if not strictly_within(folder, target.boundary) or not ancestors_clear(folder):
            metrics.skipped_special += 1
            continue
        if target.group in ("user-temp", "system-temp") and (
                toolkit_contains_or_is_inside(folder) or is_project_directory(folder)):
            metrics.skipped_special += 1
            continue
        try:
            with os.scandir(folder) as scanned:
                for entry in scanned:
                    path = Path(entry.path)
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if (stat.S_ISLNK(info.st_mode) or
                                getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT):
                            metrics.skipped_special += 1
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            if (is_preserved_temp_subtree(target, entry.name) or
                                    (target.group in ("user-temp", "system-temp") and
                                     (toolkit_contains_or_is_inside(path) or
                                      is_project_directory(path)))):
                                metrics.skipped_special += 1
                            else:
                                dirs.append(path)
                        elif stat.S_ISREG(info.st_mode):
                            if protected_temp_file(target, path):
                                metrics.skipped_special += 1
                                continue
                            if info.st_mtime > cutoff:
                                metrics.skipped_recent += 1
                                continue
                            metrics.candidates += 1
                            metrics.bytes += max(info.st_size, 0)
                            if rows is not None:
                                try:
                                    rows.writerow((target.group, target.name, str(path),
                                                  info.st_size, dt.datetime.fromtimestamp(info.st_mtime).isoformat()))
                                except (OSError, ValueError, UnicodeError):
                                    metrics.add_error("无法写入 CSV: " + str(path))
                            yield path, info
                        else:
                            metrics.skipped_special += 1
                    except OSError as exc:
                        metrics.add_error(f"无法检查文件 {path}: {exc}")
        except OSError as exc:
            metrics.add_error(f"无法读取目录 {folder}: {exc}")


def prune_empty_directories(target: Target, metrics: Counters) -> None:
    """After deletion, remove only empty cache subfolders; preserve target root."""
    if not target.valid() or not target.path.is_dir():
        return
    stack: List[Tuple[Path, bool]] = [(target.path, False)]
    while stack:
        folder, ready = stack.pop()
        if not strictly_within(folder, target.boundary) or not ancestors_clear(folder):
            continue
        if ready:
            if folder != target.path:
                try:
                    os.rmdir(folder)  # refuses any folder that isn't empty
                    metrics.deleted_folders += 1
                except OSError:
                    pass
            continue
        stack.append((folder, True))
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if (entry.is_dir(follow_symlinks=False) and
                            not is_reparse_or_link(entry.path) and
                            not is_preserved_temp_subtree(target, entry.name)):
                        stack.append((Path(entry.path), False))
        except OSError:
            continue


def scan_target(target: Target, age_days: int,
                rows: Optional[csv.writer] = None) -> Result:
    result = Result(target.name, target.group, str(target.path), age_days, "ok")
    if not target.valid():
        result.status = "不安全路径/重解析点：已跳过"
        return result
    if not target.path.is_dir():
        result.status = "不存在：已跳过"
        return result
    cutoff = time.time() - age_days * 86400
    for _ in iter_eligible_files(target, cutoff, result.metrics, rows):
        pass
    return result


def clean_target(target: Target, age_days: int, processes: Optional[set[str]]) -> Result:
    result = Result(target.name, target.group, str(target.path), age_days, "ok")
    if not target.valid():
        result.status = "不安全路径/重解析点：已跳过"
        return result
    if not target.path.is_dir():
        result.status = "不存在：已跳过"
        return result
    if target.process_name and (processes is None or target.process_name in processes):
        result.status = "相关程序仍运行/进程检测失败：未清理"
        return result
    cutoff = time.time() - age_days * 86400
    for path, st0 in iter_eligible_files(target, cutoff, result.metrics):
        try:
            # Re-validate just before the actual destructive operation.
            if (not target.valid() or not strictly_within(path, target.path) or
                    not ancestors_clear(path)):
                result.metrics.skipped_special += 1
                continue
            if protected_temp_file(target, path):
                result.metrics.skipped_special += 1
                continue
            latest = os.lstat(path)
            if (not stat.S_ISREG(latest.st_mode) or
                    getattr(latest, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT or
                    latest.st_mtime > cutoff or latest.st_mtime != st0.st_mtime or
                    latest.st_size != st0.st_size):
                result.metrics.skipped_special += 1
                continue
            os.unlink(path)
            result.metrics.deleted_files += 1
            result.metrics.deleted_bytes += max(latest.st_size, 0)
        except OSError as exc:
            result.metrics.add_error(f"无法删除 {path}: {exc}")
    # Do not remove temporary directories: other running programs may rely on
    # their existence. Cache-only directories may be pruned after real deletions.
    if result.metrics.deleted_files and target.group not in ("user-temp", "system-temp"):
        prune_empty_directories(target, result.metrics)
    return result


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def elevate(args: Sequence[str]) -> bool:
    """Run the current script with UAC; never run arbitrary shell strings."""
    try:
        # Uses argv quoting correctly for spaces and Chinese filesystem paths.
        params = subprocess.list2cmdline([str(Path(__file__).resolve()), *args, "--hold"])
        shell_exec = ctypes.windll.shell32.ShellExecuteW
        shell_exec.restype = ctypes.c_void_p
        code = shell_exec(None, "runas", sys.executable, params, None, 1)
        if code is None or code <= 32:
            print(f"管理员权限申请失败或被取消（系统代码 {code}）。")
            return False
        print("已请求 UAC 管理员授权；后续操作请查看新打开的控制台窗口。")
        return True
    except (AttributeError, OSError) as exc:
        print("无法启动管理员窗口：", exc)
        return False


def hold_screen(hold: bool) -> None:
    if hold:
        try:
            input("\n按回车关闭此窗口...")
        except (KeyboardInterrupt, EOFError):
            pass


def run_dism(hold: bool) -> int:
    try:
        print("\nWindows 官方组件维护：DISM /Online /Cleanup-Image /StartComponentCleanup")
        print("这会删除已被取代的旧系统组件；不使用 /ResetBase；不直接修改 WinSxS。")
        print("此操作可能影响卸载较早的 Windows 更新，且可能运行较久。")
        if not is_admin():
            response = input("输入 DISM 以打开管理员窗口继续（其它内容取消）：").strip()
            if response != "DISM":
                print("已取消。")
                return 0
            return 0 if elevate(["--dism"]) else 2
        response = input("管理员模式：再次输入 DISM 确认执行：").strip()
        if response != "DISM":
            print("已取消。")
            return 0
        try:
            exit_code = subprocess.call(["dism.exe", "/Online", "/Cleanup-Image", "/StartComponentCleanup"])
            print("DISM 执行结束，退出代码：", exit_code)
            return exit_code
        except OSError as exc:
            print("无法运行 DISM：", exc)
            return 2
    finally:
        hold_screen(hold)


def print_disk() -> Optional[int]:
    try:
        disk = shutil.disk_usage("C:\\")
        print(f"C 盘总容量 {format_bytes(disk.total)}，已用 {format_bytes(disk.used)}，"
              f"可用 {format_bytes(disk.free)}")
        return disk.free
    except OSError:
        print("C 盘空间信息暂时不可用。")
        return None


def report_directory() -> Path:
    # The kit may be launched from read-only media, so write per-user reports.
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    out = base / "CDriveCleanupReports"
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError:
        out = Path.cwd()
    return out


def save_report(data: Dict, stamp: str) -> Optional[Path]:
    path = report_directory() / f"cleanup_{stamp}.json"
    try:
        with path.open("w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
        print("JSON 报告：", path)
        return path
    except OSError as exc:
        print("报告写入失败（不影响清理）：", exc)
        return None


def readonly_size_audit(max_entries: int = 300000, max_seconds: int = 60,
                        root: Optional[Path] = None) -> int:
    """Bounded, read-only C:\\ inspection. NEVER deletes or opens file contents."""
    print("\nC 盘空间占用检查（只读，不删除、不读取文件内容）")
    print(f"最大遍历项数 {max_entries:,}，最长运行 {max_seconds} 秒；超限结果不完整。")
    print_disk()
    root = Path("C:\\") if root is None else root
    if not root.is_dir() or not ancestors_clear(root):
        print("无法安全访问 C 盘根目录。")
        return 2
    deadlines = time.monotonic() + max_seconds
    files_seen = 0
    dirs_seen = 0
    entries_seen = 0
    inaccessible = 0
    category_bytes: Dict[str, int] = {}
    largest: List[Tuple[int, str]] = []
    folders = [root]
    while folders and entries_seen < max_entries and time.monotonic() <= deadlines:
        folder = folders.pop()
        if is_reparse_or_link(folder):
            continue
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if entries_seen >= max_entries or time.monotonic() > deadlines:
                        break
                    entries_seen += 1
                    try:
                        st = entry.stat(follow_symlinks=False)
                        if (stat.S_ISLNK(st.st_mode) or
                                getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT):
                            continue
                        if stat.S_ISDIR(st.st_mode):
                            dirs_seen += 1
                            folders.append(Path(entry.path))
                        elif stat.S_ISREG(st.st_mode):
                            files_seen += 1
                            size = max(0, st.st_size)
                            if is_c_drive(root):
                                relative = PureWindowsPath(ntpath.relpath(entry.path, str(root))).parts
                            else:  # Isolated test roots (not available from CLI)
                                relative = Path(os.path.relpath(entry.path, root)).parts
                            category = relative[0] if len(relative) > 1 else "[C 盘根目录文件]"
                            category_bytes[category] = category_bytes.get(category, 0) + size
                            row = (size, str(entry.path))
                            if len(largest) < 20:
                                heapq.heappush(largest, row)
                            elif row > largest[0]:
                                heapq.heapreplace(largest, row)
                    except OSError:
                        inaccessible += 1
        except OSError:
            inaccessible += 1

    bounded = bool(folders) or entries_seen >= max_entries or time.monotonic() > deadlines
    print(f"遍历：{entries_seen:,} 项，文件 {files_seen:,} 个，目录 {dirs_seen:,} 个；"
          f"无权限/读取异常 {inaccessible:,} 项。")
    if bounded or inaccessible:
        print("注意：以下为已扫描部分的累计大小，不是完整磁盘占用统计。")
    print("\n已扫描文件的 C 盘一级目录体积（仅供排查，不自动删除）：")
    for group, size in sorted(category_bytes.items(), key=lambda x: x[1], reverse=True)[:20]:
        print(f"  {format_bytes(size):>13}   C:\\{group}")
    print("\n发现的最大文件（只显示位置，不清理）：")
    for size, path in sorted(largest, reverse=True):
        print(f"  {format_bytes(size):>13}   {path}")
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    save_report({
        "mode": "readonly_size_audit",
        "generated_at": dt.datetime.now().isoformat(),
        "incomplete": bounded or bool(inaccessible),
        "entries_seen": entries_seen,
        "files_seen": files_seen,
        "dirs_seen": dirs_seen,
        "inaccessible": inaccessible,
        "top_level_bytes_scanned": category_bytes,
        "top_20_largest_files": [{"path": path, "bytes": size}
                                 for size, path in sorted(largest, reverse=True)],
        "note": "READ-ONLY, partial when limits or access errors apply. Do not blindly delete these files."
    }, stamp)
    return 0


def conda_exe_candidates(env: Optional[Dict[str, str]] = None,
                         python_exe: Optional[Path] = None) -> List[Path]:
    """Search standard conda installations without scanning arbitrary files."""
    env = dict(os.environ if env is None else env)
    home = Path(env.get("USERPROFILE", str(Path.home())))
    local = Path(env.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
    programdata = Path(env.get("PROGRAMDATA", r"C:\ProgramData"))
    possible: List[Path] = []
    for key in ("C_CLEANER_CONDA_EXE", "CONDA_EXE"):
        if env.get(key):
            possible.append(Path(env[key]))

    roots: List[Path] = []
    for key in ("C_CLEANER_CONDA_ROOT", "CONDA_PREFIX"):
        if env.get(key):
            roots.append(Path(env[key]))

    exe = Path(sys.executable if python_exe is None else python_exe)
    # A Python inside <conda>/envs/myenv can still locate its conda base.
    roots.extend([exe.parent, *list(exe.parents)[:4]])
    for base in (home, local, local / "Programs", programdata, Path("C:\\"),
                 Path("D:\\"), Path("E:\\")):
        for name in ("anaconda3", "Anaconda3", "miniconda3", "Miniconda3",
                     "miniforge3", "Miniforge3", "mambaforge", "Mambaforge"):
            roots.append(base / name)
    seen = set()
    for root in roots:
        possible.append(root / "Scripts" / "conda.exe")
    found_path = shutil.which("conda.exe")
    if found_path:
        possible.append(Path(found_path))
    uniq = []
    for candidate in possible:
        key = ntpath.normcase(ntpath.normpath(str(candidate)))
        if key not in seen:
            seen.add(key)
            uniq.append(candidate)
    return uniq


def find_conda_exe(env: Optional[Dict[str, str]] = None,
                   python_exe: Optional[Path] = None) -> Optional[Path]:
    for p in conda_exe_candidates(env, python_exe):
        # Never execute conda.bat through cmd /c or a general shell.
        if p.name.casefold() != "conda.exe":
            continue
        if not p.is_absolute() or not p.is_file() or not ancestors_clear(p):
            continue
        return p
    return None


def show_environment_inventory() -> int:
    print("\nPython / Anaconda / Miniconda / Miniforge discovery")
    print("Python interpreter:", sys.executable)
    print("Python version:", sys.version.split()[0])
    print("Python prefix:", sys.prefix)
    print("Python base_prefix:", getattr(sys, "base_prefix", sys.prefix))
    exe = find_conda_exe()
    print("Conda executable:", str(exe) if exe else "not found")
    if exe:
        print("Conda base candidate:", exe.parent.parent)
    print("No environments, packages, installations, or model files are deleted by discovery.")
    return 0


def conda_pkgs_roots_c_only(executable: Path) -> Tuple[bool, List[str]]:
    """Fail closed if conda may clean caches on volumes other than C:."""
    try:
        command = subprocess.run([str(executable), "info", "--json"],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=45, check=False)
        if command.returncode != 0:
            return False, []
        payload = json.loads(command.stdout)
        dirs = payload.get("pkgs_dirs", [])
        if not isinstance(dirs, list) or not dirs or not all(isinstance(p, str) for p in dirs):
            return False, []
        return all(is_c_drive(p) for p in dirs), dirs
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False, []


def run_conda_clean(what: str) -> int:
    """Use official conda commands, never manual deletion from pkgs/ or envs/."""
    exe = find_conda_exe()
    if exe is None:
        print("未发现可执行的 conda.exe。Conda 清理已跳过；不会修改任何环境。")
        return 2
    only_c, cache_dirs = conda_pkgs_roots_c_only(exe)
    if not only_c:
        print("保护限制：无法验证 conda 所有包缓存目录都在 C:，已拒绝执行。")
        if cache_dirs:
            print("Conda 当前缓存目录：")
            for folder in cache_dirs:
                print("  ", folder)
        print("这避免了意外清理 D:/E: 等其它磁盘。")
        return 2

    flags = ["--index-cache", "--logfiles"] if what == "index" else ["--tarballs"]
    print("\nConda executable:", exe)
    print("Verified C: package-cache directories:")
    for folder in cache_dirs:
        print("  ", folder)
    print("Official conda clean preview (no deletion):")
    try:
        preview = subprocess.run([str(exe), "clean", *flags, "--dry-run"],
                                 timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("Conda 预览失败：", exc)
        return 2
    if preview.returncode != 0:
        print("Conda 预览未成功，已停止。退出码：", preview.returncode)
        return preview.returncode
    if what == "tarballs":
        print("注意：下载归档包清理后，离线重装可能需要重新下载。")
        token = "CONDA_TARBALLS"
    else:
        print("只清理 conda 的索引缓存和日志，不清理已安装包和环境。")
        token = "CONDA_INDEX"
    if input("输入 " + token + " 才执行（其它内容取消）：").strip() != token:
        print("已取消。")
        return 0
    try:
        return subprocess.call([str(exe), "clean", *flags, "--yes"], timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("Conda 清理未能完成：", exc)
        return 2


def interactive_menu() -> int:
    """Advanced mode; each potentially destructive action is confirmed."""
    choices = {
        "1": ["--scan", "--groups", "all", "--export-csv"],
        "2": ["--one-click"],
        "3": ["--clean", "--groups", "gpu,browser,ide"],
        "4": ["--clean", "--groups", "pip,npm,uv,poetry,yarn,nuget"],
        "5": ["--conda-index"],
        "6": ["--conda-tarballs"],
        "7": ["--clean", "--groups", "system-temp,system-wer"],
        "8": ["--dism"],
        "9": ["--audit", "--max-seconds", "90"],
        "A": ["--inventory"],
        "B": ["--clean", "--groups", "crash"],
    }
    while True:
        print("\n" + "=" * 72)
        print("C: 智能空间清理 v" + VERSION + " | Python 3.8+ | Windows 10/11")
        print("[1] 深度扫描所有已知缓存（只读，导出 CSV）")
        print("[2] 一键安全综合清理（无需二次输入，立即清理预设缓存）")
        print("[3] 浏览器 + GPU + IDE 缓存（需要确认）")
        print("[4] pip / uv / npm / Yarn / Poetry / NuGet 缓存（需要确认）")
        print("[5] Conda 索引 + 日志（官方命令，预览并确认）")
        print("[6] Conda 下载归档包（可能影响离线安装，确认）")
        print("[7] Windows 系统 Temp / WER（需要管理员）")
        print("[8] DISM Windows 组件清理（需要管理员）")
        print("[9] C: 最大文件占用调查（只读，时间限制）")
        print("[A] 查看 Python / Anaconda / Miniconda 检测结果")
        print("[B] 旧崩溃转储（30 天以上，谨慎）")
        print("[C] 打开 Windows 磁盘清理界面")
        print("[D] 打开 Windows 存储感知")
        print("[E] 打开报告目录")
        print("[0] 退出")
        print("保护：Conda envs/.venv、模型、源码、个人文档、WinSxS")
        try:
            choice = input("请输入选项：").strip().upper()
        except (EOFError, KeyboardInterrupt):
            return 0
        if choice == "0":
            return 0
        if choice in ("C", "D", "E"):
            try:
                if choice == "C":
                    subprocess.Popen(["cleanmgr.exe", "/d", "C:"])
                elif choice == "D":
                    os.startfile("ms-settings:storagepolicies")
                else:
                    subprocess.Popen(["explorer.exe", str(report_directory())])
            except OSError as exc:
                print("Windows 功能无法打开：", exc)
        elif choice in choices:
            try:
                cli(choices[choice])
            except KeyboardInterrupt:
                print("已停止当前操作。")
        else:
            print("选项无效，请重新输入。")


def parse_groups(expression: str) -> List[str]:
    values = [x.strip().lower() for x in expression.split(",") if x.strip()]
    if values == ["all"]:
        return list(GROUPS)
    if not values:
        raise ValueError("至少需要一个清理组")
    unknown = sorted(set(values).difference(GROUPS))
    if unknown:
        raise ValueError("未知组：" + ", ".join(unknown))
    return list(dict.fromkeys(values))


def summary(results: Iterable[Result], cleaning: bool = False) -> Tuple[int, int]:
    total_files = 0
    total_bytes = 0
    print("\n" + "=" * 82)
    for res in results:
        m = res.metrics
        total_files += m.deleted_files if cleaning else m.candidates
        total_bytes += m.deleted_bytes if cleaning else m.bytes
        if res.status == "不存在：已跳过":
            continue
        amount = m.deleted_bytes if cleaning else m.bytes
        count = m.deleted_files if cleaning else m.candidates
        print(f"[{res.group}] {res.target} | {count} 个文件 | {format_bytes(amount)}")
        print(f"    {res.path} (保留最近 {res.age_days} 天)")
        if res.status != "ok":
            print("    状态：", res.status)
        if m.skipped_special or m.errors:
            print(f"    受保护/特殊项跳过 {m.skipped_special}；访问/处理错误 {m.errors}")
        for error in m.error_examples[:2]:
            print("    错误例子：", error)
    print("-" * 82)
    verb = "已删除" if cleaning else "预计可清理（仅估算）"
    print(f"{verb}：{total_files} 个文件，{format_bytes(total_bytes)}")
    if cleaning:
        print("说明：删除字节数不等于磁盘实际增加空间（压缩/硬链接/磁盘占用差异）。")
    print("=" * 82)
    return total_files, total_bytes


def cli(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Windows C 盘缓存清理 / Python-Conda 环境自动发现（默认仅扫描）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""组：user-temp,wer,gpu,browser,pip,npm,uv,poetry,yarn,nuget,ide,crash,system-temp,system-wer
示例：python C_Drive_Cleanup.py --scan --groups all
      python C_Drive_Cleanup.py --one-click
      python C_Drive_Cleanup.py --clean --groups user-temp,wer
      python C_Drive_Cleanup.py --conda-index
      python C_Drive_Cleanup.py --clean --groups pip,uv --age-days 0
切记：--clean 需要输入 CLEAN；--one-click 只使用固定安全清理清单，自动清理。""",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--scan", action="store_true", help="扫描并报告（默认）")
    mode.add_argument("--clean", action="store_true", help="扫描、再次确认、随后清理")
    mode.add_argument("--one-click", action="store_true", help="无需确认，自动清理固定安全缓存组")
    mode.add_argument("--dism", action="store_true", help="执行 Windows 官方组件维护（需管理员）")
    mode.add_argument("--audit", action="store_true", help="只读检查 C 盘大文件及一级目录占用")
    mode.add_argument("--menu", action="store_true", help="高级交互式菜单")
    mode.add_argument("--inventory", action="store_true", help="查看所用 Python/Conda 安装信息")
    mode.add_argument("--conda-index", action="store_true", help="官方 conda 索引缓存清理，确认后执行")
    mode.add_argument("--conda-tarballs", action="store_true", help="官方 conda 包归档缓存清理，确认后执行")
    parser.add_argument("--groups", default=",".join(DEFAULT_GROUPS), help="逗号分隔组名，或 all")
    parser.add_argument("--age-days", type=int, default=None, help="覆盖默认保留天数，0 表示清理所有年龄的缓存")
    parser.add_argument("--export-csv", action="store_true", help="扫描时导出候选文件清单 CSV")
    parser.add_argument("--max-seconds", type=int, default=60, help="--audit 最多耗时秒数（5-300）")
    parser.add_argument("--max-entries", type=int, default=300000, help="--audit 最多检查项数（1000-2000000）")
    parser.add_argument("--hold", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if os.name != "nt":
        parser.error("此工具仅可在 Windows 10/11 下运行；不会在其它系统清理文件。")
    if args.age_days is not None and not 0 <= args.age_days <= 3650:
        parser.error("--age-days 范围必须是 0 到 3650")

    if args.menu:
        return interactive_menu()
    if args.inventory:
        return show_environment_inventory()
    if args.conda_index:
        return run_conda_clean("index")
    if args.conda_tarballs:
        return run_conda_clean("tarballs")
    if args.dism:
        if not is_c_drive(os.environ.get("SystemRoot", "")):
            print("为避免清理非 C 盘的 Windows 组件，已阻止 DISM：系统目录不在 C 盘。")
            return 2
        return run_dism(args.hold)
    if args.audit:
        if not 5 <= args.max_seconds <= 300 or not 1000 <= args.max_entries <= 2000000:
            parser.error("--audit 的 --max-seconds 要求 5-300；--max-entries 要求 1000-2000000")
        return readonly_size_audit(args.max_entries, args.max_seconds)
    try:
        selected = list(ONE_CLICK_GROUPS) if args.one_click else parse_groups(args.groups)
    except ValueError as exc:
        parser.error(str(exc))

    if args.one_click and (args.age_days is not None or
                           args.groups != ",".join(DEFAULT_GROUPS)):
        parser.error("--one-click 不接受 --groups 或 --age-days 覆盖，保护安全预设")

    if args.clean and SYSTEM_GROUPS.intersection(selected):
        if any(g not in SYSTEM_GROUPS for g in selected):
            print("安全限制：系统清理组不得与用户清理组混合执行。请分开操作。")
            return 2
        if not is_admin():
            print("系统临时文件和系统错误报告需要管理员授权。")
            confirm = input("输入 ADMIN 打开管理员窗口（其它内容取消）：").strip()
            if confirm != "ADMIN":
                print("已取消。")
                return 0
            return 0 if elevate(["--clean", "--groups", ",".join(selected)] +
                                (["--age-days", str(args.age_days)] if args.age_days is not None else [])) else 2

    print("=" * 82)
    print(f"C 盘安全清理工具 v{VERSION} | Windows 10/11 | 标准库，无需额外安装")
    print("一键安全模式（固定目标，自动删除）" if args.one_click else
          ("删除模式（需明确确认）" if args.clean else "扫描模式"))
    print("保护：项目源码/Downloads/桌面/文档/FinGPT / HF 模型/Conda/.venv/CUDA/WinSxS")
    print("不清除浏览器 Cookie、书签、密码、历史、Service Worker 离线数据。")
    print("=" * 82)
    before_free = print_disk()
    targets = [x for x in make_targets() if x.group in selected]
    print("已选组：", ", ".join(f"{x}({GROUPS[x][0]})" for x in selected))
    if args.age_days is not None:
        print(f"保留天数覆盖值：{args.age_days} 天")
    if not targets:
        print("未发现有效清理目标（用户目录可能不在 C 盘）。")

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    csv_file = None
    csv_writer = None
    if args.export_csv:
        csv_path = report_directory() / f"candidates_{stamp}.csv"
        try:
            csv_file = csv_path.open("w", encoding="utf-8-sig", newline="")
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(("组", "位置", "文件路径", "字节数", "修改时间"))
            print("CSV 候选清单：", csv_path)
        except OSError as exc:
            print("CSV 无法创建：", exc)
    try:
        pre_results = []
        for idx, target in enumerate(targets, 1):
            print(f"[扫描 {idx}/{len(targets)}] {target.name}", flush=True)
            pre_results.append(scan_target(
                target, args.age_days if args.age_days is not None else GROUPS[target.group][1],
                csv_writer))
    finally:
        if csv_file is not None:
            csv_file.close()
    candidate_files, candidate_bytes = summary(pre_results)
    extra_warnings: List[str] = []
    cleaning = args.clean or args.one_click
    if cleaning and "crash" in selected:
        extra_warnings.append("崩溃转储可能影响软件/蓝屏问题诊断。")
    if cleaning and any(x in selected for x in ("pip", "npm", "uv", "poetry", "yarn", "nuget")):
        extra_warnings.append("删除包缓存不删除已安装环境，但以后可能需要重新下载依赖。")
    if cleaning and "gpu" in selected:
        extra_warnings.append("图形/驱动缓存会重建，首次运行某些程序可能变慢。")
    if cleaning and "browser" in selected:
        extra_warnings.append("请先完全退出浏览器及后台进程；正在运行则自动跳过其缓存。")
    for warning in extra_warnings:
        print("注意：", warning)

    post_results: List[Result] = []
    status = "scan_only"
    if cleaning:
        if not candidate_files:
            print("目前没有达到指定清理天数的候选文件；未执行删除。")
            status = "nothing_to_clean"
        else:
            keyword = "DELETE_CRASH_DUMPS" if "crash" in selected else "CLEAN"
            print("\n注意：删除操作不经过回收站，无法由本程序撤销。")
            print("候选数值是估算，实际删除时会再次验证路径和文件年龄。")
            if args.one_click:
                print("一键模式只清理固定的用户缓存白名单，无需再输入 CLEAN。")
                approved = True
            else:
                response = input(f"确认删除请准确输入 {keyword}（其它内容取消）：").strip()
                approved = response == keyword
            if not approved:
                print("用户已取消。无任何文件被删除。")
                status = "cancelled"
            else:
                status = "completed"
                proc_info = active_processes() if any(x.process_name for x in targets) else set()
                if proc_info is None:
                    print("无法读取运行进程，涉及浏览器/Node/uv 的缓存将安全跳过。")
                for idx, target in enumerate(targets, 1):
                    print(f"\r正在清理 {idx}/{len(targets)}：{target.name}                    ", end="", flush=True)
                    post_results.append(clean_target(
                        target, args.age_days if args.age_days is not None else GROUPS[target.group][1],
                        proc_info))
                print()
                summary(post_results, cleaning=True)
    after_free = print_disk()
    if before_free is not None and after_free is not None and cleaning and post_results:
        print("运行前后 C 盘可用空间变化：", format_bytes(max(after_free - before_free, 0))
              if after_free >= before_free else "可用空间减少（可能有其它程序同时写入）")

    report = {
        "version": VERSION,
        "generated_at": dt.datetime.now().isoformat(),
        "mode": "one_click" if args.one_click else ("clean" if args.clean else "scan"),
        "status": status,
        "python_executable": sys.executable,
        "python_version": sys.version.split()[0],
        "bootstrap_source": os.environ.get("C_CLEANER_BOOTSTRAP_SOURCE", "direct"),
        "bootstrap_runtime_root": os.environ.get("C_CLEANER_BOOTSTRAP_RUNTIME_ROOT", ""),
        "groups": selected,
        "age_override_days": args.age_days,
        "estimated_files": candidate_files,
        "estimated_bytes": candidate_bytes,
        "c_free_before": before_free,
        "c_free_after": after_free,
        "pre_scan": [r.as_dict() for r in pre_results],
        "clean_results": [r.as_dict() for r in post_results],
        "not_automatically_cleaned": [
            "Downloads/Desktop/Documents/OneDrive",
            "Virtual environments: .venv/venv/conda, Python and CUDA installations",
            "FinGPT/HuggingFace/PyTorch model caches and checkpoints",
            "Windows WinSxS, SoftwareDistribution, Windows Installer, driver store",
            "Recycle Bin and Windows.old (use official Windows UI)",
        ],
    }
    save_report(report, stamp)
    hold_screen(args.hold)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(cli())
    except KeyboardInterrupt:
        print("\n用户中断，未继续处理。")
        sys.exit(130)
