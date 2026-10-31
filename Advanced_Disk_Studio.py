#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C-Scan Studio v3.4: loopback-only disk analysis dashboard.

- No third-party Python packages, tkinter, admin rights, or cloud API.
- Safe cache targets are supplied exclusively by the v2.2 allowlist engine.
- Large-file discovery is READ ONLY; optional Everything ES IPC or bounded scandir.
- Deletion is ONLY possible for previously scanned, unchanged cache file snapshots.
- Uses ephemeral random session token, same-origin POST checks and loopback binding.
"""
from __future__ import annotations

import csv
import hashlib
import heapq
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
# Also works when launched with python -I by the verified embedded runtime.
sys.path.insert(0, str(HERE))
import C_Drive_Cleanup as engine
import Everything_Official_Manager as vendor
import Security_Audit as security_audit
from Unified_Tools import Toolbox
import Drive_Inspector as inspector

VERSION = "3.6.0-beta.4"
CLEAN_PREVIEW_TTL = 120  # seconds, single-use, server-issued token
REPARSE = 0x0400
MIB = 1024 ** 2
GIB = 1024 ** 3
MAX_JSON = 64 * 1024

# Risk and priority are deliberately independent: large occupied space is not
# proof that deletion is safe. These are category policies, not AI judgments.
POLICY = {
    "user-temp": ("green", "14 天以上的临时文件；保留工程/模型等敏感类型", "旧临时文件通常可再生；仍建议先检查文件清单。"),
    "wer": ("amber", "已归档的旧错误报告", "可能影响排查历史崩溃；确实不需要诊断时再清理。"),
    "gpu": ("amber", "驱动/DirectX 会重新生成的着色器缓存", "首次启动游戏或 AI 图形程序可能卡顿，缓存会重建。"),
    "browser": ("amber", "浏览器磁盘缓存；浏览器运行时不清理", "可能重新下载网页资源；不包括 Cookies/书签/密码。"),
    "pip": ("amber", "pip 包下载和构建缓存", "不会删除已安装包；离线安装可能需要重新下载。"),
    "npm": ("amber", "npm 下载缓存", "不会删除 node_modules；离线安装可能需要重新下载。"),
    "uv": ("amber", "uv 下载缓存", "不会删除 Python 虚拟环境；离线安装可能需要重新下载。"),
    "poetry": ("amber", "Poetry 下载缓存", "不会删除工程源码或虚拟环境。"),
    "yarn": ("amber", "Yarn Classic 下载缓存", "不会删除 node_modules；之后可能重新下载。"),
    "nuget": ("amber", "NuGet HTTP 下载缓存", "不会触碰 global-packages，离线还原可能受影响。"),
    "ide": ("orange", "编辑器索引和渲染缓存", "重建缓存可能耗时；为安全起见仅建议手动查看。"),
    "crash": ("red", "崩溃转储文件", "可能是定位蓝屏/崩溃问题的唯一证据；只展示不删除。"),
    "system-temp": ("orange", "Windows 系统 Temp", "涉及管理员权限和服务占用；请使用 Windows 官方清理。"),
    "system-wer": ("orange", "系统级归档错误报告", "可能需要管理员权限；请使用 Windows 官方清理。"),
}
RISK_TEXT = {"green": "绿色 · 低", "amber": "黄色 · 中", "orange": "橙色 · 高", "red": "红色 · 极高", "gray": "灰色 · 保护"}
RISK_ORDER = {"green": 0, "amber": 1, "orange": 2, "red": 3, "gray": 4}
AUTOCLEAN_RISKS = frozenset(("green", "amber"))
# Preserve valuable install/runtime artifacts even if a user left them in Temp.
EXTRA_PRESERVE_TEMP_SUFFIXES = frozenset((
    ".exe", ".dll", ".msi", ".msix", ".msp", ".msixbundle", ".appx",
    ".whl", ".conda", ".deb", ".rpm", ".cab", ".jar", ".aab",
    ".apk", ".dmg", ".img", ".vdi", ".vmdk", ".qcow2",
    ".lock", ".yaml", ".yml", ".toml", ".ini", ".cfg",
))

ADVISORIES = [
    {"name": "下载 / 桌面 / 文档 / OneDrive", "risk": "red", "priority": "P4", "reason": "个人文件不能由清理器自动推断是否需要；只做大文件定位。"},
    {"name": "Hugging Face / FinGPT / LoRA / PyTorch 模型", "risk": "gray", "priority": "P4", "reason": "模型和权重优先保护，禁止自动删除，即使很大。"},
    {"name": "Anaconda / Conda envs / Python / CUDA", "risk": "gray", "priority": "P4", "reason": "运行环境、包目录和驱动不在删除清单中。"},
    {"name": "WinSxS / Windows Installer / DriverStore", "risk": "red", "priority": "P4", "reason": "禁止直接删除；请通过 Windows 存储设置和 DISM 官方维护。"},
    {"name": "回收站 / Windows.old / Windows 更新", "risk": "orange", "priority": "P3", "reason": "建议通过 Windows 设置 → 存储 → 临时文件检查，可能失去恢复能力。"},
    {"name": "WSL / Docker / Hyper-V 的 VHDX", "risk": "red", "priority": "P4", "reason": "磁盘镜像可能承载系统和项目数据；只能用对应工具管理。"},
]


def format_bytes(number):
    return engine.format_bytes(max(0, int(number)))


def compute_priority(risk, bytes_count, drive_free=None, drive_total=None):
    """Priority is recommendation order, never an authorization to delete."""
    size = max(0, int(bytes_count or 0))
    very_low_free = bool(drive_total and drive_free is not None and drive_free / drive_total < 0.10)
    if risk == "green":
        return "P1" if size >= 256 * MIB or (very_low_free and size >= 64 * MIB) else "P2"
    if risk == "amber":
        return "P2" if size >= 128 * MIB else "P3"
    if risk == "orange":
        return "P3"
    return "P4"


def classify_large_file(path):
    normalized = str(path).replace("/", "\\").casefold()
    suffix = Path(path).suffix.casefold()
    name = Path(path).name.casefold()
    protected_segments = ("\\huggingface\\", "\\checkpoints\\", "\\models\\", "\\lora\\",
                          "\\anaconda", "\\miniconda", "\\miniforge", "\\envs\\", "\\.venv\\",
                          "\\venv\\", "\\nvidia gpu computing toolkit\\", "\\site-packages\\")
    if any(seg in normalized for seg in protected_segments) or suffix in (".gguf", ".safetensors", ".ckpt", ".pth", ".pt", ".onnx"):
        return "gray", "模型/环境/权重：明确保护；不要直接删除。"
    if name in ("pagefile.sys", "swapfile.sys", "hiberfil.sys"):
        return "red", "Windows 虚拟内存/休眠文件，只能通过系统设置管理。"
    if suffix in (".vhdx", ".vhd", ".vmdk", ".qcow2", ".iso"):
        return "red", "虚拟磁盘/镜像文件；可能包含操作系统或重要数据。"
    if normalized.startswith("c:\\windows\\") or normalized.startswith("c:\\program files\\") or normalized.startswith("c:\\program files (x86)\\"):
        return "red", "系统或应用安装文件；禁止直接手工删除。"
    if any(seg in normalized for seg in ("\\desktop\\", "\\downloads\\", "\\documents\\", "\\onedrive\\")):
        return "red", "个人资料或下载内容；先打开确认用途。"
    return "orange", "未知大文件：只供定位，人工核实所属程序和备份后再处理。"


def detect_es_exe(tool_dir=HERE, environ=None):
    """Only use an already installed official CLI, never download/run new code."""
    env = dict(os.environ if environ is None else environ)
    paths = [Path(tool_dir) / "Tools" / "es.exe", Path(tool_dir) / "es.exe"]
    located = shutil.which("es.exe")
    if located:
        paths.append(Path(located))
    for base in (env.get("ProgramFiles"), env.get("ProgramFiles(x86)"), env.get("LOCALAPPDATA")):
        if base:
            paths.extend((Path(base) / "Everything" / "es.exe", Path(base) / "Microsoft" / "WindowsApps" / "es.exe"))
    for path in paths:
        try:
            if path.is_file() and not engine.is_reparse_or_link(path):
                return str(path)
        except OSError:
            continue
    return None


def list_large_everything(es_path, min_bytes, stop=None, limit=180, root="C:\\"):
    """Search an existing Everything index for large files. Never deletes."""
    args = [str(es_path), "-path", str(root), "-sort", "size", "-sort-descending",
            "-n", str(min(int(limit), 250)), "-full-path-and-name", f"size:>{int(min_bytes)}b"]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(args, capture_output=True, timeout=16, check=False, creationflags=flags)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"Everything CLI 不可用：{exc}"
    if stop is not None and stop.is_set():
        return [], "已取消"
    if completed.returncode != 0:
        return None, f"Everything IPC 返回 {completed.returncode}；将回退到普通扫描。"
    # ES console text uses the active Windows code page; try UTF-8 first.
    try:
        output = completed.stdout.decode("utf-8-sig")
    except UnicodeDecodeError:
        output = completed.stdout.decode("mbcs" if os.name == "nt" else "utf-8", errors="replace")
    found = []
    seen = set()
    for line in output.splitlines():
        path = line.strip().strip('"')
        if not engine.is_c_drive(path) or path.casefold() in seen:
            continue
        try:
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or ((getattr(info, "st_file_attributes", 0) or 0) & REPARSE):
                continue
            if info.st_size < min_bytes:
                continue
            found.append((str(path), int(info.st_size), float(info.st_mtime)))
            seen.add(path.casefold())
        except OSError:
            continue
    found.sort(key=lambda x: x[1], reverse=True)
    return found[:limit], "Everything 索引（仅用于大文件定位）"


def list_large_bounded(root, min_bytes, stop, max_seconds=25, max_entries=220000, limit=180, tick=None):
    """Read-only, time/entry-bounded walk using scandir. No NTFS MFT access."""
    start = time.monotonic()
    stack = [Path(root)]
    heap = []
    checked = 0
    inaccessible = 0
    stopped = False
    limited = False
    while stack:
        if stop.is_set():
            stopped = True
            break
        if time.monotonic() - start >= max_seconds or checked >= max_entries:
            limited = True
            break
        folder = stack.pop()
        try:
            with os.scandir(folder) as scan:
                for entry in scan:
                    checked += 1
                    if checked % 512 == 0:
                        if stop.is_set():
                            stopped = True
                            break
                        if time.monotonic() - start >= max_seconds or checked >= max_entries:
                            limited = True
                            break
                        if tick and checked % 8192 == 0:
                            tick(checked)
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode) or (getattr(info, "st_file_attributes", 0) or 0) & REPARSE:
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            stack.append(Path(entry.path))
                        elif stat.S_ISREG(info.st_mode) and info.st_size >= min_bytes:
                            point = (int(info.st_size), str(entry.path), float(info.st_mtime))
                            if len(heap) < limit:
                                heapq.heappush(heap, point)
                            elif point[0] > heap[0][0]:
                                heapq.heapreplace(heap, point)
                    except OSError:
                        inaccessible += 1
        except OSError:
            inaccessible += 1
        if stopped or limited:
            break
    files = [(path, size, mtime) for size, path, mtime in sorted(heap, reverse=True)]
    return files, {"scanned_entries": checked, "permission_errors": inaccessible,
                   "complete": not (stopped or limited), "stopped": stopped, "limited": limited,
                   "elapsed_seconds": round(time.monotonic() - start, 2)}


@dataclass(frozen=True)
class Snapshot:
    path: str
    size: int
    mtime_ns: int


def protected_temp_extra(target, path):
    return target.group in ("user-temp", "system-temp") and Path(path).suffix.casefold() in EXTRA_PRESERVE_TEMP_SUFFIXES


def safe_scan_target(target, age_days, stop, deadline, max_entries=180000):
    """Exact eligibility parity with v2.2 safety rules, but interruptible.

    All candidate snapshots are retained for deletion. A partial scan is NEVER
    deletable from the GUI, because preview could otherwise understate scope.
    """
    outcome = {"count": 0, "bytes": 0, "checked": 0, "skipped": 0,
               "errors": 0, "complete": True, "state": "完成"}
    snapshots = []
    if not target.valid():
        outcome.update(complete=False, state="无效或不安全的路径")
        return outcome, snapshots
    if not target.path.is_dir():
        outcome["state"] = "未找到"
        return outcome, snapshots
    cutoff = time.time() - int(age_days) * 86400
    dirs = [target.path]
    while dirs:
        if stop.is_set() or time.monotonic() >= deadline or outcome["checked"] >= max_entries:
            outcome.update(complete=False, state="已停止/超出快扫限额，仅显示部分")
            return outcome, snapshots
        folder = dirs.pop()
        if not engine.strictly_within(folder, target.boundary) or not engine.ancestors_clear(folder):
            outcome["skipped"] += 1
            continue
        if target.group in ("user-temp", "system-temp") and (
                engine.toolkit_contains_or_is_inside(folder) or engine.is_project_directory(folder)):
            outcome["skipped"] += 1
            continue
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    outcome["checked"] += 1
                    if outcome["checked"] % 128 == 0 and (
                            stop.is_set() or time.monotonic() >= deadline or outcome["checked"] >= max_entries):
                        outcome.update(complete=False, state="已停止/超出快扫限额，仅显示部分")
                        return outcome, snapshots
                    path = Path(entry.path)
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if (stat.S_ISLNK(info.st_mode) or
                                (getattr(info, "st_file_attributes", 0) or 0) & REPARSE):
                            outcome["skipped"] += 1
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            if (engine.is_preserved_temp_subtree(target, entry.name) or
                                    (target.group in ("user-temp", "system-temp") and
                                     (engine.toolkit_contains_or_is_inside(path) or engine.is_project_directory(path)))):
                                outcome["skipped"] += 1
                            else:
                                dirs.append(path)
                        elif stat.S_ISREG(info.st_mode):
                            if engine.protected_temp_file(target, path) or protected_temp_extra(target, path):
                                outcome["skipped"] += 1
                                continue
                            if info.st_mtime > cutoff:
                                continue
                            outcome["count"] += 1
                            outcome["bytes"] += max(0, int(info.st_size))
                            snapshots.append(Snapshot(str(path), max(0, int(info.st_size)),
                                                      int(info.st_mtime_ns)))
                        else:
                            outcome["skipped"] += 1
                    except OSError:
                        outcome["errors"] += 1
        except OSError:
            outcome["errors"] += 1
    return outcome, snapshots


def still_safe_snapshot(target, item, age_days):
    """Final checks before unlink. Never accept an arbitrary client path."""
    path = Path(item.path)
    if not target.valid() or not engine.strictly_within(path, target.path) or not engine.ancestors_clear(path):
        return False
    if engine.protected_temp_file(target, path) or protected_temp_extra(target, path):
        return False
    if target.group in ("user-temp", "system-temp"):
        folder = path.parent
        while engine.strictly_within(folder, target.path) or engine.same_path(folder, target.path):
            if (engine.is_preserved_temp_subtree(target, folder.name) or
                    engine.toolkit_contains_or_is_inside(folder) or engine.is_project_directory(folder)):
                return False
            if engine.same_path(folder, target.path) or folder.parent == folder:
                break
            folder = folder.parent
    try:
        latest = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(latest.st_mode) or (getattr(latest, "st_file_attributes", 0) or 0) & REPARSE:
        return False
    if (int(latest.st_size) != item.size or int(latest.st_mtime_ns) != item.mtime_ns or
            latest.st_mtime > time.time() - int(age_days) * 86400):
        return False
    return True


def clean_snapshot_target(target, snapshots, age_days, stop, running):
    """Never delete more than scanned-and-matched candidate snapshots."""
    count = 0
    removed_bytes = 0
    errors = 0
    skipped = 0
    if target.process_name and (running is None or target.process_name.lower() in running):
        return {"deleted": 0, "bytes": 0, "errors": 0, "skipped": len(snapshots), "state": "相关程序仍运行：跳过"}
    for idx, item in enumerate(snapshots):
        if stop.is_set():
            return {"deleted": count, "bytes": removed_bytes, "errors": errors,
                    "skipped": skipped, "state": "用户已中止"}
        if idx % 100 == 0 and target.process_name:
            now = engine.active_processes()
            if now is None or target.process_name.lower() in now:
                skipped += len(snapshots) - idx
                return {"deleted": count, "bytes": removed_bytes, "errors": errors,
                        "skipped": skipped, "state": "程序启动或进程状态不明：已停止"}
        if not still_safe_snapshot(target, item, age_days):
            skipped += 1
            continue
        try:
            os.unlink(item.path)
            count += 1
            removed_bytes += item.size
        except OSError:
            errors += 1
    return {"deleted": count, "bytes": removed_bytes, "errors": errors,
            "skipped": skipped, "state": "完成"}


class Analyzer:
    def __init__(self):
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.phase = "idle"
        self.message = "界面已就绪。建议先执行绿色缓存快速扫描。"
        self.progress = 0
        self.progress_max = 1
        self.targets = {}
        self.items = []
        self.snapshots = {}
        self.scan_complete = False
        self.inventory = inspector.empty_report()
        # Four-key read-only indexes are built once per immutable scan snapshot.
        # Never exposed via /api/state or included in downloadable reports.
        self._classification_cache_source = None
        self._classification_cache = {}
        self.drive_choices = []
        self.drive_choices_refreshed = 0.0
        self.large_files = []
        self.large_info = {"source": "未扫描", "complete": False, "scanned_entries": 0}
        self.logs = []
        self.latest_export = ""
        self.last_cleanup = None
        self.started_at = time.time()
        # Do not execute an ambient es.exe from PATH or third-party install paths.
        # An unknown executable must never be silently trusted by a disk scanner.
        self.es_exe = vendor.local_cli_if_verified(HERE)
        self.cleanup_preview = None
        self.thread = None
        self._record("启动本地只读分析器；默认不自动删除任何文件。")

    def _record(self, value):
        with self.lock:
            self.logs.append({"time": datetime.now().strftime("%H:%M:%S"), "message": str(value)[:300]})
            self.logs = self.logs[-120:]

    def _disk(self):
        try:
            disk = shutil.disk_usage("C:\\")
            return {"total": disk.total, "free": disk.free, "used": disk.used}
        except OSError:
            return {"total": 0, "free": 0, "used": 0}

    def list_drives(self):
        # Volume enumeration may be slow for disconnected USB drives. Cache the
        # UI list briefly; selection is *always* independently revalidated.
        with self.lock:
            if time.monotonic() - self.drive_choices_refreshed >= 20.0:
                self.drive_choices = inspector.available_drives()
                self.drive_choices_refreshed = time.monotonic()
            return list(self.drive_choices)

    def refresh_drives(self):
        with self.lock:
            self.drive_choices_refreshed = 0.0
        return self.list_drives()

    def start_inspection(self, drive_ids, min_kb=64):
        # Strict allowlist, NOT arbitrary user-supplied filesystem paths.
        try:
            size = int(min_kb)
            if type(min_kb) is bool or size not in (64, 1024, 16384):
                return False, '查重门槛只能是 64 KiB、1 MiB 或 16 MiB。'
            roots = inspector.select_drives(drive_ids)
        except (ValueError, OSError) as exc:
            return False, str(exc)
        def work():
            def tick(message):
                with self.lock:
                    self.message = message
            self._record('跨盘只读分析：' + ', '.join(str(x) for x in roots))
            found = inspector.inspect_roots(roots, self.cancel,
                                            min_duplicate_bytes=size * 1024,
                                            progress=tick)
            with self.lock:
                self.inventory = found
                self._classification_cache_source = None
                self._classification_cache = {}
                self.progress = 1
                self.progress_max = 1
                self.phase = 'idle'
                self.message = ('已取消，结果不完整；' if found['cancelled'] else
                                '只读分析完成；') + f"{found['files_seen']:,} 文件 / {found['total_duplicate_groups']} 组完整 SHA-256 相同。"
            self._record(self.message)
        return self._start('inventory', '正在对已选择磁盘做只读文件分类和查重...', work)

    def classified_files_page(self, category, offset=0, limit=50, subtype=None, drive=None):
        # All filters MUST be selected from this session's scanned hierarchy.
        # Never accept a filesystem path, glob, file handle or operation from UI.
        if (not isinstance(category, str) or len(category) > 32 or
                type(offset) is not int or type(limit) is not int or
                offset < 0 or not 1 <= limit <= 100 or
                (subtype is not None and (not isinstance(subtype, str) or len(subtype) > 48)) or
                (drive is not None and (not isinstance(drive, str) or len(drive) > 260))):
            return False, '分类分页参数无效。', None
        with self.lock:
            allowed_categories = {x['id'] for x in self.inventory.get('categories', [])}
            if category not in allowed_categories:
                return False, '请先对其他磁盘执行只读扫描，再选择已经识别的类别。', None
            hierarchy = self.inventory.get('hierarchy', [])
            cat_rows = [c for family in hierarchy for c in family.get('categories', [])
                        if c['id'] == category]
            if subtype is not None or drive is not None:
                # Filters are safe only when they match the actual scanned
                # hierarchy AND category. Missing hierarchy: do not guess.
                if not cat_rows:
                    return False, '未发现对应的已扫描分类层级，请刷新扫描。', None
                subtypes = [v for c in cat_rows for v in c.get('subtypes', [])]
                valid_subtypes = {v['id'] for v in subtypes}
                if subtype is not None and subtype not in valid_subtypes:
                    return False, '子类不属于当前扫描快照。', None
                drives = {v['id'] for v in subtypes if subtype is None or v['id'] == subtype
                          for v in v.get('drives', [])}
                if drive is not None and drive not in drives:
                    return False, '盘符不属于当前类别/子类的扫描快照。', None
            # The old implementation scanned all N records for each page.
            # A 40,000-file snapshot with 400 pages visited 16M records.
            # Cache four filter combinations under the lock; future page
            # reads are O(page length), not O(snapshot length).
            source = self.inventory.get('classified_files', [])
            if source is not self._classification_cache_source:
                index = {}
                for record in source:
                    cat = record['category']
                    sub = record.get('subtype')
                    volume = record.get('volume')
                    keys = {(cat, None, None), (cat, sub, None),
                            (cat, None, volume), (cat, sub, volume)}
                    for key in keys:
                        index.setdefault(key, []).append(record)
                self._classification_cache = index
                # Keep a strong reference: object ID reuse cannot cause stale
                # indexes when a new immutable scan snapshot replaces source.
                self._classification_cache_source = source
            all_items = self._classification_cache.get((category, subtype, drive), [])
            if offset > len(all_items):
                return False, '分页超出扫描清单。', None
            items = all_items[offset:offset + limit]
            return True, '只读展示已扫描文件的分类快照；没有打开或移动文件。', {
                'category': category, 'subtype': subtype, 'drive': drive,
                'total': len(all_items), 'offset': offset,
                'limit': limit, 'files': items,
                'next_offset': offset + len(items) if offset + len(items) < len(all_items) else None,
                'complete': bool(self.inventory.get('inventory_complete')),
            }

    def state(self):
        drives = self.list_drives()
        with self.lock:
            disk = self._disk()
            items = list(self.items)
            inventory_preview = dict(self.inventory)
            inventory_preview.pop('classified_files', None)
            preview_groups = []
            for group in self.inventory.get("duplicate_groups", [])[:100]:
                clipped = dict(group)
                clipped["hidden_copies"] = max(0, len(group["copies"]) - 30)
                clipped["copies"] = group["copies"][:30]
                preview_groups.append(clipped)
            inventory_preview["duplicate_groups"] = preview_groups
            inventory_preview["display_limit_note"] = "界面只展示最大 100 组、每组最多 30 个待复核位置。需查看所有已确认结果，请主动下载本地 JSON 报告。"
            return {"version": VERSION, "phase": self.phase, "message": self.message,
                    "progress": self.progress, "progress_max": self.progress_max,
                    "items": items, "large_files": list(self.large_files),
                    "large_info": dict(self.large_info), "scan_complete": self.scan_complete,
                    "inventory": inventory_preview, "drive_choices": drives,
                    "disk": disk, "es_status": ("官方 ES CLI 已核验（需 Everything 正在运行）" if self.es_exe else "没有经过 SHA-256 校验的官方 ES CLI；不会运行 PATH 中的未知 es.exe，采用限时扫描"),
                    "everything": vendor.status(HERE),
                    "busy": self.phase in ("scanning", "large", "cleaning", "setup", "inventory"),
                    "logs": list(self.logs[-35:]), "advisories": ADVISORIES,
                    "last_cleanup": self.last_cleanup}

    def _start(self, phase, message, worker):
        with self.lock:
            if self.phase in ("scanning", "large", "cleaning", "setup", "inventory"):
                return False, "当前任务尚未结束，请先停止或等待任务完成。"
            self.cancel.clear()
            # A preview ticket is valid only for the exact scan snapshot and
            # selection it was created from. Starting any new task revokes it.
            self.cleanup_preview = None
            self.phase = phase
            self.message = message
            self.progress = 0
            self.progress_max = 1
            if phase == "scanning":
                # Never show old candidate figures as results of a new scan.
                self.items = []
                self.targets = {}
                self.snapshots = {}
                self.scan_complete = False
            elif phase == "inventory":
                self.inventory = inspector.empty_report()
                self._classification_cache_source = None
                self._classification_cache = {}
            elif phase == "large":
                self.large_files = []
                self.large_info = {"source": "正在查询", "complete": False, "scanned_entries": 0}
            self.thread = threading.Thread(target=self._worker_wrapper, args=(worker,), daemon=True)
            self.thread.start()
        return True, "已开始"

    def _worker_wrapper(self, worker):
        try:
            worker()
        except Exception as exc:
            self._record(f"发生异常：{exc}")
            with self.lock:
                self.phase = "error"
                self.message = f"发生错误：{exc}"

    def start_everything_setup(self, confirmation):
        if confirmation != "INSTALL_OFFICIAL":
            return False, "必须明确确认下载并启动官方 Everything"
        return self._start("setup", "正在准备官方 Everything 与 ES CLI...", self._setup_everything)

    def _setup_everything(self):
        def progress(message):
            self._record(message)
            with self.lock:
                self.message = message[:260]
        try:
            installed = vendor.prepare(HERE, cancel=self.cancel, report=progress)
            if self.cancel.is_set():
                with self.lock:
                    self.phase = "idle"
                    self.message = "安装前已取消；没有启动第三方程序。"
                return
            self.es_exe = str(installed['es'])
            try:
                pid = vendor.launch(HERE)
                progress(f"已启动原版 Everything（PID {pid}）。如果索引尚未可用，请在 Everything 官方界面配置索引。")
            except (OSError, RuntimeError) as exc:
                progress(f"文件已核验并安装，但启动需要人工处理：{exc}")
            with self.lock:
                self.phase = "idle"
                self.progress = 1
                self.message = "Everything 已准备；可开始索引大文件查询。"
        except Exception as exc:
            with self.lock:
                self.phase = "error"
                self.message = "官方 Everything 准备失败：" + str(exc)[:170]
            self._record(self.message)

    def start_scan(self, mode="fast"):
        if mode not in ("fast", "complete"):
            return False, "不支持的扫描模式"
        return self._start("scanning", "正在读取安全缓存白名单...", lambda: self._scan(mode))

    def _scan(self, mode):
        targets = engine.make_targets()
        profiles = sorted(targets, key=lambda t: (RISK_ORDER.get(POLICY.get(t.group, ("gray",))[0], 9), t.name))
        disk = self._disk()
        max_seconds = 55 if mode == "fast" else 240
        max_entries = 90000 if mode == "fast" else 1000000
        deadline = time.monotonic() + max_seconds
        working = {}
        visible = []
        snapshots = {}
        processes = engine.active_processes()
        self._record(f"{mode} 扫描开始：{len(profiles)} 个已知缓存目标；期限 {max_seconds} 秒。")
        for number, target in enumerate(profiles):
            if self.cancel.is_set():
                break
            with self.lock:
                self.message = f"扫描 {number+1}/{len(profiles)}：{target.name}"
                self.progress = number
                self.progress_max = max(1, len(profiles))
            risk, note, why = POLICY.get(target.group, ("red", "未知", "未知目标不可删除"))
            age_days = engine.GROUPS[target.group][1]
            result, shots = safe_scan_target(target, age_days, self.cancel, deadline, max_entries)
            key = hashlib.sha256((target.group + "|" + str(target.path).casefold()).encode("utf-8")).hexdigest()[:24]
            process_blocked = bool(target.process_name and
                                   (processes is None or target.process_name.lower() in processes))
            priority = compute_priority(risk, result["bytes"], disk["free"], disk["total"])
            allowed = (risk in AUTOCLEAN_RISKS and result["complete"] and result["count"] > 0
                       and not process_blocked and not self.cancel.is_set())
            if process_blocked:
                result["state"] = "程序正在运行 / 进程检测不可用；禁用清理"
            visible.append({"id": key, "group": target.group, "name": target.name,
                            "path": str(target.path), "risk": risk, "risk_text": RISK_TEXT[risk],
                            "priority": priority, "size": result["bytes"], "count": result["count"],
                            "checked": result["checked"], "skipped": result["skipped"],
                            "errors": result["errors"], "complete": result["complete"],
                            "state": result["state"], "age_days": age_days,
                            "allowed": allowed, "note": note, "reason": why,
                            "process_blocked": process_blocked})
            working[key] = target
            snapshots[key] = shots
            with self.lock:
                self.items = list(visible)
        fully_scanned = (not self.cancel.is_set() and len(visible) == len(profiles)
                         and all(row["complete"] for row in visible))
        with self.lock:
            self.targets = working
            self.snapshots = snapshots
            self.scan_complete = fully_scanned
            self.progress = len(visible)
            self.progress_max = max(1, len(profiles))
            self.phase = "idle"
            self.message = ("快扫完成；已列出安全缓存候选，可按颜色筛选。" if fully_scanned else
                            "扫描被取消或达到限额：部分结果不完整；仅允许清理完整扫描且未被占用的项目。")
            # A cancelled scan is not used for deletion. For ordinary time-budget
            # truncation, individually completed targets remain eligible.
            if self.cancel.is_set():
                self.items = [dict(r, allowed=False) for r in self.items]
        self._record(self.message)
        self._auto_report("scan")

    def start_large(self, min_mb=512):
        try:
            size = int(min_mb)
        except (TypeError, ValueError):
            return False, "无效大文件门槛"
        if not 128 <= size <= 16384:
            return False, "门槛必须为 128 到 16384 MiB"
        return self._start("large", "查找 C 盘大文件（只读）...", lambda: self._large(size))

    def _large(self, min_mb):
        size_floor = min_mb * MIB
        result = None
        source = ""
        metadata = {"source": "", "complete": False, "scanned_entries": 0,
                    "min_mb": min_mb, "warning": ""}
        # Verify SHA-256 again immediately before launching the executable.
        # A previously verified path could have been replaced after startup.
        verified_now = vendor.local_cli_if_verified(HERE) if self.es_exe else None
        if self.es_exe and verified_now and os.path.normcase(str(verified_now)) == os.path.normcase(str(self.es_exe)):
            with self.lock:
                self.message = "尝试已核验的 Everything 官方索引查询..."
            result, source = list_large_everything(self.es_exe, size_floor, self.cancel)
            if result is not None:
                metadata["complete"] = not self.cancel.is_set()
                metadata["source"] = source
                metadata["scanned_entries"] = len(result)
                metadata["warning"] = "此列表由 Everything 的索引生成，仅覆盖它实际索引的路径。"
        if self.es_exe and not verified_now:
            source = "Everything ES CLI 文件已变化或校验失败：不会执行。"
            self.es_exe = None
        if result is None and not self.cancel.is_set():
            self._record((source or "没有已经通过校验的 Everything ES CLI") + "，使用有预算的 scandir 扫描。")
            with self.lock:
                self.message = "普通全盘扫描中（有时间/数量限制）..."
            root = Path("C:\\")
            if root.is_dir():
                result, detail = list_large_bounded(root, size_floor, self.cancel,
                                                     tick=self._large_tick)
                metadata.update(detail)
                metadata["source"] = "os.scandir 限时只读扫描"
                if not detail["complete"]:
                    metadata["warning"] = "结果不完整：达到扫描时间/条目上限或已取消，不能视为 C 盘全部大文件。"
            else:
                result = []
                metadata["source"] = "无法访问 C:"
                metadata["warning"] = "未找到本机 C:\\，此工具只适用于 Windows C 盘。"
        large = []
        for index, (path, size, mtime) in enumerate(result or []):
            risk, note = classify_large_file(path)
            large.append({"id": f"large-{index}", "path": path, "size": size,
                          "mtime": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d"),
                          "risk": risk, "risk_text": RISK_TEXT[risk], "priority": compute_priority(risk, size),
                          "reason": note, "action": "只读定位，不提供删除"})
        with self.lock:
            self.large_files = large
            self.large_info = metadata
            self.phase = "idle"
            self.message = f"大文件查找结束：{len(large)} 项；来源 {metadata['source']}。"
            self.progress = 1
            self.progress_max = 1
        self._record(self.message)
        self._auto_report("large")

    def _large_tick(self, count):
        with self.lock:
            self.message = f"已遍历 {count:,} 个文件/目录条目（只读）..."

    def stop(self):
        with self.lock:
            if self.phase not in ("scanning", "large", "cleaning", "setup"):
                return False, "当前没有正在执行的任务。"
            self.cancel.set()
            self.message = "正在停止：会在当前文件或查询结束后退出。"
            self._record("用户请求停止当前任务。")
            return True, "已请求停止"

    def _validated_jobs(self, target_ids, *, copy_snapshots=True):
        """Validate an entire selected allowlisted scan snapshot, under lock.

        No arbitrary paths from the browser are accepted. Returns (jobs, error).
        """
        if not isinstance(target_ids, list) or not 1 <= len(target_ids) <= 100:
            return None, "请选择至少一项、最多 100 项。"
        if any(not isinstance(key, str) for key in target_ids):
            return None, "清理项目 ID 格式无效。"
        if len(target_ids) != len(set(target_ids)):
            return None, "重复清理目标。"
        if self.phase in ("scanning", "large", "cleaning", "setup", "inventory"):
            return None, "当前有任务正在运行。"
        if not self.items:
            return None, "请先运行缓存扫描。"
        indexed = {row["id"]: row for row in self.items}
        jobs = []
        for key in target_ids:
            if key not in indexed or key not in self.targets:
                return None, "存在不属于本轮扫描的项目。"
            row = indexed[key]
            if not row["allowed"] or row["risk"] not in AUTOCLEAN_RISKS:
                return None, f"该项目不允许清理：{row['name']}"
            shots = self.snapshots.get(key, [])
            if len(shots) != row["count"] or not shots:
                return None, "文件清单与扫描计数不一致，请重新扫描。"
            # Caller holds the analyzer lock. Preview paging borrows the
            # immutable scan list for O(page-size) reads, while cleaning and
            # ticket creation still capture their own independent copies.
            jobs.append((key, self.targets[key],
                         list(shots) if copy_snapshots else shots, row["age_days"]))
        return jobs, None

    def preview_clean(self, target_ids):
        """Read-only preflight: list exact authorized categories and samples.

        Issues an ephemeral, single-use ticket for the exact list of IDs. The
        later deletion STILL re-checks every file's original snapshot metadata.
        """
        with self.lock:
            jobs, error = self._validated_jobs(target_ids)
            if error:
                self.cleanup_preview = None
                return False, error, None
            indexed = {row["id"]: row for row in self.items}
            rows = []
            samples = []
            for key, _target, shots, days in jobs:
                row = indexed[key]
                rows.append({"name": row["name"], "risk": row["risk"],
                             "priority": row["priority"], "path": row["path"],
                             "files": len(shots), "bytes": sum(item.size for item in shots),
                             "age_days": days})
                # Samples only; no promises that any file will be deleted.
                for shot in shots[:2]:
                    if len(samples) < 12:
                        samples.append(shot.path)
            ticket = secrets.token_urlsafe(24)
            # Ticket binds to the entire file list, not merely the category
            # IDs/counts. Frozen Snapshot entries cannot be changed by a
            # later same-count list edit or stale browser tab.
            frozen_jobs = tuple(
                (key, target, tuple(shots), days)
                for key, target, shots, days in jobs)
            self.cleanup_preview = {"ticket": ticket, "ids": tuple(target_ids),
                                    "jobs": frozen_jobs,
                                    "expires": time.monotonic() + CLEAN_PREVIEW_TTL}
            self._record(f"用户请求只读删除预览：{len(jobs)} 类，共 {sum(len(j[2]) for j in jobs)} 个缓存文件。")
            return True, "已生成预览。不会删除文件。", {
                "ticket": ticket, "expires_in_seconds": CLEAN_PREVIEW_TTL,
                "categories": rows,
                "total_files": sum(row["files"] for row in rows),
                "total_bytes": sum(row["bytes"] for row in rows),
                "sample_paths": samples,
                "warning": "预览仅基于上次扫描快照。删除前仍会逐文件复核；跳过变更或受保护的文件。操作不经过回收站，不能撤销。",
            }

    def preview_files(self, ticket, offset=0, limit=50):
        """Read-only, bounded pagination over the *exact* selected scan snapshots.

        A client cannot supply file paths or read any other target. Pagination
        does not renew the ticket; cancellation, expiration, rescan and cleaning
        invalidate it. The underlying snapshots remain immutable while idle.
        """
        with self.lock:
            pending = self.cleanup_preview
            if (not pending or not isinstance(ticket, str) or not ticket or
                    not secrets.compare_digest(ticket, pending["ticket"]) or
                    time.monotonic() >= pending["expires"]):
                if pending and time.monotonic() >= pending["expires"]:
                    self.cleanup_preview = None
                return False, "预览凭证无效或已过期。请重新生成预览。", None
            if (type(offset) is not int or type(limit) is not int or
                    offset < 0 or not 1 <= limit <= 100):
                return False, "分页参数无效：offset 必须非负，limit 不得超过 100。", None
            # Never copy all N snapshots for each page. Validate the current
            # allowlist/counts without copying, then page the frozen ticket.
            live_jobs, error = self._validated_jobs(
                list(pending["ids"]), copy_snapshots=False)
            if error:
                self.cleanup_preview = None
                return False, error, None
            jobs = pending["jobs"]
            if (len(live_jobs) != len(jobs) or any(
                    current[0] != frozen[0] or current[1] != frozen[1] or
                    current[3] != frozen[3] or len(current[2]) != len(frozen[2])
                    for current, frozen in zip(live_jobs, jobs))):
                self.cleanup_preview = None
                return False, "预览后扫描快照已变更，请重新扫描并预览。", None
            total = sum(len(shots) for _id, _target, shots, _age in jobs)
            if offset > total:
                return False, "分页位置超出本次预览范围。", None
            files = []
            position = 0
            for (key, target, shots, age_days), (_, _, live_shots, _) in zip(jobs, live_jobs):
                end = position + len(shots)
                if end <= offset:
                    position = end
                    continue
                if position >= offset + limit:
                    break
                lo = max(0, offset - position)
                hi = min(len(shots), offset + limit - position)
                for index in range(lo, hi):
                    shot = shots[index]
                    if live_shots[index] != shot:
                        # A same-count edit must never make a newly inserted
                        # path visible under an older preview ticket.
                        self.cleanup_preview = None
                        return False, "预览文件已变化；旧凭证已失效。", None
                    try:
                        modified = datetime.fromtimestamp(shot.mtime_ns / 1_000_000_000).strftime("%Y-%m-%d")
                    except (OverflowError, ValueError, OSError):
                        modified = "未知"
                    files.append({"number": position + index + 1,
                                  "category": target.name,
                                  "path": shot.path,
                                  "bytes": shot.size,
                                  "modified": modified,
                                  "age_days": age_days})
                position = end
            next_offset = offset + len(files)
            return True, "仅返回当前预览中的文件快照，未进行删除。", {
                "offset": offset, "limit": limit, "total": total, "files": files,
                "next_offset": next_offset if next_offset < total else None,
                "expires_in_seconds": max(0, int(pending["expires"] - time.monotonic())),
                "warning": "文件路径和大小来自扫描时的快照。执行删除之前仍将逐文件重新核验。",
            }

    def discard_preview(self, ticket=None):
        """Revoke only the named pending ticket; stale tabs must not revoke new previews."""
        with self.lock:
            pending = self.cleanup_preview
            if ticket is not None and (not pending or not isinstance(ticket, str) or
                    not secrets.compare_digest(ticket, pending["ticket"])):
                return False, "预览已更换或过期；旧页面不能撤销新预览。"
            self.cleanup_preview = None
        return True, "预览授权已撤销；文件没有删除。"

    def start_clean(self, target_ids, confirmation, ticket=None):
        if confirmation != "DELETE":
            return False, "必须明确输入 DELETE 才能执行删除。"
        with self.lock:
            jobs, error = self._validated_jobs(target_ids)
            if error:
                self.cleanup_preview = None
                return False, error
            pending = self.cleanup_preview
            if (not pending or not isinstance(ticket, str) or not ticket or
                    not secrets.compare_digest(ticket, pending["ticket"]) or
                    tuple(target_ids) != pending["ids"] or
                    time.monotonic() >= pending["expires"]):
                return False, "请先预览本轮准确的清理清单；预览已过期或项目变化时必须重新预览。"
            # The final authorization must bind to every immutable snapshot,
            # including the file path, size and original mtime_ns. A list
            # mutated in-place with the same number of entries is NOT safe.
            frozen_jobs = pending["jobs"]
            if (len(jobs) != len(frozen_jobs) or any(
                    key != saved_key or target != saved_target or
                    days != saved_days or len(shots) != len(saved_shots) or
                    any(current != saved for current, saved
                        in zip(shots, saved_shots))
                    for (key, target, shots, days),
                        (saved_key, saved_target, saved_shots, saved_days)
                    in zip(jobs, frozen_jobs))):
                self.cleanup_preview = None
                return False, "本轮预览后的文件清单已变更，请重新扫描；没有执行清理。"
            # Single-use even when the worker later errors or is cancelled.
            self.cleanup_preview = None
            self.cancel.clear()
            self.phase = "cleaning"
            self.message = "准备删除已预览、明确确认且未变化的缓存文件..."
            self.progress = 0
            self.progress_max = len(jobs)
            self.thread = threading.Thread(target=self._worker_wrapper,
                                           args=(lambda: self._clean(jobs),), daemon=True)
            self.thread.start()
        return True, "已开始按预览清单清理"

    def _clean(self, jobs):
        before_disk = self._disk()  # best-effort measurement, not a guarantee
        start_time = time.monotonic()
        running = engine.active_processes()
        result_rows = []
        for index, (key, target, snapshots, age_days) in enumerate(jobs):
            if self.cancel.is_set():
                break
            with self.lock:
                self.message = f"清理 {index+1}/{len(jobs)}：{target.name}"
                self.progress = index
            result = clean_snapshot_target(target, snapshots, age_days, self.cancel, running)
            result_rows.append({"name": target.name, "path": str(target.path),
                                "risk": POLICY[target.group][0], **result})
        totals = {"deleted": sum(x["deleted"] for x in result_rows),
                  "bytes": sum(x["bytes"] for x in result_rows),
                  "errors": sum(x["errors"] for x in result_rows),
                  "skipped": sum(x["skipped"] for x in result_rows)}
        after_disk = self._disk()
        measurement_ok = bool(before_disk.get("total") and after_disk.get("total") and
                              before_disk["total"] == after_disk["total"])
        disk_comparison = {
            "available": measurement_ok,
            "before_free": before_disk["free"] if measurement_ok else None,
            "after_free": after_disk["free"] if measurement_ok else None,
            "net_free_change": (after_disk["free"] - before_disk["free"]) if measurement_ok else None,
            "duration_seconds": round(max(0, time.monotonic() - start_time), 2),
            "disclaimer": "C 盘净空闲空间变化包含同期其他程序的读写，不等同于本工具独占释放量。",
        }
        with self.lock:
            self.last_cleanup = {"at": datetime.now().isoformat(timespec="seconds"),
                                 "items": result_rows, "totals": totals,
                                 "disk_comparison": disk_comparison,
                                 "aborted": self.cancel.is_set()}
            self.phase = "idle"
            self.scan_complete = False
            self.items = [dict(x, allowed=False, state="清理后结果已过期，请重新扫描") for x in self.items]
            self.progress = len(result_rows)
            self.message = f"已删除 {totals['deleted']} 个缓存文件，约 {format_bytes(totals['bytes'])}；建议重新扫描。"
        self._record(self.message)
        self._auto_report("clean")

    def reveal(self, category, key):
        with self.lock:
            if category == "cache":
                item = next((x for x in self.items if x["id"] == key), None)
            elif category == "large":
                item = next((x for x in self.large_files if x["id"] == key), None)
            else:
                item = None
        if not item:
            return False, "无效的文件项目。"
        path = Path(item["path"])
        if not engine.is_c_drive(path):
            return False, "仅允许打开 C 盘中已验证过的扫描结果。"
        try:
            if category == "large" and path.is_file():
                subprocess.Popen(["explorer.exe", "/select,", str(path)],
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            else:
                folder = path if path.is_dir() else path.parent
                if not folder.exists():
                    return False, "文件夹不存在或已被清理。"
                subprocess.Popen(["explorer.exe", str(folder)],
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return True, "已请求资源管理器打开位置。"
        except OSError as exc:
            return False, str(exc)

    def report(self):
        state = self.state()
        return {"product": "C-Scan Studio", "version": VERSION,
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "disk": state["disk"], "scan_complete": state["scan_complete"],
                "summary": self.summary(), "cache_items": state["items"],
                "large_files": state["large_files"], "large_info": state["large_info"],
                "advisories": ADVISORIES, "cleanup": state["last_cleanup"],
                "inventory": self.inventory,
                "warnings": ["所有空间数值是逻辑大小，不保证等于磁盘实际释放量。",
                             "不完整/取消扫描的结果不代表 C 盘全量数据。",
                             "大文件列表仅定位，绝不提供删除操作。",
                             "跨盘智能分类只根据文件扩展名/文件名推断，未自动解析文件内容。",
                             "重复文件只读检测，无自动删除；报告可能含本机路径，请自行妥善保管。"]}

    def summary(self):
        with self.lock:
            ready = [x for x in self.items if x["allowed"]]
            green = [x for x in ready if x["risk"] == "green"]
            return {"recommended_bytes": sum(x["size"] for x in green),
                    "optional_bytes": sum(x["size"] for x in ready if x["risk"] == "amber"),
                    "recommended_count": len(green), "optional_count": len(ready) - len(green),
                    "candidate_files": sum(x["count"] for x in self.items),
                    "categories": len(self.items)}

    def _auto_report(self, reason):
        try:
            report_dir = engine.report_directory()
            report_dir.mkdir(parents=True, exist_ok=True)
            filename = f"cscan_v3_{reason}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filename_path = report_dir / filename
            with filename_path.open("w", encoding="utf-8") as f:
                json.dump(self.report(), f, ensure_ascii=False, indent=2)
            with self.lock:
                self.latest_export = str(filename_path)
        except OSError as exc:
            self._record(f"报告写入失败：{exc}")


def json_bytes(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def csv_bytes(report):
    # Prefix formula-looking values to prevent CSV/Excel formula execution.
    def spreadsheet_safe(value):
        if isinstance(value, str) and value and value[0] in "=+-@\t\r\n":
            return "'" + value
        return value

    buffer = io.StringIO(newline="")
    out = csv.writer(buffer)
    def row(values):
        out.writerow([spreadsheet_safe(x) for x in values])
    row(("项目", "优先级", "风险颜色", "逻辑字节", "候选文件", "完整扫描", "可在界面清理", "路径", "说明"))
    for rec in report["cache_items"]:
        row((rec["name"], rec["priority"], RISK_TEXT[rec["risk"]], rec["size"],
                      rec["count"], "是" if rec["complete"] else "否",
                      "是" if rec["allowed"] else "否", rec["path"], rec["reason"]))
    row([])
    row(("大文件（仅查看，不提供删除）", "优先级", "风险颜色", "逻辑字节", "修改时间", "文件路径", "说明"))
    for rec in report["large_files"]:
        row(("大文件", rec["priority"], RISK_TEXT[rec["risk"]], rec["size"], rec["mtime"],
                      rec["path"], rec["reason"]))
    inventory = report.get("inventory") or {}
    row([])
    row(("其他盘文件分类（只读）", "数量", "逻辑字节", "置信度来自扩展名/名称", "示例路径"))
    for item in inventory.get("categories", []):
        row((item["label"], item["count"], item["bytes"],
             "扩展名规则，不是文件内容识别", "样本见下方完整分类清单"))
    row([])
    row(("其他盘分类明细（只读）", "类别 ID", "逻辑字节", "修改日期", "置信度", "完整路径", "分类依据"))
    for item in inventory.get("classified_files", []):
        row((inspector.CAT_LABELS[item["category"]], item["category"], item["size"],
             item["mtime"], item["confidence"], item["path"], item["reason"]))
    row([])
    row(("其他盘 SHA-256 重复文件（手工复核，不自动删除）", "角色", "逻辑字节", "SHA-256", "风险", "文件完整路径", "建议"))
    for group in inventory.get("duplicate_groups", []):
        row((group["id"], "建议优先保留候选原件", group["size"], group["sha256"],
             "保护", group["keeper"]["path"], group["keeper"]["reason"]))
        for copy in group["copies"]:
            row((group["id"], "仅供人工复核的重复文件", group["size"], group["sha256"],
                 copy["risk"], copy["path"], copy["suggestion"]))
    return ("\ufeff" + buffer.getvalue()).encode("utf-8")


class LocalHandler(BaseHTTPRequestHandler):
    server_version = "CScanLocal/3.6"

    def log_message(self, fmt, *args):
        # Avoid leaking the random token into logs.
        return

    def _headers(self, status=200, kind="application/json; charset=utf-8", length=0, attachment=None):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; "
                         "script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.end_headers()

    def _answer(self, status, data):
        body = json_bytes(data)
        self._headers(status, length=len(body))
        self.wfile.write(body)

    def _authorized(self, parsed, require_header=False):
        if self.headers.get("Host", "") != f"127.0.0.1:{self.server.server_port}":
            return False
        if require_header:
            if not secrets.compare_digest(self.headers.get("X-CSCAN-Token", ""), self.server.session_token):
                return False
            origin = self.headers.get("Origin", "")
            if origin != f"http://127.0.0.1:{self.server.server_port}":
                return False
            if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
                return False
        else:
            supplied = urllib.parse.parse_qs(parsed.query).get("t", [""])[0]
            if not secrets.compare_digest(supplied, self.server.session_token):
                return False
        return True

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if not self._authorized(parsed):
            return self._answer(403, {"error": "访问被拒绝：需要本机随机会话密钥。"})
        if parsed.path == "/":
            page = (HERE / "ui" / "dashboard.html").read_bytes()
            self._headers(200, "text/html; charset=utf-8", len(page))
            self.wfile.write(page)
        elif parsed.path == "/api/state":
            state = self.server.analyzer.state()
            state["toolbox"] = self.server.toolbox.state()
            self._answer(200, state)
        elif parsed.path == "/api/toolbox/export":
            payload = json.dumps(self.server.toolbox.state(), ensure_ascii=False, indent=2).encode("utf-8")
            self._headers(200, "application/json; charset=utf-8", len(payload),
                          "CScan_Toolbox_Local_Report.json")
            self.wfile.write(payload)
        elif parsed.path in ("/api/security", "/api/security/export"):
            # On-demand local hashes only. Nothing is uploaded and no AV verdict is claimed.
            report = security_audit.audit(HERE)
            payload = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
            attachment = "CScan_Local_Integrity_Report.json" if parsed.path.endswith("/export") else None
            self._headers(200, "application/json; charset=utf-8", len(payload), attachment)
            self.wfile.write(payload)
        elif parsed.path == "/api/export":
            report = self.server.analyzer.report()
            csv_mode = urllib.parse.parse_qs(parsed.query).get("type", ["json"])[0] == "csv"
            if csv_mode:
                body, mimetype, suffix = csv_bytes(report), "text/csv; charset=utf-8", "csv"
            else:
                body, mimetype, suffix = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"), "application/json; charset=utf-8", "json"
            self._headers(200, mimetype, len(body), f"CScan_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.{suffix}")
            self.wfile.write(body)
        else:
            self._answer(404, {"error": "找不到页面"})

    def _discard_small_rejected_post_body(self):
        """Bounded drain prevents WinSock TCP reset on a rejected POST.

        Closing a socket while its small request body remains unread can
        produce WinError 10053 instead of the intended HTTP 403 on Windows.
        Never parse an unauthorized body or wait unboundedly for its bytes.
        """
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 0 or size > MAX_JSON:
                return
            if size:
                previous = self.connection.gettimeout()
                self.connection.settimeout(0.5)
                try:
                    self.rfile.read(size)
                finally:
                    self.connection.settimeout(previous)
        except (ValueError, OSError):
            pass

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        if not self._authorized(parsed, require_header=True):
            self._discard_small_rejected_post_body()
            return self._answer(403, {"error": "拒绝不可信来源的修改请求"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 0 or size > MAX_JSON:
                return self._answer(413, {"error": "请求过大"})
            body = json.loads(self.rfile.read(size) or b"{}")
            if not isinstance(body, dict):
                return self._answer(400, {"error": "JSON 对象必须有效"})
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return self._answer(400, {"error": "JSON 无效"})
        manager = self.server.analyzer
        if parsed.path == "/api/scan":
            ok, msg = manager.start_scan(body.get("mode", "fast"))
        elif parsed.path == "/api/large":
            ok, msg = manager.start_large(body.get("min_mb", 512))
        elif parsed.path == "/api/inspect":
            ok, msg = manager.start_inspection(body.get("drives", []), body.get("min_kb", 64))
        elif parsed.path == "/api/inspect-refresh":
            manager.refresh_drives()
            ok, msg = True, "已重新读取本机可选盘符。"
        elif parsed.path == "/api/inspect-files":
            ok, msg, page = manager.classified_files_page(
                body.get('category'), body.get('offset', 0), body.get('limit', 50),
                body.get('subtype'), body.get('drive'))
            return self._answer(200 if ok else 409, {
                'ok': ok, 'message': msg, 'page': page if ok else None})
        elif parsed.path == "/api/everything":
            ok, msg = manager.start_everything_setup(body.get("confirm", ""))
        elif parsed.path == "/api/stop":
            ok, msg = manager.stop()
        elif parsed.path == "/api/preview-clean":
            ok, msg, preview = manager.preview_clean(body.get("ids", []))
            return self._answer(200 if ok else 409, {"ok": ok, "message": msg,
                                                     "preview": preview if ok else None})
        elif parsed.path == "/api/preview-files":
            ok, msg, page = manager.preview_files(body.get("ticket"),
                                                   body.get("offset", 0), body.get("limit", 50))
            return self._answer(200 if ok else 409, {"ok": ok, "message": msg,
                                                     "page": page if ok else None})
        elif parsed.path == "/api/cancel-preview":
            ok, msg = manager.discard_preview(body.get("ticket"))
        elif parsed.path == "/api/clean":
            ok, msg = manager.start_clean(body.get("ids", []), body.get("confirm", ""),
                                          body.get("ticket"))
        elif parsed.path == "/api/reveal":
            ok, msg = manager.reveal(body.get("type", ""), body.get("id", ""))
        elif parsed.path == "/api/tool-action":
            if manager.phase in ("scanning", "large", "cleaning", "setup", "inventory"):
                ok, msg = False, "扫描、查重或清理期间不能启动其他系统工具。"
            else:
                ok, msg = self.server.toolbox.start(body.get("action"), body.get("confirm"))
        else:
            return self._answer(404, {"error": "没有对应的操作"})
        self._answer(200 if ok else 409, {"ok": ok, "message": msg})


def main(argv=None):
    if os.name != "nt":
        print("C-Scan Studio 仅可在 Windows 上运行；Linux 测试不会对任何磁盘执行清理。")
        return 2
    path = HERE / "ui" / "dashboard.html"
    if not path.exists():
        print(f"缺少界面文件：{path}")
        return 2
    token = secrets.token_urlsafe(32)
    analyzer = Analyzer()
    http = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    http.daemon_threads = True
    http.session_token = token
    http.analyzer = analyzer
    http.toolbox = Toolbox(log=analyzer._record)
    url = f"http://127.0.0.1:{http.server_port}/?t={token}"
    print("=" * 70)
    print("C-Scan Studio v3.5.2-beta.1 - Windows 本地多磁盘智能分析器")
    print("只在本机 127.0.0.1 监听，默认仅读取数据。")
    print("请勿公开包含随机会话密钥的地址。"); print(url)
    print("退出方式：关闭此 BAT 控制台窗口或按 Ctrl+C。")
    print("=" * 70)
    try:
        opened = webbrowser.open(url, new=2)
        if not opened:
            print("浏览器没有自动打开。请复制上面网址到本机浏览器。")
    except Exception as exc:
        print(f"浏览器启动失败：{exc}。请手动打开上面地址。")
    try:
        http.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("本地服务已停止。")
    finally:
        http.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
