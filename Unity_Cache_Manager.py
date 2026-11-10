#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unity cache locations and bounded, read-only Windows diagnostics.

Custom configuration NEVER extends the cleanup allowlist. ``cleanup_specs``
contains only fixed, documented cache folders; the Studio owns confirmation,
process checks, snapshots, and deletion. This module never deletes anything.
"""
from __future__ import annotations

import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import stat
import time


WINDOWS = os.name == "nt"
REPARSE = 0x0400
MAX_CONFIG_BYTES = 64 * 1024
MAX_AUDIT_ENTRIES = 250000
MAX_LOCATION_ENTRIES = 100000

UNITY_PROCESSES = (
    "unity.exe", "unity hub.exe", "unitypackagemanager.exe",
    "unityshadercompiler.exe", "bee_backend.exe", "bee.exe",
    "unitycrashhandler64.exe", "unitycrashhandler32.exe",
)
UNITY_GROUPS = {
    "unity-upm": ("Unity Package Manager 下载/解包缓存", 0),
    "unity-gi": ("Unity GI 全局光照缓存", 0),
    "unity-logs": ("Unity 14 天以上的编辑器/包管理器日志", 14),
}
OFFLINE_GROUPS = frozenset(("unity-upm",))
UNITY_POLICY = {
    "unity-upm": (
        "amber", "可重新下载的 UPM 全局缓存；保留离线能力时不清理",
        "清理后 Unity 可能重新下载并解包；旧项目或离线项目可能无法恢复依赖。"
        "确认联网且包仍可获得，再关闭 Unity/Hub 并逐项预览。",
    ),
    "unity-gi": (
        "amber", "GI 烘焙中间缓存；优先在 Unity 中限制大小或改址",
        "Unity 官方建议将清空作为最后手段。清理后下次烘焙可能明显变慢；"
        "必须关闭相关编辑器与构建进程，不包括项目中的光照贴图。",
    ),
    "unity-logs": (
        "green", "仅 Editor.log、Editor-prev.log、upm.log、upm-prev.log，且至少 14 天",
        "日志可能用于排查旧崩溃；需要诊断时先保留。精确匹配文件名，"
        "不递归清空 Editor 目录，也不触碰许可证、项目或设置。",
    ),
}
EDITOR_LOG_NAMES = ("Editor.log", "Editor-prev.log", "upm.log", "upm-prev.log")

SOURCES = {
    "upm": "https://docs.unity.com/en-us/engine/6000.0/manual/packages-list/package-manager-caches/upm-config-cache",
    "upm_legacy": "https://docs.unity3d.com/2022.3/Documentation/Manual/upm-config-cache.html",
    "asset_store": "https://docs.unity.com/en-us/engine/6000.0/manual/packages-list/package-manager-caches/upm-config-cache-as",
    "gi": "https://docs.unity.com/en-us/engine/6000.0/manual/unity-editor/editor-settings-reference/preferences/gi-cache",
    "bee": "https://docs.unity.com/en-us/engine/6000.0/manual/building-and-publishing/build-cache-location-reference",
    "gradle": "https://docs.gradle.org/current/userguide/directory_layout.html",
}


def cleanup_specs(profile, local, roaming=None):
    """Return fixed locations, not environment-controlled deletion roots.

    The caller must supply its independently validated canonical Windows roots
    and apply its normal Target.valid() checks. ``roaming`` may be unavailable.
    """
    if profile is None or local is None:
        return []
    profile, local = Path(profile), Path(local)
    cache = local / "Unity" / "cache"
    low = profile / "AppData" / "LocalLow"
    entries = [
        ("unity-upm", "Unity 6 UPM 全局缓存", cache / "upm", local, ()),
        ("unity-upm", "Unity 旧版 UPM npm 缓存", cache / "npm", local, ()),
        ("unity-upm", "Unity 旧版 UPM packages 缓存", cache / "packages", local, ()),
        ("unity-upm", "Unity UPM Git LFS 缓存", cache / "git-lfs", local, ()),
        ("unity-gi", "Unity GI 全局光照缓存", low / "Unity" / "Caches" / "GiCache", low, ()),
        ("unity-logs", "Unity 旧编辑器/包管理器日志", local / "Unity" / "Editor", local, EDITOR_LOG_NAMES),
    ]
    return [dict(group=group, name=name, path=path, boundary=boundary,
                 process_names=UNITY_PROCESSES, file_names=names)
            for group, name, path, boundary, names in entries]


def _key(path):
    return ntpath.normcase(ntpath.normpath(str(path)))


def _validated_path(raw, profile=None):
    """Validate a *read-only* configured local Windows location.

    No expansion, shell evaluation, UNC/device namespace, ADS, traversal, drive
    root or broad profile/system root. Returned text remains a lexical path.
    """
    if not isinstance(raw, str) or not raw or len(raw) > 32700:
        return None, "路径为空、类型无效或过长"
    if raw != raw.strip() or any(ord(c) < 32 for c in raw):
        return None, "路径含外层空白或控制字符"
    if re.search(r"%[^%]+%", raw) or raw.startswith("~"):
        return None, "未展开的环境变量/用户缩写；请在 Unity 设置中核实"
    drive, rest = ntpath.splitdrive(raw.replace("/", "\\"))
    if not re.fullmatch(r"[A-Za-z]:", drive) or not rest.startswith("\\"):
        return None, "只诊断本地磁盘的绝对路径；不访问网络、设备或相对路径"
    parts = [p for p in rest.split("\\") if p]
    if not parts or any(p in (".", "..") for p in parts):
        return None, "不扫描磁盘根目录或含父级跳转的路径"
    if any(c in rest for c in ':*?"<>|') or any(p.endswith((".", " ")) for p in parts):
        return None, "路径含特殊命名、通配符或备用数据流"
    normalized = ntpath.normpath(raw)
    blocked = {"windows", "winnt", "recovery", "boot", "$recycle.bin", "system volume information"}
    if parts[0].casefold() in blocked:
        return None, "系统目录不作为 Unity 缓存诊断目标"
    if len(parts) == 1 and parts[0].casefold() in {
            "users", "programdata", "program files", "program files (x86)", "documents and settings"}:
        return None, "不扫描整个用户目录、程序目录或系统数据目录"
    if profile:
        broad = [profile, ntpath.join(profile, "AppData"),
                 ntpath.join(profile, "AppData", "Local"),
                 ntpath.join(profile, "AppData", "LocalLow"),
                 ntpath.join(profile, "AppData", "Roaming"),
                 ntpath.join(profile, "Documents"), ntpath.join(profile, "Desktop"),
                 ntpath.join(profile, "Downloads")]
        if _key(normalized) in {_key(p) for p in broad}:
            return None, "不将整个用户资料或 AppData 根目录视为缓存"
    return normalized, ""


def _profile_path(environ):
    raw = environ.get("USERPROFILE", "")
    value, error = _validated_path(raw)
    if value is None:
        return None, error
    parts = [p for p in ntpath.splitdrive(value)[1].split("\\") if p]
    if len(parts) < 2 or parts[0].casefold() in {
            "programdata", "program files", "program files (x86)"}:
        return None, "USERPROFILE 不是具体的用户资料目录"
    return value, ""


def _links_clear(path):
    """lstat all ancestors; never resolve or traverse junctions/symlinks."""
    current = Path(path)
    while True:
        try:
            info = os.lstat(current)
        except (FileNotFoundError, NotADirectoryError):
            pass
        except OSError:
            return False
        else:
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE:
                return False
        if current.parent == current:
            return True
        current = current.parent


def _identity(info):
    return int(getattr(info, "st_dev", 0)), int(getattr(info, "st_ino", 0))


def measure_directory(root, stop=None, deadline=None, max_entries=MAX_LOCATION_ENTRIES,
                      seen_files=None, file_names=()):
    """Bounded metadata walk, also used by isolated temporary-tree tests.

    ``bytes`` is the sum of logical sizes of unique regular files. It is not
    disk allocation or a promise of reclaimable space. No file data is read.
    """
    root = Path(root)
    deadline = time.monotonic() + 25 if deadline is None else deadline
    seen_files = set() if seen_files is None else seen_files
    allowed_names = {name.casefold() for name in file_names}
    report = dict(bytes=0, count=0, checked=0, errors=0, skipped=0,
                  duplicate_files=0, complete=True, exists=False, state="未找到")
    try:
        root_info = os.lstat(root)
    except (FileNotFoundError, NotADirectoryError):
        return report
    except OSError:
        report.update(exists=None, complete=False, errors=1, state="无法读取目录信息；是否存在尚未确认")
        return report
    report["exists"] = True
    if not _links_clear(root) or not stat.S_ISDIR(root_info.st_mode):
        report.update(complete=False, skipped=1, state="链接、重解析点或非目录：已跳过")
        return report
    directories = [(root, _identity(root_info))]
    visited = set()
    while directories:
        if stop is not None and stop.is_set():
            report.update(complete=False, state="已取消；仅显示已读取部分")
            return report
        if time.monotonic() >= deadline or report["checked"] >= max(0, int(max_entries)):
            report.update(complete=False, state="达到扫描时间/条目限额；仅显示已读取部分")
            return report
        folder, expected_identity = directories.pop()
        try:
            current = os.lstat(folder)
            if (not stat.S_ISDIR(current.st_mode) or not _links_clear(folder) or
                    _identity(current) != expected_identity):
                report["skipped"] += 1
                report["complete"] = False
                continue
            folder_key = _key(folder)
            if folder_key in visited:
                report["skipped"] += 1
                report["complete"] = False
                continue
            visited.add(folder_key)
            with os.scandir(folder) as entries:
                for entry in entries:
                    if ((stop is not None and stop.is_set()) or time.monotonic() >= deadline or
                            report["checked"] >= max(0, int(max_entries))):
                        report.update(complete=False, state="已取消/达到限额；仅显示已读取部分")
                        return report
                    report["checked"] += 1
                    try:
                        # DirEntry.stat() has zero device/inode fields on
                        # Windows. A fresh lstat is required both for queued
                        # directory identities and hardlink/overlap accounting.
                        # It also avoids trusting cached enumeration metadata.
                        info = os.lstat(entry.path)
                        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE:
                            report["skipped"] += 1
                            report["complete"] = False
                        elif stat.S_ISDIR(info.st_mode):
                            if not allowed_names:
                                directories.append((Path(entry.path), _identity(info)))
                        elif stat.S_ISREG(info.st_mode):
                            if allowed_names and entry.name.casefold() not in allowed_names:
                                continue
                            identity = _identity(info)
                            unique = ("inode", *identity) if identity[1] else ("path", _key(entry.path))
                            if unique in seen_files:
                                report["duplicate_files"] += 1
                                continue
                            seen_files.add(unique)
                            report["count"] += 1
                            report["bytes"] += max(0, int(info.st_size))
                        else:
                            report["skipped"] += 1
                            report["complete"] = False
                    except OSError:
                        report["errors"] += 1
                        report["complete"] = False
        except OSError:
            report["errors"] += 1
            report["complete"] = False
    report["state"] = "完成" if report["complete"] else "部分目录不可读、变化或链接已跳过；结果不完整"
    if report["duplicate_files"]:
        report["state"] += "；部分文件已计入其他位置或同一硬链接，此处为去重后的新增量"
    return report


def read_upm_cache_root(profile):
    """Read only root-level cacheRoot, never return config text or credentials.

    We accept the simple quoted-string form used by Unity's documented examples.
    Unsupported TOML is reported as unverified instead of being guessed.
    """
    config = Path(profile) / ".upmconfig.toml"
    result = {"name": "cacheRoot", "value": "", "source": str(config),
              "valid": False, "note": "未找到用户 UPM 配置；未读取系统注册表"}
    if not _links_clear(config):
        result["note"] = "用户 UPM 配置为链接/不可安全读取，已跳过"
        return result
    try:
        info = os.lstat(config)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONFIG_BYTES:
            result["note"] = "用户 UPM 配置不是普通小文件，已跳过"
            return result
        with open(config, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (_identity(opened) != _identity(info) or not stat.S_ISREG(opened.st_mode) or
                    opened.st_size > MAX_CONFIG_BYTES or not _links_clear(config)):
                result["note"] = "用户 UPM 配置在读取前发生变化，已跳过"
                return result
            data = handle.read(MAX_CONFIG_BYTES + 1)
        if len(data) > MAX_CONFIG_BYTES:
            result["note"] = "用户 UPM 配置超过读取上限，已跳过"
            return result
        text = data.decode("utf-8-sig")
    except FileNotFoundError:
        return result
    except (OSError, UnicodeError):
        result["note"] = "无法安全读取用户 UPM 配置"
        return result
    in_root = True
    found = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            in_root = False
        match = re.fullmatch(r"cacheRoot\s*=\s*(.*)", line) if in_root else None
        if not match:
            continue
        if found:
            result.update(value="", valid=False, note="cacheRoot 重复，配置未验证")
            return result
        found = True
        literal = match.group(1)
        try:
            if literal.startswith('"'):
                value, end = json.JSONDecoder().raw_decode(literal)
                trailing = literal[end:].strip()
            elif literal.startswith("'"):
                end = literal.index("'", 1)
                value, trailing = literal[1:end], literal[end + 1:].strip()
            else:
                raise ValueError("unsupported form")
            if trailing and not trailing.startswith("#"):
                raise ValueError("unsupported trailing text")
            normalized, error = _validated_path(value, profile)
            result.update(value=value if isinstance(value, str) else "", valid=normalized is not None,
                          note=error or "用户配置根级 cacheRoot；进程 UPM_CACHE_ROOT 的优先级更高")
        except (ValueError, TypeError):
            result.update(value="", valid=False, note="cacheRoot 不是受支持的单行路径字符串；请在 Unity 中核实")
    if not found:
        result["note"] = "用户配置未包含根级 cacheRoot；其他配置键未输出"
    return result


def _guidance():
    return [
        {"title": "为何 Unity 在 D 盘，C 盘仍增长", "text": "编辑器安装、项目目录和用户级缓存有独立位置。只清理 D 盘工程的 Library 不会增加 C 盘空间。",
         "steps": ["先比较下方 C 盘与其他盘的缓存大小。", "先清旧日志，再按需求处理包缓存和光照缓存。"], "url": SOURCES["upm"]},
        {"title": "把后续 UPM 缓存放到 D 盘", "text": "建议在 Unity Preferences 的 Package Manager 缓存设置中选择专用目录，例如 D:\\UnityCache\\UPM；也可使用官方 UPM_CACHE_ROOT。",
         "steps": ["先关闭所有 Unity 编辑器和 Hub。", "修改支持的缓存设置后，重新启动 Hub 与编辑器，验证项目可正常打开。", "修改位置不会自动搬走或清理旧缓存；验证后再预览旧位置的清理清单。"], "url": SOURCES["upm"]},
        {"title": "光照缓存先限额，再改址", "text": "Preferences → GI Cache 可调整最大容量和自定义路径。外部清理只是最后手段。",
         "steps": ["选用 D:\\UnityCache\\GI 等独立缓存目录。", "项目已有的光照贴图与全局 GI 缓存是不同内容。"], "url": SOURCES["gi"]},
        {"title": "Asset Store、Bee 与 Gradle 需要人工决定", "text": "Asset Store 缓存可能是下架资源的唯一副本；Bee 影响增量构建；Gradle 与其他 Android 工程共享。这里仅诊断。",
         "steps": ["Asset Store 优先备份并在 Preferences 中改址。", "Bee 改址可使用 BEE_CACHE_DIRECTORY；按 Unity 官方构建缓存说明操作。", "Gradle 使用其官方维护策略；不要直接删除整个 .gradle。"], "url": SOURCES["bee"]},
        {"title": "Hub 下载与工程缓存", "text": "Hub 下载/临时目录随版本和设置不同。工具不把整个 TEMP 或 UnityHub 数据目录当成 Unity 垃圾。",
         "steps": ["在 Hub 设置中检查编辑器安装位置和可用的下载位置选项。", "工程的 Library/Temp/obj 可重建但代价较高；Assets、Packages、ProjectSettings、UserSettings 和 .meta 必须保留。", "Editor 安装内的 SDK、NDK、OpenJDK 与 Unity 许可证不在清理白名单。"], "url": SOURCES["upm"]},
    ]


def audit(environ=None, stop=None, deadline=None):
    """Inspect bounded, known Unity-related locations without deleting files."""
    env = dict(os.environ if environ is None else environ)
    deadline = time.monotonic() + 30 if deadline is None else deadline
    report = {"items": [], "settings": [], "guidance": _guidance(), "totals_by_drive": {},
              "summary": {"c_drive_bytes": 0, "other_drive_bytes": 0, "logical_bytes": 0,
                          "count": 0, "complete": False},
              "complete": False, "supported": WINDOWS, "warnings": [],
              "measurement": "已读取的唯一普通文件逻辑字节；不是磁盘分配字节或保证可释放量。重叠路径和硬链接不重复累加。",
              "settings_scope": "读取当前进程环境变量及用户 .upmconfig.toml 的 cacheRoot。未读取注册表、Hub 私有配置格式、Editor Preferences 或启动命令行；它们可能覆盖默认位置。"}
    if not WINDOWS:
        report["warnings"].append("此诊断仅在 Windows 上读取真实缓存；当前平台未扫描用户主目录。")
        return report
    profile, error = _profile_path(env)
    if profile is None:
        report["warnings"].append("无法确认安全的 Windows 用户资料路径：" + error)
        return report
    local = ntpath.join(profile, "AppData", "Local")
    roaming = ntpath.join(profile, "AppData", "Roaming")
    low = ntpath.join(profile, "AppData", "LocalLow")
    locations, indexed = [], {}

    def add(name, path, group, source, reason, file_names=()):
        normalized, error = _validated_path(path, profile)
        if normalized is None:
            report["warnings"].append(name + "：" + error)
            return
        key = _key(normalized)
        if key in indexed:
            indexed[key]["aliases"].append(name + "（" + source + "）")
            return
        entry = dict(id=hashlib.sha256(key.encode("utf-8")).hexdigest()[:20], name=name,
                     path=normalized, group=group, source=source, drive=ntpath.splitdrive(normalized)[0].upper(),
                     action="只读诊断", reason=reason, aliases=[], file_names=tuple(file_names))
        indexed[key] = entry
        locations.append(entry)

    for sub, label in (("upm", "Unity 6 UPM 默认缓存"), ("npm", "Unity 旧版 npm 缓存"),
                       ("packages", "Unity 旧版 packages 缓存"), ("git-lfs", "Unity 旧版 Git LFS 缓存")):
        add(label, ntpath.join(local, "Unity", "cache", sub), "unity-upm", "官方默认位置/旧版残留候选",
            "缓存可能由不同 Unity 版本共用；是否正在使用需结合编辑器设置核实。离线工作时保留。")
    add("Unity GI 光照缓存", ntpath.join(low, "Unity", "Caches", "GiCache"), "unity-gi", "常见 Windows 默认位置",
        "GI Preferences 或 -giCustomCacheLocation 可改变实际位置；不推断正在使用的自定义位置。")
    add("Unity 编辑器/UPM 日志", ntpath.join(local, "Unity", "Editor"), "unity-logs", "官方日志位置",
        "此处统计四个明确日志名的所有年龄；清理列表另外只允许至少 14 天的日志。", EDITOR_LOG_NAMES)
    add("Unity Bee 构建缓存", ntpath.join(local, "Unity", "Caches", "bee"), "unity-bee", "官方默认位置",
        "影响增量构建；不提供外部自动删除。")
    add("Asset Store 下载资源", ntpath.join(roaming, "Unity", "Asset Store-5.x"), "unity-assets", "官方默认位置",
        "部分资源可能无法重新下载；先备份，再通过 Unity 设置管理。")
    add("Unity Hub 日志", ntpath.join(roaming, "UnityHub", "logs"), "unity-hub-logs", "经典 Hub 日志位置候选",
        "只统计日志；不清理整个 UnityHub 设置、项目列表和身份数据。MSIX 版本可能使用其他位置。")

    config = read_upm_cache_root(profile)
    report["settings"].append(config)
    if config["valid"]:
        add("UPM 用户配置 cacheRoot", config["value"], "unity-configured-upm", config["source"],
            "自定义位置只做诊断，不扩展删除白名单。若进程设置 UPM_CACHE_ROOT，其优先级更高。")

    settings = (
        ("UPM_CACHE_ROOT", "UPM 自定义全局缓存", "unity-configured-upm", "优先于用户 cacheRoot；该路径自身就是实际缓存根，不额外拼接 upm。"),
        ("UPM_NPM_CACHE_PATH", "旧版 UPM npm 覆盖缓存", "unity-configured-upm", "仅旧版生效；Unity 6 此变量已废弃。"),
        ("UPM_CACHE_PATH", "旧版 UPM packages 覆盖缓存", "unity-configured-upm", "旧版解包缓存位置；Unity 6 不再使用旧 packages 子缓存。"),
        ("UPM_GIT_LFS_CACHE_PATH", "UPM Git LFS 覆盖缓存", "unity-configured-upm", "独立子缓存覆盖可能优先于全局根，需按所用 Unity 版本核实。"),
        ("ASSETSTORE_CACHE_PATH", "Asset Store 自定义缓存", "unity-assets", "该变量指定父根，实际缓存再拼接 Asset Store-5.x；改址不会搬走旧缓存。"),
        ("BEE_CACHE_DIRECTORY", "Bee 自定义构建缓存", "unity-bee", "影响增量构建；只读诊断。"),
        ("GRADLE_USER_HOME", "Gradle 用户目录", "unity-gradle", "只统计 caches 和 wrapper/dists；不扫描配置与 init 脚本。"),
        ("ANDROID_HOME", "Android SDK", "unity-sdk", "这是安装工具链，禁止作为缓存清理；可能被其他 Android 工程使用。"),
        ("ANDROID_SDK_ROOT", "Android SDK 兼容变量", "unity-sdk", "旧变量/兼容设置，只作安装路径诊断；不代表 Unity 当前实际使用的位置。"),
    )
    gradle = ntpath.join(profile, ".gradle")
    for name, title, group, note in settings:
        raw = env.get(name)
        if raw is None or raw == "":
            continue
        value, error = _validated_path(raw, profile)
        report["settings"].append(dict(name=name, value=raw if isinstance(raw, str) else "",
                                       source="当前进程环境变量", valid=value is not None, note=error or note))
        if value is None:
            report["warnings"].append(name + " 已设置但未扫描：" + error)
            continue
        if name == "GRADLE_USER_HOME":
            gradle = value
            continue
        path = ntpath.join(value, "Asset Store-5.x") if name == "ASSETSTORE_CACHE_PATH" else value
        add(title, path, group, name + "（当前进程）", note + " 自定义路径只读，不加入删除白名单。")
    for base, source in ((ntpath.join(profile, ".gradle"), "默认 Gradle 用户目录"), (gradle, "有效 Gradle 用户目录（进程环境）")):
        add("Gradle 下载/构建缓存", ntpath.join(base, "caches"), "unity-gradle", source,
            "供多个 Android 工程共用；由 Gradle 官方维护策略管理。")
        add("Gradle Wrapper 分发包", ntpath.join(base, "wrapper", "dists"), "unity-gradle", source,
            "删除后可能需要联网重新下载；不自动删除。")
    if env.get("GI_CACHE_FOLDER"):
        report["settings"].append(dict(name="GI_CACHE_FOLDER", value=str(env["GI_CACHE_FOLDER"]),
                                       source="当前进程环境变量", valid=False,
                                       note="未确认这是 Unity 官方支持变量，未据此扫描；请核实 Preferences 或 -giCustomCacheLocation。"))
    seen, remaining = set(), MAX_AUDIT_ENTRIES
    for location in locations:
        names = location.pop("file_names")
        measured = measure_directory(Path(location["path"]), stop=stop, deadline=deadline,
                                     max_entries=min(MAX_LOCATION_ENTRIES, max(0, remaining)),
                                     seen_files=seen, file_names=names)
        remaining -= measured["checked"]
        row = dict(location, **measured)
        report["items"].append(row)
        totals = report["totals_by_drive"].setdefault(row["drive"], {"bytes": 0, "count": 0, "complete": True})
        totals["bytes"] += row["bytes"]
        totals["count"] += row["count"]
        totals["complete"] = totals["complete"] and row["complete"]
    complete = all(item["complete"] for item in report["items"])
    if stop is not None and stop.is_set():
        complete = False
    report["complete"] = complete
    report["summary"] = dict(c_drive_bytes=report["totals_by_drive"].get("C:", {}).get("bytes", 0),
                             other_drive_bytes=sum(v["bytes"] for d, v in report["totals_by_drive"].items() if d != "C:"),
                             logical_bytes=sum(v["bytes"] for v in report["totals_by_drive"].values()),
                             count=sum(v["count"] for v in report["totals_by_drive"].values()), complete=complete)
    return report
