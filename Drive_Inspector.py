#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read-only, opt-in inventory for *selected* non-C Windows volumes.

Duplicate candidates use size -> first/last block -> whole-file SHA-256.  No
file deletion, moving, quarantine or mutation operations exist in this module.
Limited budgets, no junction traversal, no network shares and no cloud calls.
Classification uses explainable local suffix/name rules, not external AI.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import os
from pathlib import Path
import re
import stat
import time

REPARSE = 0x400
BLOCK = 128 * 1024
DEFAULT_MAX_FILES = 120_000
DEFAULT_MAX_SECONDS = 150
DEFAULT_HASH_BYTES = 12 * 1024 ** 3
DEFAULT_HASH_SECONDS = 150
WIN_DRIVE = re.compile(r"^[D-Z]:$", re.IGNORECASE)
PROTECTED_DIRS = frozenset({
    '$recycle.bin', 'system volume information', 'windows', 'windowsapps',
    'program files', 'program files (x86)', 'programdata', 'recovery',
    'msocache', '$windows.~bt', 'boot', '.git', '.venv', 'venv', '__pycache__',
    'node_modules', 'site-packages', '.conda', 'envs', '.trash', '.trashes',
})
KEEP_DIRS = frozenset({'backup', 'backups', '备份', 'archive', 'archives',
                       'snapshots', 'checkpoint', 'checkpoints', 'recovery'})
SENSITIVE_DIRS = frozenset({'models', 'huggingface', 'lora', 'checkpoints',
                            '.git', 'sources', 'source', 'src', 'secrets', '.ssh',
                            'windows', 'system32', 'windowsapps', '.venv', 'venv',
                            'envs', 'site-packages'})
CATEGORIES = (
    ('images', '图片/设计素材', {'.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp', '.tiff', '.tif', '.heic', '.svg', '.psd', '.ai', '.raw', '.cr2', '.dng'}),
    ('videos', '视频', {'.mp4', '.mov', '.mkv', '.avi', '.wmv', '.flv', '.webm', '.m4v', '.mts'}),
    ('audio', '音频', {'.mp3', '.wav', '.flac', '.m4a', '.aac', '.ogg', '.opus', '.aiff', '.mid'}),
    ('documents', '文档/表格', {'.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.txt', '.rtf', '.odt', '.md', '.epub', '.csv'}),
    ('archives', '压缩包', {'.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz', '.zst', '.tgz'}),
    ('installers', '安装包/程序', {'.exe', '.msi', '.msix', '.dll', '.sys', '.apk', '.aab', '.deb', '.rpm', '.appx', '.whl', '.iso'}),
    ('models', 'AI 模型/权重', {'.safetensors', '.gguf', '.ckpt', '.pth', '.pt', '.onnx', '.tflite', '.pb', '.engine'}),
    ('virtual_disks', '虚拟磁盘/映像', {'.vhdx', '.vhd', '.vmdk', '.vdi', '.qcow2', '.img', '.wim', '.esd'}),
    ('code', '工程/源代码', {'.py', '.js', '.ts', '.jsx', '.tsx', '.cs', '.cpp', '.c', '.h', '.java', '.rs', '.go', '.sh', '.ps1', '.bat', '.cmd', '.json', '.yaml', '.yml', '.toml', '.ipynb', '.unity', '.prefab', '.fbx'}),
    ('databases', '数据库/存档', {'.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.bak', '.sql', '.pst', '.ost'}),
)
_SUFFIX_TO_CAT = {suffix: (cat, label) for cat, label, suffixes in CATEGORIES for suffix in suffixes}
CAT_LABELS = {cat: label for cat, label, _ in CATEGORIES} | {'other': '其他/未知'}
HARD_PROTECT = frozenset({'models', 'virtual_disks', 'code', 'databases'})


def available_drives():
    """Windows only; fixed/removable volumes D:..Z:; never C: or network/optical."""
    if os.name != 'nt':
        return []
    try:
        import ctypes
        kernel = ctypes.windll.kernel32
        mask = int(kernel.GetLogicalDrives())
        found = []
        for number in range(3, 26):
            letter = chr(65 + number)
            if not (mask & (1 << number)):
                continue
            root = f'{letter}:\\'
            kind = int(kernel.GetDriveTypeW(ctypes.c_wchar_p(root)))
            # 2 = removable; 3 = fixed. No mapped/cloud network drives.
            if kind not in (2, 3):
                continue
            try:
                import shutil
                space = shutil.disk_usage(root)
                total, free = space.total, space.free
            except OSError:
                total, free = 0, 0
            found.append({'id': f'{letter}:', 'path': root,
                          'type': '可移动磁盘' if kind == 2 else '本地磁盘',
                          'total': total, 'free': free})
        return found
    except (OSError, AttributeError, ValueError):
        return []


def select_drives(ids, drive_choices=None):
    """Reject arbitrary paths (including traversal), duplicate IDs and C:."""
    if not isinstance(ids, list) or not 1 <= len(ids) <= 8:
        raise ValueError('请选择 1 至 8 个本机非 C 盘。')
    if any(not isinstance(x, str) or not WIN_DRIVE.fullmatch(x) for x in ids):
        raise ValueError('只接受界面列出的 D: 至 Z: 盘符，不能输入任意目录或网络路径。')
    normalized = [x.upper() for x in ids]
    if len(normalized) != len(set(normalized)):
        raise ValueError('不能重复选择同一个磁盘。')
    drives = {x['id'].upper(): x for x in (available_drives() if drive_choices is None else drive_choices)}
    if any(x not in drives for x in normalized):
        raise ValueError('磁盘已断开、未授权或不是本机固定/可移动磁盘，请刷新列表。')
    return [Path(drives[x]['path']) for x in normalized]


def is_reparse(info):
    return bool(stat.S_ISLNK(info.st_mode) or (getattr(info, 'st_file_attributes', 0) or 0) & REPARSE)


def classification(path):
    """Explanations are based only on local metadata; no upload/ML inference."""
    p = Path(path)
    name, suffix = p.name.casefold(), p.suffix.casefold()
    if suffix in _SUFFIX_TO_CAT:
        cat, label = _SUFFIX_TO_CAT[suffix]
        return {'id': cat, 'label': label, 'confidence': '高', 'reason': f'按扩展名 {suffix} 分类（未解析文件内容）'}
    if any(s in name for s in ('backup', '备份', 'snapshot', 'restore')):
        return {'id': 'archives', 'label': CAT_LABELS['archives'], 'confidence': '低', 'reason': '按文件名推测为备份；请人工复核'}
    return {'id': 'other', 'label': CAT_LABELS['other'], 'confidence': '低', 'reason': '无法凭扩展名确定文件类型，保持未分类'}


def protected_file(path, category):
    p = Path(path)
    segments = {seg.casefold() for seg in p.parts[:-1]}
    if category in HARD_PROTECT or segments & SENSITIVE_DIRS:
        return True, '模型/虚拟磁盘/源码/数据库或工程运行环境，优先保护'
    if segments & KEEP_DIRS or any(x in p.name.casefold() for x in ('backup', '备份', 'restore', 'snapshot')):
        return True, '可能是备份或恢复点，避免据此自动建议删除'
    if category in ('documents', 'images', 'videos', 'audio'):
        return False, '个人文件可能有独特价值，确认原件、云同步和备份后手动判断'
    return False, '文件内容相同也不代表可无损删除：请核对软件引用与备份'


def file_digest(entry, stop, deadline, bytes_left, sample=False):
    """Open read-only, compare descriptor identity+metadata and reject mutations."""
    if stop.is_set() or time.monotonic() >= deadline:
        raise TimeoutError('哈希阶段已取消或达到时间上限')
    path = entry['path']
    if bytes_left <= 0:
        raise TimeoutError('哈希字节预算已用尽')
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or is_reparse(before):
        raise OSError('文件已变化或变为连接点')
    if (before.st_size, before.st_mtime_ns, before.st_dev, before.st_ino) != entry['identity']:
        raise OSError('文件在扫描后已修改')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    total = 0
    try:
        opened = os.fstat(fd)
        if (opened.st_size, opened.st_mtime_ns, opened.st_dev, opened.st_ino) != entry['identity'] or not stat.S_ISREG(opened.st_mode):
            raise OSError('文件打开时与扫描快照不一致')
        h = hashlib.sha256()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            if sample:
                if bytes_left < (min(opened.st_size, BLOCK) * (2 if opened.st_size > BLOCK else 1)):
                    raise TimeoutError('采样预算不足')
                data = stream.read(BLOCK)
                total += len(data)
                h.update(data)
                if opened.st_size > BLOCK:
                    stream.seek(max(BLOCK, opened.st_size - BLOCK))
                    data = stream.read(BLOCK)
                    total += len(data)
                    h.update(data)
                # Sampling is only a candidate filter; NEVER proof of equality.
                h.update(str(opened.st_size).encode('ascii'))
            else:
                while total < opened.st_size:
                    if stop.is_set() or time.monotonic() >= deadline or total >= bytes_left:
                        raise TimeoutError('哈希字节/时间预算耗尽，未验证的文件不能判定为重复')
                    buf = stream.read(min(1024 * 1024, opened.st_size - total, bytes_left - total))
                    if not buf:
                        raise OSError('哈希时文件内容提前结束')
                    total += len(buf)
                    h.update(buf)
            after = os.fstat(fd)
            if (after.st_size, after.st_mtime_ns, after.st_dev, after.st_ino) != entry['identity']:
                raise OSError('哈希期间文件发生变化')
        return h.hexdigest(), total
    finally:
        os.close(fd)


def inspect_roots(roots, stop, *, min_duplicate_bytes=64*1024,
                  max_files=DEFAULT_MAX_FILES, max_scan_seconds=DEFAULT_MAX_SECONDS,
                  max_hash_bytes=DEFAULT_HASH_BYTES, max_hash_seconds=DEFAULT_HASH_SECONDS,
                  progress=None):
    """Pure read-only bounded volume inventory, safe to unit test in a tmpdir.

    The HTTP-facing caller must use select_drives; this function is deliberately
    generic for isolated tests. No mkdir/unlink/rename/rmdir/move operation.
    """
    if not roots or len(roots) > 8 or min_duplicate_bytes < 1:
        raise ValueError('扫描目标或大小门槛无效')
    start = time.monotonic()
    scan_deadline = start + max_scan_seconds
    seen_roots, stack, files, inode_paths = set(), [], [], set()
    incomplete, cancel_flag, skipped, denied = False, False, 0, 0
    for root in roots:
        root = Path(root)
        root_abs = os.path.abspath(root)
        if root_abs in seen_roots or not root.is_dir() or is_reparse(os.lstat(root)):
            raise ValueError('磁盘路径失效、重复或为符号链接/联接点')
        seen_roots.add(root_abs)
        stack.append((root, root_abs))
    class_stats = defaultdict(lambda: {'count': 0, 'bytes': 0, 'samples': []})
    volume_counts = Counter()
    while stack:
        if stop.is_set():
            incomplete = cancel_flag = True
            break
        if len(files) >= max_files or time.monotonic() >= scan_deadline:
            incomplete = True
            break
        folder, volume = stack.pop()
        try:
            with os.scandir(folder) as stream:
                for candidate in stream:
                    if stop.is_set() or len(files) >= max_files or time.monotonic() >= scan_deadline:
                        incomplete = True
                        cancel_flag = stop.is_set()
                        break
                    try:
                        info = candidate.stat(follow_symlinks=False)
                        if is_reparse(info):
                            skipped += 1
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            if candidate.name.casefold() in PROTECTED_DIRS:
                                skipped += 1
                                continue
                            stack.append((Path(candidate.path), volume))
                        elif stat.S_ISREG(info.st_mode):
                            # Additional hardlink names are NOT another reclaimable copy.
                            identity = (int(info.st_dev), int(info.st_ino))
                            if info.st_nlink > 1 and info.st_ino and identity in inode_paths:
                                skipped += 1
                                continue
                            if info.st_nlink > 1 and info.st_ino:
                                inode_paths.add(identity)
                            label = classification(candidate.path)
                            item = {'path': str(candidate.path), 'size': max(0, int(info.st_size)),
                                    'mtime_ns': int(info.st_mtime_ns), 'identity': (
                                        int(info.st_size), int(info.st_mtime_ns), int(info.st_dev), int(info.st_ino)),
                                    'category': label['id'], 'volume': volume,
                                    'classification': label}
                            files.append(item)
                            bucket = class_stats[label['id']]
                            bucket['count'] += 1
                            bucket['bytes'] += item['size']
                            if len(bucket['samples']) < 6:
                                bucket['samples'].append({'path': item['path'], 'bytes': item['size'],
                                                          'confidence': label['confidence'], 'reason': label['reason']})
                            volume_counts[volume] += 1
                        else:
                            skipped += 1
                    except OSError:
                        denied += 1
        except OSError:
            denied += 1
        if progress and len(files) % 2500 < 60:
            progress('已识别 {:,} 个文件；正在逐类统计（只读）'.format(len(files)))
        if incomplete:
            break
    # Only count actual successful SHA-256 comparisons, not size/name matches.
    sizes = defaultdict(list)
    for f in files:
        if f['size'] >= min_duplicate_bytes:
            sizes[f['size']].append(f)
    candidates = [(size, recs) for size, recs in sizes.items() if len(recs) > 1]
    candidates.sort(key=lambda x: x[0] * (len(x[1])-1), reverse=True)
    hash_start = time.monotonic()
    hash_deadline = hash_start + max_hash_seconds
    hash_budget = max_hash_bytes
    hash_failures = 0
    matched = defaultdict(list)
    verified_files = 0
    hashing_incomplete = False
    for size, records in candidates:
        if stop.is_set() or time.monotonic() >= hash_deadline:
            hashing_incomplete = True
            break
        sample_map = defaultdict(list)
        for rec in records:
            try:
                fingerprint, nbytes = file_digest(rec, stop, hash_deadline, hash_budget, sample=True)
                hash_budget -= nbytes
                if hash_budget <= 0:
                    hashing_incomplete = True
                    break
                sample_map[fingerprint].append(rec)
            except TimeoutError:
                hashing_incomplete = True
                break
            except (OSError, ValueError):
                hash_failures += 1
        if hashing_incomplete:
            break
        for overlap in sample_map.values():
            if len(overlap) < 2:
                continue
            for rec in overlap:
                try:
                    digest, nbytes = file_digest(rec, stop, hash_deadline, hash_budget, sample=False)
                    hash_budget -= nbytes
                    verified_files += 1
                    matched[(size, digest)].append(rec)
                except TimeoutError:
                    hashing_incomplete = True
                    break
                except (OSError, ValueError):
                    hash_failures += 1
            if hashing_incomplete:
                break
        if progress and verified_files % 40 == 0:
            progress('已完成 {:,} 个文件的 SHA-256 全量校验'.format(verified_files))
        if hashing_incomplete:
            break
    groups = []
    for (size, digest), members in matched.items():
        if len(members) < 2:
            continue
        # Protect source/backup/model paths as possible originals; no deletion.
        def keeper_rank(rec):
            protect, _ = protected_file(rec['path'], rec['category'])
            return (not protect, rec['mtime_ns'], len(rec['path']), rec['path'].casefold())
        ordered = sorted(members, key=keeper_rank)
        keeper = ordered[0]
        copies = []
        for rec in ordered[1:]:
            protect, reason = protected_file(rec['path'], rec['category'])
            copies.append({'path': rec['path'], 'size': size, 'category': rec['category'],
                           'risk': 'red' if protect else 'amber',
                           'suggestion': ('重要数据：不要依据查重结果删除' if protect else
                                          '仅供人工复核：核对引用/备份后通过资源管理器决定'),
                           'reason': reason})
        potential_bytes = size * (len(members) - 1)
        groups.append({'id': f'dup-{digest[:18]}-{size}', 'sha256': digest,
                       'size': size, 'count': len(members), 'theoretical_bytes': potential_bytes,
                       'keeper': {'path': keeper['path'], 'category': keeper['category'],
                                  'reason': '建议优先保留的候选原件；请人工复核'},
                       'copies': copies, 'manual_only': True,
                       'warning': '完整 SHA-256 一致，但文件可能被应用/工程引用；不提供删除按钮。'})
    groups.sort(key=lambda r: r['theoretical_bytes'], reverse=True)
    category_rows = sorted(({'id': cat, 'label': CAT_LABELS[cat], **counts}
                            for cat, counts in class_stats.items()),
                           key=lambda x: x['bytes'], reverse=True)
    return {
        'roots': sorted(seen_roots),
        'complete': not incomplete and not hashing_incomplete and hash_failures == 0 and denied == 0,
        'inventory_complete': not incomplete and denied == 0,
        'hash_complete': not hashing_incomplete and hash_failures == 0,
        'cancelled': cancel_flag or stop.is_set(),
        'files_seen': len(files), 'skipped_links_hardlinks_protected': skipped,
        'permission_errors': denied, 'hash_errors': hash_failures,
        'duplicate_groups': groups[:200], 'total_duplicate_groups': len(groups),
        'duplicate_files': sum(g['count'] - 1 for g in groups),
        'theoretical_savings': sum(g['theoretical_bytes'] for g in groups),
        'categories': category_rows,
        # Complete read-only file catalog is served ONLY by authenticated,
        # bounded pagination or an explicit locally downloaded report.
        'classified_files': [{'path': item['path'], 'size': item['size'],
                              'category': item['category'],
                              'mtime': datetime.fromtimestamp(item['mtime_ns'] / 1_000_000_000).strftime('%Y-%m-%d'),
                              'confidence': item['classification']['confidence'],
                              'reason': item['classification']['reason']}
                             for item in files],
        'min_duplicate_bytes': min_duplicate_bytes,
        'elapsed_seconds': round(time.monotonic() - start, 2),
        'warning': ('扫描未完整覆盖允许访问的目录（超限/取消/无权限/哈希失败），结果只能代表已完成校验的部分文件。'
                    if incomplete or hashing_incomplete or hash_failures or denied else
                    '允许访问的文件已扫描并完成哈希验证；仍跳过系统/环境等受保护目录，不代表盘符上全部文件。') +
                   ' 所有建议仅供手工查看，不提供跨盘自动删除/移动功能。',
    }


def empty_report():
    return {'roots': [], 'complete': False, 'inventory_complete': False, 'hash_complete': False,
            'files_seen': 0, 'duplicate_groups': [], 'total_duplicate_groups': 0,
            'duplicate_files': 0, 'theoretical_savings': 0, 'categories': [], 'classified_files': [],
            'warning': '尚未开始：必须主动选择本机 D: 至 Z: 磁盘，扫描只读。'}
