#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""User-opt-in, resumable, read-only network-file *metadata* indexing.

The share is never modified. The local SQLite file contains sensitive filenames
and paths, so callers must explicitly choose a non-C: local fixed disk.
No background monitoring, uploads, content hashes, or automatically scheduled walks.
Only paths returned by the Windows mapped-drive allowlist can be scanned by the UI.
"""
from __future__ import annotations

import ctypes
from contextlib import closing
import hashlib
import os
import re
import sqlite3
import stat
import time
from pathlib import Path

import Drive_Inspector as drives

DB_VERSION = 1
DIR_NAME = 'CScanStudio_NetworkIndex'
REPARSE = 0x400
MAX_ROWS = 500_000
DEFAULT_SECONDS = 12
DEFAULT_ENTRIES = 12_000
MAX_SECONDS = 60
MAX_ENTRIES = 60_000
MAX_RESULTS = 180
DRIVE_RE = re.compile(r'[D-Z]:', re.IGNORECASE)


def local_storage_drives():
    """Only Windows fixed non-C: disks; no removable or mapped network disks."""
    if os.name != 'nt':
        return []
    try:
        kernel = ctypes.windll.kernel32
        mask = int(kernel.GetLogicalDrives())
        found = []
        for i in range(3, 26):
            root = f'{chr(65+i)}:\\'
            if mask & (1 << i) and int(kernel.GetDriveTypeW(ctypes.c_wchar_p(root))) == 3:
                found.append(f'{chr(65+i)}:')
        return found
    except (OSError, AttributeError, ValueError):
        return []


def _storage_folder(storage, *, test_folder=None, create=False):
    if test_folder is not None:  # Test-only filesystem injected from Python; never in HTTP parameters.
        folder = Path(test_folder)
    else:
        if not isinstance(storage, str) or storage.upper() not in local_storage_drives():
            raise ValueError('索引必须保存于 Windows 本机 D:～Z: 固定盘，不允许 C:、U 盘或网络盘。')
        folder = Path(storage.upper() + '\\') / DIR_NAME
        # Reject preexisting junctions/reparse points on the app-owned directory.
        if folder.exists() or folder.is_symlink():
            info = os.lstat(folder)
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or (
                    (getattr(info, 'st_file_attributes', 0) or 0) & REPARSE):
                raise ValueError('索引目录不能是联接点或符号链接。')
    if create:
        folder.mkdir(parents=True, exist_ok=True)
        info = os.lstat(folder)
        if not stat.S_ISDIR(info.st_mode) or ((getattr(info, 'st_file_attributes', 0) or 0) & REPARSE):
            raise ValueError('索引目录安全检查失败。')
    return folder


def _mapping_identity(drive):
    """Hash a Win32 mapped UNC target, never expose its name to the browser."""
    if os.name != 'nt':
        return 'synthetic'
    try:
        size = ctypes.c_ulong(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        result = ctypes.windll.mpr.WNetGetConnectionW(ctypes.c_wchar_p(drive), buf, ctypes.byref(size))
        if result == 0 and buf.value:
            return hashlib.sha256(buf.value.casefold().encode('utf-8')).hexdigest()[:20]
    except (OSError, AttributeError, ValueError):
        pass
    # Mapping target not verifiable; do not silently merge with another share's db.
    return 'identity-unavailable'


def _database_path(drive, storage, *, test_folder=None, identity=None, create=False):
    if not isinstance(drive, str) or DRIVE_RE.fullmatch(drive) is None:
        raise ValueError('仅支持 D:～Z: 映射网络盘。')
    folder = _storage_folder(storage, test_folder=test_folder, create=create)
    target_id = identity if identity is not None else _mapping_identity(drive.upper())
    # Never bind two differently mapped shares to a common fallback identity.
    # An unavailable UNC target is NOT evidence that the previous O: is still O:.
    if test_folder is None and target_id == 'identity-unavailable':
        raise ValueError('无法确认映射网络盘的真实共享目标；暂不读取或创建索引，避免混淆网盘。')
    if not isinstance(target_id, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}', target_id):
        raise ValueError('索引身份无效。')
    db = folder / f'{drive[0].upper()}_{target_id}.sqlite3'
    if db.exists() or db.is_symlink():
        info = os.lstat(db)
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or (
                (getattr(info, 'st_file_attributes', 0) or 0) & REPARSE):
            raise ValueError('索引数据库不能是联接点、链接或非普通文件。')
    return db


def _connect(db, *, writable):
    if not writable and not db.is_file():
        return None
    # SQLite's regular connect() may recreate a missing database after a
    # path check. In search/status mode explicitly forbid database creation.
    conn = (sqlite3.connect(str(db), timeout=3.0) if writable else
            sqlite3.connect(db.resolve(strict=True).as_uri() + '?mode=ro',
                            timeout=3.0, uri=True))
    conn.execute('PRAGMA busy_timeout=3000')
    if writable:
        conn.execute('PRAGMA journal_mode=DELETE')
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY COLLATE NOCASE,
                name_fold TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime REAL NOT NULL,
                seen INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pending (
                path TEXT PRIMARY KEY COLLATE NOCASE,
                offset INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_files_size ON files(size DESC);
        ''')
        with conn:
            conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('schema','1')")
            conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('generation','0')")
            conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('state','unstarted')")
    else:
        conn.execute('PRAGMA query_only=ON')
    return conn


def _meta(conn, key, default=''):
    row = conn.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    return row[0] if row is not None else default


def _set_meta(conn, key, value):
    conn.execute('INSERT INTO meta(key,value) VALUES(?,?) '
                 'ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, str(value)))


def status(drive, storage, *, test_folder=None, identity=None):
    """Read only a local database; safe even when the network share is offline."""
    db = _database_path(drive, storage, test_folder=test_folder, identity=identity)
    initial = {'drive': drive.upper(), 'storage': storage, 'state': 'missing',
               'files': 0, 'pending': 0, 'scanned': 0, 'errors': 0,
               'updated': '', 'complete': False, 'index_path': str(db),
               'note': '尚未建立本地文件名索引；仅用户手动确认后才访问网盘。'}
    if not db.is_file():
        return initial
    try:
        with closing(_connect(db, writable=False)) as conn:
            state = _meta(conn, 'state', 'invalid')
            total = conn.execute('SELECT count(*) FROM files').fetchone()[0]
            pending = conn.execute('SELECT count(*) FROM pending').fetchone()[0]
            initial.update({'state': state, 'files': total, 'pending': pending,
                            'scanned': int(_meta(conn, 'scanned', '0')),
                            'errors': int(_meta(conn, 'errors', '0')),
                            'updated': _meta(conn, 'updated'), 'complete': state == 'complete',
                            'note': ('索引完整性未知；数据可能过时。' if state != 'complete'
                                     else '上次扫描完整结束；扫描之后变动的文件可能尚未反映。')})
    except (OSError, sqlite3.DatabaseError, ValueError) as exc:
        initial.update({'state': 'error', 'note': '本地索引不可用：' + str(exc)[:120]})
    return initial


def lookup(drive, storage, filename='', *, limit=MAX_RESULTS, test_folder=None, identity=None):
    """Return file metadata only; never stat/open any remote file during search."""
    if not isinstance(filename, str) or len(filename) > 120 or '\x00' in filename:
        raise ValueError('文件名关键词必须在 120 字以内。')
    if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
        raise ValueError('文件结果数量超出限制。')
    db = _database_path(drive, storage, test_folder=test_folder, identity=identity)
    if not db.is_file():
        return [], status(drive, storage, test_folder=test_folder, identity=identity)
    with closing(_connect(db, writable=False)) as conn:
        query = "SELECT path,size,mtime FROM files"
        values = []
        if filename:
            query += ' WHERE instr(name_fold, ?) > 0'
            values.append(filename.casefold())
        query += ' ORDER BY size DESC, path LIMIT ?'
        values.append(limit)
        rows = [(str(path), int(size), float(mtime)) for path, size, mtime in
                conn.execute(query, values)]
    return rows, status(drive, storage, test_folder=test_folder, identity=identity)


def scan(drive, storage, stop, *, max_seconds=DEFAULT_SECONDS, max_entries=DEFAULT_ENTRIES,
         progress=None, test_root=None, test_folder=None, identity=None):
    """Explicit, resumable metadata walk. Partial runs never delete old indexed rows.

    ``test_root``/``test_folder`` are internal synthetic test hooks, never supplied
    by HTTP. The production root is ALWAYS revalidated via mapped-drive API.
    """
    if type(max_seconds) not in (int, float) or not 1 <= max_seconds <= MAX_SECONDS:
        raise ValueError('扫描时间限制无效。')
    if type(max_entries) is not int or not 1 <= max_entries <= MAX_ENTRIES:
        raise ValueError('扫描目录项限制无效。')
    if not isinstance(drive, str) or DRIVE_RE.fullmatch(drive) is None:
        raise ValueError('索引盘符无效。')
    root = Path(test_root) if test_root is not None else drives.select_network_drive(drive.upper())
    root = Path(os.path.abspath(root))
    mapping_id = _mapping_identity(drive.upper()) if test_root is None else 'synthetic'
    if test_root is None and mapping_id == 'identity-unavailable':
        # Remote target identity is required to avoid merging two O: mappings.
        raise ValueError('无法确认映射网络盘的 UNC 目标；拒绝把不同共享盘的索引混合。')
    db = _database_path(drive, storage, test_folder=test_folder, identity=identity, create=True)
    started = time.monotonic()
    count, errors, writes = 0, 0, 0
    with closing(_connect(db, writable=True)) as conn:
        if int(_meta(conn, 'schema', '0')) != DB_VERSION:
            raise ValueError('未知索引数据库版本；不会覆盖已有数据。')
        old_state = _meta(conn, 'state')
        gen = int(_meta(conn, 'generation'))
        if old_state in ('complete', 'unstarted') or not conn.execute('SELECT 1 FROM pending LIMIT 1').fetchone():
            gen += 1
            with conn:
                conn.execute('DELETE FROM pending')
                conn.execute('INSERT INTO pending(path,offset) VALUES(?,0)', (str(root),))
                _set_meta(conn, 'generation', gen)
                _set_meta(conn, 'root', str(root))
                _set_meta(conn, 'scanned', 0)
                _set_meta(conn, 'errors', 0)
                _set_meta(conn, 'state', 'partial')
        elif os.path.normcase(_meta(conn, 'root')) != os.path.normcase(str(root)):
            raise ValueError('网络盘根目录发生变化；不能混合索引快照。')
        while not stop.is_set() and count < max_entries and time.monotonic()-started < max_seconds:
            item = conn.execute('SELECT path,offset FROM pending ORDER BY rowid DESC LIMIT 1').fetchone()
            if item is None:
                break
            folder, offset = item
            if test_root is None:
                # Mapping was changed or disconnected while the task was running.
                drives.select_network_drive(drive.upper())
                if _mapping_identity(drive.upper()) != mapping_id:
                    raise ValueError('检测到共享盘重映射；保留部分索引并停止，以免混合不同网盘的路径。')
            # Reject unexpected links even if directory was queued earlier.
            try:
                info = os.lstat(folder)
                if not stat.S_ISDIR(info.st_mode) or (getattr(info, 'st_file_attributes', 0) or 0) & REPARSE:
                    raise OSError('not a normal directory')
                with os.scandir(folder) as it:
                    current = 0
                    completed_folder = True
                    children = []
                    newfiles = []
                    for entry in it:
                        if current < offset:
                            current += 1
                            if time.monotonic()-started >= max_seconds:
                                completed_folder = False
                                break
                            continue
                        if stop.is_set() or count >= max_entries or time.monotonic()-started >= max_seconds:
                            completed_folder = False
                            break
                        current += 1
                        count += 1
                        try:
                            if entry.is_symlink():
                                continue
                            st = entry.stat(follow_symlinks=False)
                            if (getattr(st, 'st_file_attributes', 0) or 0) & REPARSE:
                                continue
                            if stat.S_ISDIR(st.st_mode):
                                children.append(str(entry.path))
                            elif stat.S_ISREG(st.st_mode):
                                newfiles.append((str(entry.path), entry.name.casefold(),
                                                 max(0,int(st.st_size)), float(st.st_mtime), gen))
                        except OSError:
                            errors += 1
                        # Commit limited chunks so cancellation never discards all progress.
                        if len(children)+len(newfiles) >= 250:
                            with conn:
                                conn.executemany('INSERT OR IGNORE INTO pending(path,offset) VALUES(?,0)',
                                                 [(p,) for p in children])
                                conn.executemany('INSERT INTO files(path,name_fold,size,mtime,seen) VALUES(?,?,?,?,?) '
                                                 'ON CONFLICT(path) DO UPDATE SET name_fold=excluded.name_fold, '
                                                 'size=excluded.size,mtime=excluded.mtime,seen=excluded.seen', newfiles)
                                conn.execute('UPDATE pending SET offset=? WHERE path=?', (current, folder))
                            writes += len(newfiles)
                            children, newfiles = [], []
                    with conn:
                        conn.executemany('INSERT OR IGNORE INTO pending(path,offset) VALUES(?,0)',
                                         [(p,) for p in children])
                        conn.executemany('INSERT INTO files(path,name_fold,size,mtime,seen) VALUES(?,?,?,?,?) '
                                         'ON CONFLICT(path) DO UPDATE SET name_fold=excluded.name_fold, '
                                         'size=excluded.size,mtime=excluded.mtime,seen=excluded.seen', newfiles)
                        writes += len(newfiles)
                        if completed_folder:
                            conn.execute('DELETE FROM pending WHERE path=?', (folder,))
                        else:
                            conn.execute('UPDATE pending SET offset=? WHERE path=?', (current, folder))
            except OSError:
                errors += 1
                with conn:
                    conn.execute('DELETE FROM pending WHERE path=?', (folder,))
            if progress is not None:
                progress(count)
            if conn.execute('SELECT count(*) FROM files').fetchone()[0] >= MAX_ROWS:
                break
        remaining = conn.execute('SELECT count(*) FROM pending').fetchone()[0]
        prior_errors = int(_meta(conn, 'errors', '0'))
        total_errors = prior_errors + errors
        complete = remaining == 0 and total_errors == 0 and not stop.is_set()
        with conn:
            if complete:
                # Remove stale metadata ONLY after a successful full cycle.
                conn.execute('DELETE FROM files WHERE seen != ?', (gen,))
            _set_meta(conn, 'state', 'complete' if complete else 'partial')
            _set_meta(conn, 'scanned', int(_meta(conn, 'scanned', '0')) + count)
            _set_meta(conn, 'errors', total_errors)
            _set_meta(conn, 'updated', time.strftime('%Y-%m-%d %H:%M:%S'))
    result = status(drive, storage, test_folder=test_folder, identity=identity)
    result['this_run'] = {'entries': count, 'files_recorded': writes,
                          'elapsed_seconds': round(time.monotonic()-started, 2),
                          'cancelled': bool(stop.is_set())}
    return result
