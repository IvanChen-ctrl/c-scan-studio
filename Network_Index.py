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

DB_VERSION = 2
DIR_NAME = 'CScanStudio_NetworkIndex'
REPARSE = 0x400
DEFAULT_SECONDS = 12
DEFAULT_ENTRIES = 12_000
MAX_SECONDS = 60
MAX_ENTRIES = 60_000
MAX_RESULTS = 180
# Per-directory safety ceiling, analogous to Coractive's journal-frame limit.
MAX_DIRECTORY_ENTRIES = 250_000
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
    # Search/status never create an empty DB. PRAGMA query_only forbids writes.
    conn = (sqlite3.connect(str(db), timeout=3.0) if writable else
            sqlite3.connect(db.resolve(strict=True).as_uri() + '?mode=ro',
                            timeout=3.0, uri=True))
    try:
        conn.execute('PRAGMA busy_timeout=3000')
        if not writable:
            conn.execute('PRAGMA query_only=ON')
            return conn
        # Local DB commit: SQLite rollback journal + FULL synchronization.
        # The remote share is NEVER modified.
        conn.execute('PRAGMA journal_mode=DELETE')
        conn.execute('PRAGMA synchronous=FULL')
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY COLLATE NOCASE,
                name_fold TEXT NOT NULL, size INTEGER NOT NULL,
                mtime REAL NOT NULL, seen INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS staged (
                path TEXT PRIMARY KEY COLLATE NOCASE,
                name_fold TEXT NOT NULL, size INTEGER NOT NULL, mtime REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pending (
                path TEXT PRIMARY KEY COLLATE NOCASE,
                offset INTEGER NOT NULL DEFAULT 0
            );
            -- Only completely enumerated directories become staged_dirs.
            -- This preserves empty folders as well as files in the published view.
            CREATE TABLE IF NOT EXISTS staged_dirs (
                path TEXT PRIMARY KEY COLLATE NOCASE
            );
            CREATE TABLE IF NOT EXISTS folders (
                rel TEXT PRIMARY KEY, parent TEXT NOT NULL, name TEXT NOT NULL,
                name_fold TEXT NOT NULL, direct_files INTEGER NOT NULL,
                tree_files INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_folders_parent ON folders(parent);
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_files_size ON files(size DESC);
        ''')
        with conn:
            schema = _meta(conn, 'schema')
            if schema not in ('', '1', '2'):
                raise ValueError('未知索引数据库版本；不会覆盖已有数据。')
            if schema == '1':
                # v1 used unstable os.scandir positional offsets and modified
                # searchable rows during a partial refresh. Keep its existing
                # searchable rows, but never reuse those unsafe resume cursors.
                conn.execute('DELETE FROM pending')
                conn.execute('DELETE FROM staged')
                conn.execute('DELETE FROM staged_dirs')
                if _meta(conn, 'state') != 'complete':
                    _set_meta(conn, 'state', 'unstarted')
                    _set_meta(conn, 'legacy_partial', '1')
                _set_meta(conn, 'schema', DB_VERSION)
            elif not schema:
                _set_meta(conn, 'schema', DB_VERSION)
                _set_meta(conn, 'generation', 0)
                _set_meta(conn, 'state', 'unstarted')
                _set_meta(conn, 'skipped', 0)
            _set_meta(conn, 'migration', 'directory-atomic-v2')
        _ensure_fts(conn)
        return conn
    except BaseException:
        conn.close()
        raise


def _ensure_fts(conn):
    """Optional SQLite FTS5 trigram: Coractive-style fast filename substrings.

    The file table remains the authoritative published snapshot; external
    content FTS is updated by triggers. Older Windows SQLite builds without
    FTS5/trigram keep the existing read-only instr() search behavior.
    """
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='files_fts'").fetchone()
    try:
        conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING "
                     "fts5(name_fold, content='files', content_rowid='rowid', tokenize='trigram')")
    except sqlite3.OperationalError as exc:
        if ('no such module' in str(exc).lower() or
                'no such tokenizer' in str(exc).lower()):
            return False
        raise
    conn.executescript('''
        CREATE TRIGGER IF NOT EXISTS files_fts_insert AFTER INSERT ON files BEGIN
            INSERT INTO files_fts(rowid,name_fold) VALUES(new.rowid,new.name_fold);
        END;
        CREATE TRIGGER IF NOT EXISTS files_fts_delete AFTER DELETE ON files BEGIN
            INSERT INTO files_fts(files_fts,rowid,name_fold)
            VALUES('delete',old.rowid,old.name_fold);
        END;
        CREATE TRIGGER IF NOT EXISTS files_fts_update AFTER UPDATE ON files BEGIN
            INSERT INTO files_fts(files_fts,rowid,name_fold)
            VALUES('delete',old.rowid,old.name_fold);
            INSERT INTO files_fts(rowid,name_fold) VALUES(new.rowid,new.name_fold);
        END;
    ''')
    if not exists:
        conn.execute("INSERT INTO files_fts(files_fts) VALUES('rebuild')")
    return True


def _glob_literal(text):
    """Prevent filename search terms from being interpreted as GLOB syntax."""
    return '*' + text.replace('[', '[[]').replace('*', '[*]').replace('?', '[?]') + '*'


def _meta(conn, key, default=''):
    row = conn.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    return row[0] if row is not None else default


def _set_meta(conn, key, value):
    conn.execute('INSERT INTO meta(key,value) VALUES(?,?) '
                 'ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, str(value)))


def status(drive, storage, *, test_folder=None, identity=None):
    """Read only a local published DB; incomplete work never changes results."""
    db = _database_path(drive, storage, test_folder=test_folder, identity=identity)
    initial = {'drive': drive.upper(), 'storage': storage, 'state': 'missing',
               'files': 0, 'staged': 0, 'pending': 0, 'scanned': 0,
               'errors': 0, 'skipped': 0, 'coverage_errors': 0, 'updated': '', 'complete': False,
               'fts': False, 'folder_ready': False, 'folders': 0,
               'index_path': str(db),
               'note': '尚未建立本地文件名索引；仅用户手动确认后才访问网盘。'}
    if not db.is_file():
        return initial
    try:
        with closing(_connect(db, writable=False)) as conn:
            state = _meta(conn, 'state', 'invalid')
            files = conn.execute('SELECT count(*) FROM files').fetchone()[0]
            pending = conn.execute('SELECT count(*) FROM pending').fetchone()[0]
            staged = (conn.execute('SELECT count(*) FROM staged').fetchone()[0]
                      if conn.execute("SELECT 1 FROM sqlite_master WHERE name='staged'").fetchone() else 0)
            fts = bool(conn.execute("SELECT 1 FROM sqlite_master WHERE name='files_fts'").fetchone())
            folder_ready = _meta(conn, 'folder_catalog', '0') == '1'
            folders = (conn.execute('SELECT count(*) FROM folders').fetchone()[0]
                       if folder_ready else 0)
            initial.update({'state': state, 'files': files, 'staged': staged,
                            'folder_ready': folder_ready, 'folders': folders,
                            'pending': pending, 'fts': fts,
                            'scanned': int(_meta(conn, 'scanned', '0')),
                            'errors': int(_meta(conn, 'errors', '0')),
                            'skipped': int(_meta(conn, 'skipped', '0')),
                            'coverage_errors': int(_meta(conn, 'coverage_errors', '0')),
                            'updated': _meta(conn, 'updated'),
                            'complete': state == 'complete',
                            'note': ('上次已完整发布，扫描后文件可能发生变化。' if state == 'complete'
                                     else '本轮索引尚未发布：旧索引继续可搜索；新文件保留在本地检查点中。')})
            if _meta(conn, 'legacy_partial', '0') == '1':
                initial['note'] += ' 旧版 v1 未完成的索引已保护，请完成一次 v2 重建。'
    except (OSError, sqlite3.DatabaseError, ValueError) as exc:
        initial.update({'state': 'error', 'note': '本地索引不可用：' + str(exc)[:120]})
    return initial


def lookup(drive, storage, filename='', *, limit=MAX_RESULTS, test_folder=None, identity=None):
    """Search a published local snapshot; no remote file I/O, even offline.

    Filename-only trigram FTS (as in Coractive) is optional; fallback always
    works with literal casefolded substring matching for Unicode and symbols.
    """
    if not isinstance(filename, str) or len(filename) > 120 or '\x00' in filename:
        raise ValueError('文件名关键词必须在 120 字以内。')
    if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
        raise ValueError('文件结果数量超出限制。')
    db = _database_path(drive, storage, test_folder=test_folder, identity=identity)
    if not db.is_file():
        return [], status(drive, storage, test_folder=test_folder, identity=identity)
    with closing(_connect(db, writable=False)) as conn:
        term = filename.casefold()
        fts = bool(conn.execute("SELECT 1 FROM sqlite_master WHERE name='files_fts'").fetchone())
        if term and len(term) >= 3 and fts:
            # GLOB can be accelerated by FTS5 trigram; escape the three
            # wildcard syntaxes and retain literal instr() as a guard.
            query = ("SELECT f.path,f.size,f.mtime FROM files AS f "
                     "JOIN files_fts AS t ON f.rowid=t.rowid "
                     "WHERE t.name_fold GLOB ? AND instr(f.name_fold,?)>0 "
                     "ORDER BY f.size DESC,f.path LIMIT ?")
            values = (_glob_literal(term), term, limit)
        else:
            query = "SELECT path,size,mtime FROM files"
            values = []
            if term:
                query += " WHERE instr(name_fold,?)>0"
                values.append(term)
            query += " ORDER BY size DESC,path LIMIT ?"
            values.append(limit)
        rows = [(str(path), int(size), float(mtime)) for path, size, mtime in
                conn.execute(query, values)]
    return rows, status(drive, storage, test_folder=test_folder, identity=identity)


def _relative_folder(root, folder):
    """Convert a verified absolute path into a safe root-relative folder key."""
    try:
        rel = os.path.relpath(folder, root)
    except (OSError, ValueError) as exc:
        raise ValueError('索引目录超出所选盘符范围。') from exc
    if rel in ('.', ''):
        return ''
    rel = rel.replace('\\', '/')
    if rel.startswith('/') or any(p in ('', '.', '..') for p in rel.split('/')):
        raise ValueError('索引目录超出所选盘符范围。')
    return rel


def _publish_folder_catalog(conn, root):
    """Build folder metadata from staged paths; no share reads during publish.

    Memory scales with distinct folder count, not with every indexed file.
    A SQLite transaction around the caller keeps the old catalog immutable on
    disk full, crash or invalid relative path.
    """
    cache = {'': ['', '', '', 0, 0]}

    def ensure(rel):
        # Iterative: deeply nested folders cannot overflow Python's recursion.
        missing = []
        while rel not in cache:
            missing.append(rel)
            rel = rel.rpartition('/')[0]
        for item in reversed(missing):
            parent = item.rpartition('/')[0]
            name = item.rsplit('/', 1)[-1]
            cache[item] = [parent, name, name.casefold(), 0, 0]

    for (folder,) in conn.execute('SELECT path FROM staged_dirs'):
        ensure(_relative_folder(root, folder))
    for (path,) in conn.execute('SELECT path FROM staged'):
        rel = _relative_folder(root, os.path.dirname(path))
        ensure(rel)
        cache[rel][3] += 1
        while True:
            cache[rel][4] += 1
            if not rel:
                break
            rel = cache[rel][0]
    conn.execute('DELETE FROM folders')
    conn.executemany('INSERT INTO folders(rel,parent,name,name_fold,direct_files,tree_files) '
                     'VALUES(?,?,?,?,?,?)', ((rel, *data) for rel, data in cache.items()))


def scan(drive, storage, stop, *, max_seconds=DEFAULT_SECONDS, max_entries=DEFAULT_ENTRIES,
         progress=None, test_root=None, test_folder=None, identity=None):
    """Explicit, crash-safe directory-atomic metadata scan.

    Mirrors Coractive v1.21's per-directory durable checkpoint principle.
    Never resume from an os.scandir positional offset: remote directory
    enumeration order can change between SMB reconnects. A directory is
    committed to local staging in ONE transaction only after complete listing.
    Per-run time/entry budgets are soft boundaries *between* directories; a
    large single directory can exceed a budget, so cancellation is checked on
    each entry and SMB blocking I/O is not interruptible by Python.
    Searchable rows are swapped atomically only on finished traversal.
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
        raise ValueError('无法确认映射盘 UNC 目标；不能混合不同共享盘索引。')
    db = _database_path(drive, storage, test_folder=test_folder,
                        identity=mapping_id if test_root is None else identity, create=True)
    started = time.monotonic()
    entries, errors, writes = 0, 0, 0
    with closing(_connect(db, writable=True)) as conn:
        if int(_meta(conn, 'schema', '0')) != DB_VERSION:
            raise ValueError('未知索引数据库版本；不会覆盖旧索引。')
        previous_state = _meta(conn, 'state', 'unstarted')
        previous_root = _meta(conn, 'root')
        pending = conn.execute('SELECT 1 FROM pending LIMIT 1').fetchone()
        # A complete or failed older generation starts fresh; while scanning,
        # only the staging table is written and the published files stay stable.
        if (previous_state != 'partial' or
                _meta(conn, 'folder_journal', '0') != '1' or
                (not pending and int(_meta(conn, 'errors', '0')) > 0)):
            generation = int(_meta(conn, 'generation', '0')) + 1
            with conn:
                conn.execute('DELETE FROM pending')
                conn.execute('DELETE FROM staged')
                conn.execute('DELETE FROM staged_dirs')
                conn.execute('INSERT INTO pending(path,offset) VALUES(?,0)', (str(root),))
                _set_meta(conn, 'folder_journal', 1)
                _set_meta(conn, 'generation', generation)
                _set_meta(conn, 'root', str(root))
                _set_meta(conn, 'scanned', 0)
                _set_meta(conn, 'errors', 0)
                _set_meta(conn, 'skipped', 0)
                _set_meta(conn, 'coverage_errors', 0)
                _set_meta(conn, 'state', 'partial')
        else:
            generation = int(_meta(conn, 'generation', '0'))
            if os.path.normcase(previous_root) != os.path.normcase(str(root)):
                raise ValueError('网络盘根目录变化；不能混合检查点。')
        interrupted = False
        while not stop.is_set() and entries < max_entries and time.monotonic()-started < max_seconds:
            row = conn.execute('SELECT path FROM pending ORDER BY rowid DESC LIMIT 1').fetchone()
            if row is None:
                break
            folder = row[0]
            if test_root is None:
                drives.select_network_drive(drive.upper())
                if _mapping_identity(drive.upper()) != mapping_id:
                    raise ValueError('检测到共享盘重映射；停止索引并保留检查点。')
            # A whole directory is one local DB commit, never an offset cursor.
            children, files = [], []
            skipped_dir = 0
            errors_dir = 0
            directory_entries = 0
            try:
                info = os.lstat(folder)
                if not stat.S_ISDIR(info.st_mode) or (getattr(info,'st_file_attributes',0) or 0) & REPARSE:
                    raise OSError('目录无法安全访问或是重解析点')
                with os.scandir(folder) as iterator:
                    for item in iterator:
                        if stop.is_set():
                            interrupted = True
                            break
                        entries += 1
                        directory_entries += 1
                        if directory_entries > MAX_DIRECTORY_ENTRIES:
                            raise OSError('单一目录条目超过安全内存上限，请联系管理员分目录索引')
                        if item.is_symlink():
                            skipped_dir += 1
                            continue
                        try:
                            st = item.stat(follow_symlinks=False)
                        except OSError:
                            # One unreadable entry does not invalidate all of its
                            # accessible siblings; publish with partial coverage.
                            errors_dir += 1
                            continue
                        if (getattr(st, 'st_file_attributes', 0) or 0) & REPARSE:
                            skipped_dir += 1
                            continue
                        if stat.S_ISDIR(st.st_mode):
                            children.append(str(item.path))
                        elif stat.S_ISREG(st.st_mode):
                            files.append((str(item.path), item.name.casefold(),
                                          max(0, int(st.st_size)), float(st.st_mtime)))
                        else:
                            skipped_dir += 1
                if interrupted or stop.is_set():
                    interrupted = True
                    break
                with conn:
                    conn.executemany('INSERT OR IGNORE INTO pending(path,offset) VALUES(?,0)',
                                     ((name,) for name in children))
                    conn.executemany('INSERT INTO staged(path,name_fold,size,mtime) VALUES(?,?,?,?) '
                                     'ON CONFLICT(path) DO UPDATE SET '
                                     'name_fold=excluded.name_fold,size=excluded.size,mtime=excluded.mtime', files)
                    conn.execute('INSERT OR IGNORE INTO staged_dirs(path) VALUES(?)', (folder,))
                    conn.execute('DELETE FROM pending WHERE path=?', (folder,))
                    _set_meta(conn, 'skipped', int(_meta(conn, 'skipped', '0')) + skipped_dir)
                    _set_meta(conn, 'coverage_errors',
                              int(_meta(conn, 'coverage_errors', '0')) + errors_dir)
                writes += len(files)
            except PermissionError as exc:
                # ACL-denied non-root subtree: record honest incomplete
                # coverage, but continue with accessible siblings (Coractive).
                if os.path.normcase(folder) != os.path.normcase(str(root)):
                    with conn:
                        conn.execute('DELETE FROM pending WHERE path=?', (folder,))
                        _set_meta(conn, 'coverage_errors',
                                  int(_meta(conn, 'coverage_errors', '0')) + 1)
                        _set_meta(conn, 'last_error', 'PermissionError: ' + str(exc)[:100])
                    continue
                errors += 1
                with conn:
                    _set_meta(conn, 'last_error', str(exc)[:100])
                break
            except OSError as exc:
                # Never dequeue a directory that could not be read completely:
                # a subsequent user-authorized scan can retry it.
                errors += 1
                with conn:
                    _set_meta(conn, 'last_error', type(exc).__name__ + ': ' + str(exc)[:100])
                break
            if progress is not None:
                progress(entries)
        remaining = conn.execute('SELECT count(*) FROM pending').fetchone()[0]
        # Staging is published atomically. SQLite rolls back all changes on
        # power loss/disk-full, keeping the previous complete snapshot usable.
        finished = remaining == 0 and errors == 0 and not stop.is_set() and not interrupted
        skipped_total = int(_meta(conn, 'skipped', '0'))
        coverage_errors = int(_meta(conn, 'coverage_errors', '0'))
        with conn:
            if finished:
                # Folder names/counts and files are published in the SAME local
                # transaction; neither a partial nor a failed refresh is shown.
                _publish_folder_catalog(conn, str(root))
                conn.execute('DELETE FROM files')
                conn.execute('INSERT INTO files(path,name_fold,size,mtime,seen) '
                             'SELECT path,name_fold,size,mtime,? FROM staged', (generation,))
                conn.execute('DELETE FROM staged')
                conn.execute('DELETE FROM staged_dirs')
                _set_meta(conn, 'folder_catalog', 1)
                _set_meta(conn, 'state', 'complete' if skipped_total == 0 and coverage_errors == 0
                          else 'partial_coverage')
                _set_meta(conn, 'updated', time.strftime('%Y-%m-%d %H:%M:%S'))
                _set_meta(conn, 'legacy_partial', 0)
            else:
                _set_meta(conn, 'state', 'partial')
            _set_meta(conn, 'scanned', int(_meta(conn, 'scanned', '0')) + entries)
            _set_meta(conn, 'errors', errors)
    result = status(drive, storage, test_folder=test_folder,
                    identity=mapping_id if test_root is None else identity)
    result['this_run'] = {'entries': entries, 'files_recorded': writes,
                          'elapsed_seconds': round(time.monotonic()-started, 2),
                          'cancelled': bool(stop.is_set()),
                          'budget_soft_per_directory': True}
    return result
