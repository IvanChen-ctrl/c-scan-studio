#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read-only, paginated search and folder views over an approved local snapshot.

Inspired by the *behavior* of CoractiveFileFinder v1.21, not a code copy.
Never enumerate mapped drives, open shared files, download content or modify DBs.
All queries operate on files/folders that were published by Network_Index.scan.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import ntpath
import os
import re
import sqlite3

import Network_Index as index

PAGE_LIMIT = 100
MAX_PAGE = 200
MAX_OFFSET = 1_000_000
MAX_QUERY = 450
MAX_FOLDER = 2048


@dataclass(frozen=True)
class Filter:
    names: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()
    extension: str = ''
    kind: str = ''


def _terms(text):
    if type(text) is not str or len(text) > MAX_QUERY or any(c in text for c in '\x00\r\n'):
        raise ValueError('高级查询过长或包含无效控制字符（最多 450 字）。')
    tokens, word, quoted = [], [], False
    for c in text:
        if c == '"':
            quoted = not quoted
        elif c.isspace() and not quoted:
            if word:
                tokens.append(''.join(word))
                word.clear()
        else:
            word.append(c)
    if quoted:
        raise ValueError('高级查询的双引号未闭合。')
    if word:
        tokens.append(''.join(word))
    return tokens


def parse_query(query):
    """Literal name fragments, ext:, path:, name:, type: and -exclusions."""
    names, paths, excluded, extension, kind = [], [], [], '', ''
    for term in _terms(query):
        key = term.casefold()
        if key.startswith('ext:'):
            ext = key[4:].lstrip('.')
            if not ext or len(ext) > 30 or any(c in ext for c in r'\/\\:*?"<>|'):
                raise ValueError('扩展名过滤无效。示例：ext:pdf')
            if extension and extension != ext:
                raise ValueError('不能同时指定不同的扩展名。')
            extension = ext
        elif key.startswith('name:'):
            if not key[5:]:
                raise ValueError('name: 后必须输入文件名片段。')
            names.append(key[5:])
        elif key.startswith('path:'):
            if not key[5:]:
                raise ValueError('path: 后必须输入目录片段。')
            paths.append(key[5:].replace('\\', '/'))
        elif key.startswith('type:'):
            new = {'file': 'file', 'files': 'file', 'folder': 'folder',
                   'dir': 'folder', 'directory': 'folder'}.get(key[5:])
            if not new:
                raise ValueError('type: 只允许 file 或 folder。')
            if kind and kind != new:
                raise ValueError('文件与文件夹类型过滤冲突。')
            kind = new
        elif key.startswith('-') and len(key) > 1:
            excluded.append(key[1:])
        elif key:
            names.append(key)
    return Filter(tuple(names), tuple(paths), tuple(excluded), extension, kind)


def _bounds(offset, limit):
    if type(offset) is not int or not 0 <= offset <= MAX_OFFSET:
        raise ValueError('分页偏移无效（0～1,000,000）。')
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise ValueError('单页文件数量必须在 1～200。')
    return offset, limit


def _folder_name(rel):
    if type(rel) is not str or len(rel) > MAX_FOLDER or '\x00' in rel:
        raise ValueError('文件夹标识无效。')
    if not rel:
        return ''
    # Browser uses index-relative forward slash paths, not UNC or drive paths.
    if rel.startswith(('/', '\\')) or ':' in rel or '\\' in rel or any(
            c in rel for c in '\r\n') or any(p in ('', '.', '..') for p in rel.split('/')):
        raise ValueError('只能浏览已索引的相对文件夹，不能指定任意网盘路径。')
    return rel


def _fold_path(text):
    return text.replace('\\', '/').casefold() if isinstance(text, str) else ''


def _connect(drive, storage, test_folder=None, identity=None):
    path = index._database_path(drive, storage, test_folder=test_folder, identity=identity)
    if not path.is_file():
        return None
    return index._connect(path, writable=False)


def _meta(conn):
    state = index._meta(conn, 'state', 'invalid')
    return {'state': state, 'updated': index._meta(conn, 'updated', ''),
            'partial': state != 'complete',
            'folder_ready': index._meta(conn, 'folder_catalog', '0') == '1'}


def _conditions(f: Filter, alias='f'):
    clauses, params = [], []
    for value in f.names:
        clauses.append(f'instr({alias}.name_fold,?)>0')
        params.append(value)
    for value in f.paths:
        clauses.append(f'instr(cscan_fold_path({alias}.path),?)>0')
        params.append(value)
    for value in f.excluded:
        clauses.append(f'(instr({alias}.name_fold,?)=0 AND '
                       f'instr(cscan_fold_path({alias}.path),?)=0)')
        params.extend((value, value))
    if f.extension:
        # instr/suffix test is literal, never LIKE/regex with user expressions.
        clauses.append(f'substr({alias}.name_fold,-length(?))=?')
        suffix = '.' + f.extension
        params.extend((suffix, suffix))
    return clauses, params


def _db_fold(conn):
    # SQLite NOCASE/LOWER only handle ASCII: casefold corrects Unicode paths.
    conn.create_function('cscan_fold_path', 1, _fold_path, deterministic=True)


def _search_selection(conn, f):
    """Use optional FTS5 trigram as candidate lookup, then literal SQL filters."""
    joins, clauses, params = '', [], []
    if f.names and index._glob_literal and any(len(x) >= 3 for x in f.names):
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='files_fts'").fetchone():
            try:
                # A database may be copied to an older Python build that lacks
                # FTS5/trigram. Its ordinary files table remains searchable.
                conn.execute('SELECT rowid FROM files_fts LIMIT 0')
            except sqlite3.OperationalError:
                pass
            else:
                term = next(x for x in f.names if len(x) >= 3)
                joins = ' JOIN files_fts AS t ON f.rowid=t.rowid '
                clauses.append('t.name_fold GLOB ?')
                params.append(index._glob_literal(term))
    remaining, rest = _conditions(f)
    clauses.extend(remaining)
    params.extend(rest)
    return joins, clauses, params


def _page(conn, base, where, params, ordering, offset, limit, metadata, *, columns):
    full_where = ' WHERE ' + ' AND '.join(where) if where else ''
    # Start a read transaction so COUNT and result page describe one snapshot.
    conn.execute('BEGIN')
    try:
        total = conn.execute('SELECT count(*) ' + base + full_where, params).fetchone()[0]
        rows = conn.execute('SELECT ' + columns + ' ' + base + full_where +
                            ' ORDER BY ' + ordering + ' LIMIT ? OFFSET ?',
                            [*params, limit, offset]).fetchall()
        conn.execute('COMMIT')
    except BaseException:
        conn.execute('ROLLBACK')
        raise
    return {'total': total, 'offset': offset, 'limit': limit,
            'has_more': offset + len(rows) < total, 'rows': rows, **metadata}


def search(drive, storage, query='', offset=0, limit=PAGE_LIMIT,
           *, test_folder=None, identity=None):
    """Search every published file, not just the first 180 candidates."""
    offset, limit = _bounds(offset, limit)
    f = parse_query(query)
    if f.kind == 'folder':
        raise ValueError('搜索文件夹请使用文件夹浏览页。')
    conn = _connect(drive, storage, test_folder=test_folder, identity=identity)
    if conn is None:
        return {'rows': [], 'total': 0, 'offset': offset, 'limit': limit,
                'has_more': False, 'state': 'missing', 'updated': '', 'partial': True}
    with closing(conn):
        _db_fold(conn)
        meta = _meta(conn)
        joins, clauses, params = _search_selection(conn, f)
        result = _page(conn, 'FROM files AS f' + joins, clauses, params,
                       'f.size DESC, f.path COLLATE NOCASE, f.path',
                       offset, limit, meta, columns='f.path,f.size,f.mtime')
    result['rows'] = [dict(path=path, name=ntpath.basename(path.replace('/', '\\')),
                           size=int(size), mtime=float(mtime))
                      for path, size, mtime in result['rows']]
    return result


def folder_children(drive, storage, folder='', query='', offset=0, limit=PAGE_LIMIT,
                    *, test_folder=None, identity=None):
    """Page direct child folders of an indexed relative directory (never SMB)."""
    offset, limit = _bounds(offset, limit)
    folder = _folder_name(folder)
    f = parse_query(query)
    if f.kind == 'file':
        raise ValueError('文件夹筛选不接受 type:file。')
    if f.extension:
        raise ValueError('文件夹不能按文件扩展名过滤。')
    conn = _connect(drive, storage, test_folder=test_folder, identity=identity)
    if conn is None:
        return {'rows': [], 'total': 0, 'offset': offset, 'limit': limit,
                'has_more': False, 'state': 'missing', 'folder': folder,
                'folder_ready': False, 'partial': True}
    with closing(conn):
        _db_fold(conn)
        metadata = _meta(conn)
        if not metadata['folder_ready']:
            raise ValueError('旧索引尚未建立文件夹目录表；请重新执行一次网盘索引扫描。')
        exact = conn.execute('SELECT rel FROM folders WHERE rel=?', (folder,)).fetchone()
        if exact is None:
            raise ValueError('指定文件夹不在已发布索引中，无法访问。')
        where = ['g.parent=?', "g.rel<>''"]
        params = [folder]
        for term in f.names:
            where.append('instr(g.name_fold,?)>0')
            params.append(term)
        for term in f.paths:
            where.append('instr(cscan_fold_path(g.rel),?)>0')
            params.append(term)
        for term in f.excluded:
            where.append('instr(g.name_fold,?)=0 AND instr(cscan_fold_path(g.rel),?)=0')
            params.extend((term, term))
        output = _page(conn, 'FROM folders AS g', where, params,
                       'g.name_fold, g.rel', offset, limit, metadata,
                       columns='g.rel,g.name,g.direct_files,g.tree_files')
    output['folder'] = folder
    output['rows'] = [{'rel': rel, 'name': name, 'direct_files': int(direct),
                       'indexed_files': int(tree), 'nested_files': int(tree-direct)}
                      for rel, name, direct, tree in output['rows']]
    return output


def folder_files(drive, storage, folder='', query='', offset=0, limit=PAGE_LIMIT,
                 recursive=True, *, test_folder=None, identity=None):
    """List indexed folder contents, optionally only immediate files."""
    offset, limit = _bounds(offset, limit)
    folder = _folder_name(folder)
    if type(recursive) is not bool:
        raise ValueError('递归搜索选项无效。')
    f = parse_query(query)
    if f.kind == 'folder':
        raise ValueError('文件结果页不支持 type:folder。')
    conn = _connect(drive, storage, test_folder=test_folder, identity=identity)
    if conn is None:
        return {'rows': [], 'total': 0, 'offset': offset, 'limit': limit,
                'has_more': False, 'state': 'missing', 'folder': folder,
                'folder_ready': False, 'partial': True}
    with closing(conn):
        _db_fold(conn)
        metadata = _meta(conn)
        if not metadata['folder_ready']:
            raise ValueError('索引缺少文件夹目录表；请手动重新扫描。')
        rel = conn.execute('SELECT rel FROM folders WHERE rel=?', (folder,)).fetchone()
        if rel is None:
            raise ValueError('指定文件夹不在已发布索引中，无法访问。')
        root = index._meta(conn, 'root')
        if not root:
            raise ValueError('索引缺少根目录元数据，请重新扫描。')
        prefix = os.path.join(root, *folder.split('/')) if folder else root
        prefix = prefix.rstrip('\\/') + os.sep
        joins, where, params = _search_selection(conn, f)
        # Primary key on files.path makes this an indexable prefix range.
        # The bound is read from the published folder table, never raw user input.
        where.extend(['f.path >= ? COLLATE NOCASE', 'f.path < ? COLLATE NOCASE'])
        params.extend((prefix, prefix + '\uffff'))
        if not recursive:
            where.append('instr(substr(f.path,length(?)+1),?)=0')
            params.extend((prefix, os.sep))
        result = _page(conn, 'FROM files AS f' + joins, where, params,
                       'f.name_fold, f.path COLLATE NOCASE, f.path',
                       offset, limit, metadata, columns='f.path,f.size,f.mtime')
    result['folder'] = folder
    result['recursive'] = recursive
    result['rows'] = [dict(path=path, name=ntpath.basename(path.replace('/', '\\')),
                           size=int(size), mtime=float(mtime))
                      for path, size, mtime in result['rows']]
    return result
