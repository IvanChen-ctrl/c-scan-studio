#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent *local integrity* check; no network and no file deletion.

IMPORTANT: The manifest in the same distribution is not a trust anchor.
Users must compare an externally supplied whole-release ZIP SHA-256 and
consult third-party scanners themselves before trusting any publisher.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
MANIFEST = 'FILE_INTEGRITY_SHA256.csv'
MAX_FILES = 2000
MAX_FILE_SIZE = 128 * 1024 * 1024
SERVICES = (
    ('VirusTotal', 'https://www.virustotal.com/gui/home/upload'),
    ('MetaDefender Cloud', 'https://metadefender.opswat.com/'),
    ('Jotti', 'https://virusscan.jotti.org/zh-cn'),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def valid_relpath(raw: str) -> bool:
    if not isinstance(raw, str) or not raw or '\\' in raw or ':' in raw or raw.startswith('/'):
        return False
    parts = PurePosixPath(raw).parts
    return bool(parts) and not any(p in ('.', '..', '') for p in raw.split('/'))


def safe_file(root: Path, raw: str) -> Path | None:
    if not valid_relpath(raw):
        return None
    current = root
    for part in raw.split('/'):
        current = current / part
        try:
            st = os.lstat(current)
            if stat.S_ISLNK(st.st_mode) or (getattr(st, 'st_file_attributes', 0) & 0x400):
                return None
        except FileNotFoundError:
            continue
        except OSError:
            return None
    return current


def audit(root: Path = ROOT) -> dict:
    root = Path(root).absolute()
    manifest = root / MANIFEST
    result = {
        'title': 'C-Scan Studio 本地文件一致性检查（不是无毒认证）',
        'checked_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'network_requests': 0,
        'scanned_for_malware': False,
        'manifest_sha256': None,
        'checked': 0, 'matching': 0, 'changed': [], 'missing': [],
        'unsafe_paths': [], 'errors': [], 'status': 'unverified',
        'disclaimer': '包内清单及校验代码可能同时被替换，且未列入清单的新增文件不在本检查范围。必须独立核对发行版 ZIP SHA-256；本地哈希匹配不等于恶意软件检测通过。',
        'online_services': [{'name': name, 'url': url} for name, url in SERVICES],
    }
    if not manifest.is_file() or manifest.is_symlink():
        result['errors'].append('完整性清单缺失或为符号链接')
        result['status'] = 'error'
        return result
    try:
        result['manifest_sha256'] = sha256_file(manifest)
        if manifest.stat().st_size > 256 * 1024:
            raise ValueError('完整性清单超过安全大小上限')
        with manifest.open('r', encoding='utf-8-sig', newline='') as handle:
            records = list(csv.DictReader(handle))
        if len(records) > MAX_FILES or not records:
            raise ValueError('清单为空或文件数超过上限')
        seen = set()
        for row in records:
            raw = (row.get('Path') or '').strip()
            digest = (row.get('SHA256') or '').strip().lower()
            if not valid_relpath(raw) or raw.casefold() in seen or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                result['unsafe_paths'].append(raw[:220])
                continue
            seen.add(raw.casefold())
            target = safe_file(root, raw)
            if target is None:
                result['unsafe_paths'].append(raw[:220])
                continue
            result['checked'] += 1
            try:
                st = os.lstat(target)
                if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_SIZE:
                    result['errors'].append('文件类型或大小异常：' + raw)
                elif sha256_file(target) == digest:
                    result['matching'] += 1
                else:
                    result['changed'].append(raw)
            except FileNotFoundError:
                result['missing'].append(raw)
            except OSError:
                result['errors'].append('读取失败：' + raw)
    except (OSError, ValueError, UnicodeError, csv.Error) as exc:
        result['errors'].append('读取清单失败：' + str(exc)[:240])
    ok = (result['checked'] > 0 and result['checked'] == result['matching']
          and not result['changed'] and not result['missing']
          and not result['unsafe_paths'] and not result['errors'])
    result['status'] = 'matched' if ok else 'mismatch'
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='只核验包内清单，不清理、不联网、不扫描病毒')
    parser.add_argument('--json', action='store_true', help='在控制台打印 JSON')
    parser.add_argument('--output', help='将 JSON 报告写到指定文件')
    args = parser.parse_args(argv)
    report = audit()
    if args.json or args.output:
        data = json.dumps(report, ensure_ascii=False, indent=2)
        if args.output:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(data, encoding='utf-8')
            print('报告文件:', out)
        if args.json:
            print(data)
    else:
        print('本地完整性:', report['status'])
        print('比对文件:', report['checked'], '| 匹配:', report['matching'])
        for field in ('changed', 'missing', 'unsafe_paths', 'errors'):
            for value in report[field]:
                print('  ' + field + ': ' + value)
        print(report['disclaimer'])
    return 0 if report['status'] == 'matched' else 4


if __name__ == '__main__':
    raise SystemExit(main())
