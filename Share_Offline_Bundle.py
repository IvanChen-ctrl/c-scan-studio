#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build a shareable source+official-vendor-ZIP package with checksums.

Includes only the files on the reviewed SHA256 source manifest and the TWO
unchanged, pinned, vendor ZIPs. Excludes user reports, models, settings, logs,
private Python, hidden files, arbitrary EXE, histories and personal paths.
The friend must supply Python or allow official CPython bootstrap on first run.
"""
from __future__ import annotations

import csv
import hashlib
import io
import zipfile
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import Everything_Official_Manager as vendor


def prepare_share(root=HERE, output=None):
    root = Path(root)
    manifest = root / 'FILE_INTEGRITY_SHA256.csv'
    if not manifest.is_file():
        raise RuntimeError('未发现原始源码清单，无法安全导出')
    with manifest.open('r', encoding='utf-8-sig', newline='') as stream:
        entries = list(csv.DictReader(stream))
    if not entries:
        raise RuntimeError('源码清单为空')
    checked = []
    for item in entries:
        relative = Path(item['Path'])
        if (relative.is_absolute() or '..' in relative.parts or relative.parts[0] in ('.git', '_runtime')):
            raise RuntimeError('清单包含不安全文件路径')
        target = root / relative
        if target.is_symlink() or not target.is_file() or vendor.hash_file(target) != item['SHA256'].lower():
            raise RuntimeError('源码有变化，拒绝制作可信分发包：' + str(relative))
        checked.append((target, relative.as_posix()))
    checked.append((manifest, 'FILE_INTEGRITY_SHA256.csv'))
    specs = vendor.files_for_arch(vendor.architecture())
    for spec in specs:
        path = root / 'Tools' / 'Official_Offline' / spec['name']
        vendor.verify_archive(path, spec)
        checked.append((path, 'Tools/Official_Offline/' + spec['name']))
    archive_output = Path(output) if output else root.parent / 'C_Scan_Studio_v3.4.0-beta.1_Offline_Everything_For_Friends.zip'
    if root.resolve() in archive_output.resolve().parents:
        raise RuntimeError('导出 ZIP 不能放到源码目录内部')
    archive_output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=7) as container:
        for path, name in sorted(checked, key=lambda x: x[1]):
            container.write(path, 'C_Scan_Studio_v3.4.0-beta.1/' + name)
    outer_hash = vendor.hash_file(archive_output)
    detached = archive_output.with_name(archive_output.name + '.sha256.txt')
    detached.write_text(outer_hash + '  ' + archive_output.name + '\n', encoding='ascii')
    print('发布包：' + str(archive_output))
    print('官方 Everything 和 ES ZIP 已完整保留并校验 SHA256。')
    print('整包 SHA256：' + outer_hash)
    print('校验文件：' + str(detached))
    print('注意：整包 SHA256 应通过独立可信渠道分享给朋友，否则攻击者也可同时替换清单和文件。')
    print('注意：本工具不含 Python 可执行环境；没有 Python 的电脑首次需联网或手动提供官方 Python。')
    return archive_output


if __name__ == '__main__':
    try:
        prepare_share()
    except Exception as exc:
        print('无法生成离线包：' + str(exc))
        raise SystemExit(3)
