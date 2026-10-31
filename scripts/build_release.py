#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic, reviewable source-only distribution. No personal files/EXEs/ZIPs."""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import os
import stat
import sys
import zipfile
from pathlib import Path

VERSION = '3.5.0-beta.1'
ROOT = Path(__file__).resolve().parents[1]
PREFIX = f'C_Scan_Studio_v{VERSION}'
SOURCE_NAMES = frozenset({
    '00_启动C-Scan智能清理与安全中心.bat', 'Advanced_Disk_Studio.py',
    'C_Drive_Cleanup.py', 'Everything_Official_Manager.py',
    'Drive_Inspector.py',
    'Security_Audit.py', 'Share_Offline_Bundle.py', 'Unified_Tools.py',
    'LICENSE', 'NOTICE.md', 'README.md', 'SECURITY.md', 'CONTRIBUTING.md',
    '.gitignore',
})
SOURCE_DIRS = frozenset({
    'internal', 'ui', 'LICENSES', 'Tools', 'Runtime_Offline',
    'docs', 'tests', 'tests_v3', 'tests_v31', 'tests_v32', 'tests_v33',
    'scripts', '.github', 'tests_v34', 'tests_v35',
})
EXCLUDES = frozenset({
    '.git', '__pycache__', '_runtime', 'Installer_Files', 'Official_Offline',
    'Everything', 'ES', 'docs/historical', 'logs', 'Reports', 'dist',
})
ALLOWED_SUFFIX = frozenset({'.py', '.html', '.md', '.txt', '.cmd', '.bat',
                            '.yml', '.yaml', '.json', '.ini', '.csv', '.png', '.ps1', '.js'})
DANGEROUS_SUFFIX = frozenset({'.exe', '.dll', '.msi', '.zip', '.whl', '.pfx',
                              '.pem', '.key', '.env', '.conda', '.p12'})
DATE = (2026, 10, 31, 0, 0, 0)


def eligible(root: Path) -> list[tuple[str, bytes]]:
    """Only explicitly enumerated source top-level names and subdirectories."""
    found = []
    for item in sorted(root.rglob('*')):
        rel = item.relative_to(root)
        if any(p in EXCLUDES or p in ('historical',) or p.startswith('.env') for p in rel.parts):
            continue
        if rel.parts[0] not in SOURCE_DIRS and rel.as_posix() not in SOURCE_NAMES:
            continue
        if item.is_symlink() or (getattr(item.lstat(), 'st_file_attributes', 0) & 0x400):
            raise RuntimeError('Dangerous junction/symlink in source: ' + rel.as_posix())
        if not item.is_file():
            continue
        if item.suffix.lower() in DANGEROUS_SUFFIX:
            raise RuntimeError('Executable/archive unexpectedly in source: ' + rel.as_posix())
        if not (item.suffix.lower() in ALLOWED_SUFFIX or rel.name in SOURCE_NAMES or rel.name == '.gitignore'):
            raise RuntimeError('Unexpected source file type: ' + rel.as_posix())
        if item.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError('Unexpected huge source file: ' + rel.as_posix())
        name = rel.as_posix()
        if name == 'FILE_INTEGRITY_SHA256.csv' or name == 'SHA256SUMS.txt':
            continue
        found.append((name, item.read_bytes()))
    for required in SOURCE_NAMES:
        if required not in (name for name, _ in found):
            raise RuntimeError('Required source missing: ' + required)
    return sorted(found)


def manifest_bytes(files):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf, lineterminator='\n')
    writer.writerow(('Path', 'SHA256'))
    for name, data in files:
        writer.writerow((name, hashlib.sha256(data).hexdigest()))
    return ('\ufeff' + buf.getvalue()).encode('utf-8')


def make_zip(files, manifest, dst):
    with zipfile.ZipFile(dst, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=8, strict_timestamps=True) as archive:
        for name, data in [*files, ('FILE_INTEGRITY_SHA256.csv', manifest)]:
            info = zipfile.ZipInfo(PREFIX + '/' + name, DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=8)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--outdir', type=Path, default=ROOT.parent)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    folder = args.outdir.resolve()
    if root == folder or root in folder.parents:
        raise SystemExit('Choose outdir OUTSIDE source root to avoid writing arbitrary build artifacts into source.')
    files = eligible(root)
    manifest = manifest_bytes(files)
    # Keep root's manifest current for local GUI; never rely on it as a trust anchor.
    (root / 'FILE_INTEGRITY_SHA256.csv').write_bytes(manifest)
    folder.mkdir(parents=True, exist_ok=True)
    archive = folder / f'C_Scan_Studio_v{VERSION}_Source.zip'
    make_zip(files, manifest, archive)
    with zipfile.ZipFile(archive) as container:
        if container.testzip() is not None:
            raise RuntimeError('ZIP CRC check failed')
        if len(container.namelist()) != len(files) + 1:
            raise RuntimeError('ZIP file count mismatch')
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum_path = folder / (archive.name + '.sha256.txt')
    checksum_path.write_text(checksum + '  ' + archive.name + '\n', encoding='ascii')
    print('Release ZIP:', archive)
    print('SHA-256:', checksum)
    print('Source files:', len(files))
    print('SHA256 file:', checksum_path)
    print('No bundled EXE/ZIP or cached/private model/data files.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
