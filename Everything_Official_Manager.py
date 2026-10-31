#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pinned, opt-in Everything 1.4 + ES CLI portable acquisition.

No arbitrary URL inputs; only vendor downloads with independently pinned SHA256.
No registry, service, firewall, PATH or global policy modifications are made here.
Offline vendor ZIPs can be supplied in Tools/Official_Offline; original archives
are preserved for later transparent redistribution with third-party notices.

Third-party executables are NOT included in the source-only C-Scan ZIP.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable, Optional

HERE = Path(__file__).resolve().parent
VENDOR_VERSION = 'Everything 1.4.1.1032 / ES CLI 1.1.0.37'
TRUSTED_HOSTS = frozenset({'www.voidtools.com', 'voidtools.com'})
MAX_ARCHIVE_BYTES = 15 * 1024 * 1024
MAX_MEMBER_BYTES = 15 * 1024 * 1024
MANIFEST_NAME = 'CScan_Verified_Vendor.json'

# Fixed versions, original HTTPS URLs, and SHA-256 confirmed independently
# against Scoop / WSCC / Chocolatey published package manifests.
SPECS = {
    'x64': (
        ('everything', 'Everything-1.4.1.1032.x64.zip',
         '698df475ec44e638f66f1b6a32d28fea613cec78d3b6310e6abe53431eeb940c'),
        ('es', 'ES-1.1.0.37.x64.zip',
         '7a57670d9152068d05876c58858c82fe6d3915a9df2c819f4de8801e2929d3a7')),
    'x86': (
        ('everything', 'Everything-1.4.1.1032.x86.zip',
         '156db5beb747d69470518a7b9b55af11efc4d3285ddb7cc013c0cc13ced5f237'),
        ('es', 'ES-1.1.0.37.x86.zip',
         '35f8fe8c92b44d834cf51239ee345927e44d33c6c86d64b756990b066fa0da47')),
}


def architecture():
    machine = platform.machine().lower()
    if machine in ('amd64', 'x86_64', 'x64'):
        return 'x64'
    if machine in ('x86', 'i386', 'i686'):
        return 'x86'
    raise RuntimeError('该自动安装器目前支持 Windows x64/x86。ARM64 请从 voidtools 官方安装并配合 ES CLI。')


def reject_reparse_chain(root, destination):
    """Reject junctions/symlinks inside the tool-owned installation tree."""
    root = Path(root)
    destination = Path(destination)
    relative = destination.relative_to(root)  # raises for traversal/outside paths
    current = root
    parts = (current,) + tuple(current / Path(*relative.parts[:idx])
                                for idx in range(1, len(relative.parts) + 1))
    for current in parts:
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise RuntimeError('目标目录含符号链接或联接点，已拒绝：' + str(current))


def hash_file(path, chunk_bytes=1024 * 1024):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(chunk_bytes), b''):
            h.update(block)
    return h.hexdigest()


def files_for_arch(arch):
    if arch not in SPECS:
        raise ValueError('Unsupported architecture')
    return [{'kind': kind, 'name': filename, 'sha256': digest,
             'url': 'https://www.voidtools.com/' + filename}
            for kind, filename, digest in SPECS[arch]]


class VendorRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != 'https' or parsed.hostname not in TRUSTED_HOSTS or parsed.username or parsed.password:
            raise RuntimeError('官方文件发生跨域或非 HTTPS 跳转；已拒绝：' + newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_verified(spec, destination, cancel=None, report=None):
    """Fetch a fixed vendor URL, verify BEFORE moving to destination."""
    source = urllib.parse.urlsplit(spec['url'])
    if (source.scheme != 'https' or source.hostname not in TRUSTED_HOSTS
            or source.path != '/' + spec['name'] or source.query or source.fragment):
        raise ValueError('拒绝非预先固定的官方下载来源')
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() or destination.with_name(destination.name + '.unverified.part').is_symlink():
        raise RuntimeError('拒绝通过符号链接下载可执行文件')
    tmp = destination.with_name(destination.name + '.unverified.part')
    if tmp.exists():
        tmp.unlink()
    opener = urllib.request.build_opener(VendorRedirects())
    count = 0
    try:
        req = urllib.request.Request(spec['url'], headers={'User-Agent': 'C-Scan-Studio/3.1 source-only-verifier'})
        with opener.open(req, timeout=35) as src, tmp.open('wb') as dest:
            if urllib.parse.urlsplit(src.geturl()).hostname not in TRUSTED_HOSTS:
                raise RuntimeError('下载不在 voidtools 官方域名下')
            while True:
                if cancel and cancel.is_set():
                    raise RuntimeError('用户取消了官方文件获取')
                chunk = src.read(256 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                if count > MAX_ARCHIVE_BYTES:
                    raise RuntimeError('文件超过安全体积上限')
                dest.write(chunk)
                if report and count % (1024 * 1024) < len(chunk):
                    report(f'下载 {spec["name"]}：{count // (1024 * 1024)} MiB')
        got = hash_file(tmp)
        if got.casefold() != spec['sha256'].casefold():
            raise RuntimeError('SHA256 不匹配：' + spec['name'] + '；拒绝运行')
        os.replace(tmp, destination)
    finally:
        if tmp.exists():
            tmp.unlink()
    return destination


def verify_archive(path, spec):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError('缺少官方下载文件：' + str(path))
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise RuntimeError('官方包体积异常')
    if hash_file(path).casefold() != spec['sha256'].casefold():
        raise RuntimeError(f'{spec["name"]}: SHA256 不匹配，拒绝安装')
    with zipfile.ZipFile(path) as archive:
        bad = archive.testzip()
        if bad:
            raise RuntimeError('ZIP CRC 校验失败：' + bad)
        for member in archive.infolist():
            if member.file_size > MAX_MEMBER_BYTES:
                raise RuntimeError('ZIP 内含异常大的文件')
            # Reject absolute, parent-traversal, NTFS alternate stream, and symlink entries.
            canonical = member.filename.replace('\\', '/')
            if (canonical.startswith('/') or ':' in canonical
                    or any(seg in ('', '.', '..') for seg in canonical.split('/') if seg != canonical.split('/')[-1])
                    or any(seg == '..' for seg in canonical.split('/'))):
                raise RuntimeError('ZIP 内存在异常路径：' + member.filename)
            if stat.S_IFMT(member.external_attr >> 16) == stat.S_IFLNK:
                raise RuntimeError('ZIP 内存在符号链接')
    return True


def _extract_selected(zip_path, wanted, output):
    """Extract ONE expected executable, never bulk-extract an archive."""
    with zipfile.ZipFile(zip_path) as archive:
        candidates = [m for m in archive.infolist()
                      if not m.is_dir() and Path(m.filename.replace('\\', '/')).name.lower() == wanted.lower()]
        if len(candidates) != 1:
            raise RuntimeError('官方 ZIP 中未找到唯一的 ' + wanted)
        member = candidates[0]
        if member.file_size > MAX_MEMBER_BYTES:
            raise RuntimeError('可执行文件体积异常')
        with archive.open(member) as source, open(output, 'wb') as dest:
            shutil.copyfileobj(source, dest, length=1024 * 1024)
    return hash_file(output)


def member_digest(archive_path, wanted):
    """Expected EXE digest is derived from the fixed-SHA official archive."""
    with zipfile.ZipFile(archive_path) as archive:
        members = [m for m in archive.infolist()
                   if not m.is_dir() and Path(m.filename.replace('\\', '/')).name.casefold() == wanted.casefold()]
        if len(members) != 1:
            raise RuntimeError('ZIP missing expected executable')
        h = hashlib.sha256()
        with archive.open(members[0]) as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                h.update(block)
        return h.hexdigest()


def trusted_local(root=HERE):
    """Return verified installed EXE paths or None; doesn't execute code."""
    root = Path(root)
    manifest = root / 'Tools' / MANIFEST_NAME
    if not manifest.is_file() or manifest.is_symlink():
        return None
    try:
        data = json.loads(manifest.read_text(encoding='utf-8'))
        arch = data['architecture']
        specs = files_for_arch(arch)
        if data['vendor_archives'] != {s['name']: s['sha256'] for s in specs}:
            return None
        expected = {'everything': root / 'Tools' / 'Everything' / 'Everything.exe',
                    'es': root / 'Tools' / 'ES' / 'es.exe'}
        for name, path in expected.items():
            if not path.is_file() or path.is_symlink():
                return None
            if hash_file(path) != data['executable_sha256'][name]:
                return None
        # Crucially, do not trust ONLY the mutable local manifest. Check each
        # installed binary against the original ZIP pinned by trusted source code.
        for spec in specs:
            archive = root / 'Tools' / 'Official_Offline' / spec['name']
            verify_archive(archive, spec)
            kind = spec['kind']
            filename = 'Everything.exe' if kind == 'everything' else 'es.exe'
            if member_digest(archive, filename) != hash_file(expected[kind]):
                return None
        return expected
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, zipfile.BadZipFile, json.JSONDecodeError):
        return None


def local_cli_if_verified(root=HERE):
    paths = trusted_local(root)
    return str(paths['es']) if paths else None


def status(root=HERE):
    root = Path(root)
    paths = trusted_local(root)
    offline = root / 'Tools' / 'Official_Offline'
    try:
        specs = files_for_arch(architecture())
    except RuntimeError as ex:
        return {'ready': False, 'status': str(ex), 'archives': []}
    available = [s['name'] for s in specs if (offline / s['name']).is_file()]
    return {'ready': bool(paths), 'status': '官方 ZIP 校验安装完成' if paths else '尚未准备本地官方 Everything / ES',
            'archives': available, 'version': VENDOR_VERSION}


def prepare(root=HERE, cancel=None, report: Optional[Callable[[str], None]]=None,
            offline_only=False, _test_specs=None):
    """Install without privilege, only after explicit user opt-in. Atomic per-file writes."""
    root = Path(root)
    installed = trusted_local(root)
    if installed and _test_specs is None:
        return installed
    arch = architecture()
    specs = _test_specs if _test_specs is not None else files_for_arch(arch)
    tools = root / 'Tools'
    offline = tools / 'Official_Offline'
    reject_reparse_chain(root, offline)
    offline.mkdir(parents=True, exist_ok=True)
    reject_reparse_chain(root, offline)
    verified_archives = {}
    for spec in specs:
        if cancel and cancel.is_set():
            raise RuntimeError('已取消，未启动 Everything')
        archive = offline / spec['name']
        reject_reparse_chain(root, archive)
        if archive.exists():
            if report:
                report(f'校验已提供的官方 ZIP：{spec["name"]}')
        else:
            if offline_only:
                raise RuntimeError('缺少离线官方文件：' + spec['name'])
            if report:
                report('从 www.voidtools.com 官方下载：' + spec['name'])
            fetch_verified(spec, archive, cancel=cancel, report=report)
        verify_archive(archive, spec)
        verified_archives[spec['name']] = spec['sha256']
        if report:
            report('SHA256 校验通过：' + spec['name'])
    # Verify both ZIPs BEFORE installing any executables.
    with tempfile.TemporaryDirectory(prefix='cscan-vendor-', dir=tools) as temp:
        tmp = Path(temp)
        extracted_hashes = {}
        extracted_hashes['everything'] = _extract_selected(offline / specs[0]['name'], 'Everything.exe', tmp / 'Everything.exe')
        extracted_hashes['es'] = _extract_selected(offline / specs[1]['name'], 'es.exe', tmp / 'es.exe')
        if cancel and cancel.is_set():
            raise RuntimeError('已取消，未启动 Everything')
        dest_everything = tools / 'Everything' / 'Everything.exe'
        dest_es = tools / 'ES' / 'es.exe'
        for destination in (dest_everything, dest_es):
            reject_reparse_chain(root, destination)
            if (destination.exists() or destination.is_symlink()) and not trusted_local(root):
                raise RuntimeError('发现未经本工具确认的同名文件：' + str(destination) + '。请人工检查。')
            destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tmp / 'Everything.exe', dest_everything)
        shutil.copy2(tmp / 'es.exe', dest_es)
        # Manifest itself is local provenance (not a code-signature or proof of origin).
        manifest = {'schema': 1, 'architecture': arch, 'vendor_archives': verified_archives,
                    'executable_sha256': extracted_hashes, 'created_utc': int(time.time()),
                    'source': 'https://www.voidtools.com/downloads/',
                    'license': 'https://www.voidtools.com/License.txt'}
        temp_manifest = tools / (MANIFEST_NAME + '.tmp')
        temp_manifest.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        os.replace(temp_manifest, tools / MANIFEST_NAME)
    verified = trusted_local(root) if _test_specs is None else {'everything': dest_everything, 'es': dest_es}
    if not verified:
        raise RuntimeError('安装后校验失败，不会启动第三方程序')
    if report:
        report('两份官方包均已核验，便携文件准备完毕；未修改系统 PATH/服务/注册表')
    return verified


def launch(root=HERE):
    paths = trusted_local(root)
    if not paths:
        raise RuntimeError('未找到已核验的官方便携 Everything')
    if os.name != 'nt':
        raise RuntimeError('Everything 只允许在 Windows 上运行')
    # Explicit user opt-in is required by the caller; do not request elevation.
    proc = subprocess.Popen([str(paths['everything'])], cwd=str(paths['everything'].parent),
                            close_fds=True)
    return proc.pid


def main(argv=None):
    parser = argparse.ArgumentParser(description='Everything official pinned portable manager')
    parser.add_argument('operation', choices=['status', 'prepare', 'offline-prepare', 'launch'])
    args = parser.parse_args(argv)
    print('C-Scan verified Everything manager: ' + VENDOR_VERSION)
    if args.operation == 'status':
        print(json.dumps(status(), indent=2, ensure_ascii=False))
        return 0
    if args.operation == 'launch':
        print('Everything 已请求启动，PID=' + str(launch()))
        return 0
    try:
        result = prepare(offline_only=(args.operation == 'offline-prepare'), report=print)
        print('已准备：' + str(result['everything']))
        print('索引需 Everything 运行；首次使用可能需通过其官方界面设置 NTFS 服务/UAC。')
        return 0
    except Exception as exc:
        print('拒绝继续：' + str(exc))
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
