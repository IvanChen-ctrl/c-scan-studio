#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Explicit, allowlisted GUI tools for C-Scan Studio v3.3.

No general shell/command endpoint. Every mutating or external operation requires
an exact action-specific acknowledgement, and none is called on page load.
Nothing in this module is an anti-malware certification or an AV verdict.
"""
from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import Security_Audit as audit
import Everything_Official_Manager as vendor
import Share_Offline_Bundle as share

HERE = Path(__file__).resolve().parent
CONFIRMATIONS = {
    'defender_scan': 'DEFENDER_SCAN',
    'signature_check': 'CHECK_SIGNATURES',
    'share_offline': 'MAKE_SHARE_PACKAGE',
    'python_installer': 'OPEN_PYTHON_INSTALLER',
    'everything_launch': 'LAUNCH_VERIFIED_EVERYTHING',
    'windows_storage': 'OPEN_WINDOWS_STORAGE',
}
ACTION_LABELS = {
    'defender_scan': 'Microsoft Defender 对工具目录的自定义扫描',
    'signature_check': '检查已下载 EXE 的数字签名（只读）',
    'share_offline': '从已校验文件生成朋友分享包',
    'python_installer': '打开官方 Python 完整安装器的独立确认窗口',
    'everything_launch': '启动已经 SHA-256 核验的 Everything',
    'windows_storage': '打开 Windows 官方存储管理设置',
}


def command_encoded(script):
    return base64.b64encode(script.encode('utf-16le')).decode('ascii')


def powershell_path():
    system_root = Path(os.environ.get('SystemRoot', r'C:\Windows'))
    candidate = system_root / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
    if not candidate.is_file():
        raise RuntimeError('本机未找到系统自带 Windows PowerShell；操作没有执行。')
    return str(candidate)


def _safe_under_root(target, root):
    try:
        root = Path(root).resolve(strict=True)
        target = Path(target)
        if target.is_symlink() or not target.is_file():
            return False
        info = os.lstat(target)
        if not stat.S_ISREG(info.st_mode) or (getattr(info, 'st_file_attributes', 0) & 0x400):
            return False
        return target.resolve(strict=True).is_relative_to(root)
    except (OSError, ValueError):
        return False


def python_environment(root=HERE):
    root = Path(root).resolve()
    exe = Path(sys.executable)
    try:
        source = '工具专用便携 Python' if exe.resolve().is_relative_to(root) else '现有 Python / Conda'
    except (OSError, ValueError):
        source = '现有 Python / Conda'
    return {
        'version': sys.version.split()[0], 'executable': str(exe),
        'source': source, 'system_python_not_modified': True,
        'full_python_install_automatic': False,
    }


class Toolbox:
    def __init__(self, root=HERE, log=None):
        self.root = Path(root).resolve()
        self.lock = threading.RLock()
        self.busy = False
        self.last = {'status': 'idle', 'message': '没有运行辅助任务', 'action': None, 'at': None}
        self.history = []
        self._log = log or (lambda message: None)

    def state(self):
        with self.lock:
            return {
                'busy': self.busy, 'last': dict(self.last), 'history': list(self.history[-12:]),
                'python': python_environment(self.root),
                'actions': [{'id': key, 'label': value, 'requires_confirmation': True}
                            for key, value in ACTION_LABELS.items()],
                'caution': '所有操作由本机用户主动触发；Defender 可能依照本机策略隔离文件；不自动上传文件。',
            }

    def start(self, action, confirmation):
        if not isinstance(action, str) or action not in CONFIRMATIONS:
            return False, '未列入白名单的功能，拒绝执行。'
        if confirmation != CONFIRMATIONS[action]:
            return False, '必须使用该功能的准确确认码。'
        with self.lock:
            if self.busy:
                return False, '另一个辅助任务仍在运行。'
            self.busy = True
            self.last = {'status': 'running', 'message': '操作开始：' + ACTION_LABELS[action],
                         'action': action, 'at': datetime.now(timezone.utc).isoformat()}
            worker = threading.Thread(target=self._worker, args=(action,), daemon=True)
            worker.start()
        return True, '已请求执行：' + ACTION_LABELS[action]

    def _worker(self, action):
        try:
            # A local manifest is not independent trust, but unexpected changes
            # must never be silently ignored before launching external processes.
            # A compromised distribution MUST remain scannable by Defender.
            # Only gate actions which execute/download or repackage software.
            if action in ('share_offline', 'python_installer', 'everything_launch'):
                integrity = audit.audit(self.root)
                if integrity['status'] != 'matched':
                    raise RuntimeError('源码与包内 SHA-256 清单不一致；拒绝启动或分发软件。Defender 检测仍可执行。')
            if action == 'defender_scan':
                result = self._defender()
            elif action == 'signature_check':
                result = self._signatures()
            elif action == 'share_offline':
                output = share.prepare_share(self.root)
                result = '已生成分享包：' + str(output) + '。必须再通过独立渠道公布 ZIP SHA-256。'
            elif action == 'python_installer':
                result = self._python_installer()
            elif action == 'everything_launch':
                result = f'已请求启动官方核验版 Everything，进程 ID：{vendor.launch(self.root)}'
            elif action == 'windows_storage':
                if os.name != 'nt':
                    raise RuntimeError('本操作仅在 Windows 上支持。')
                os.startfile('ms-settings:storagesense')  # nosec: fixed, local OS settings URI
                result = '已打开 Windows 存储设置。此工具没有直接更改系统组件。'
            else:
                raise RuntimeError('未知功能')
            status = 'completed'
        except Exception as exc:
            status, result = 'error', str(exc)[:350]
        with self.lock:
            record = {'status': status, 'message': result[:2000], 'action': action,
                      'at': datetime.now(timezone.utc).isoformat()}
            self.last = record
            self.history.append(record)
            self.history = self.history[-40:]
            self.busy = False
        self._log(ACTION_LABELS.get(action, action) + '：' + str(result)[:220])

    def _defender(self):
        if os.name != 'nt':
            raise RuntimeError('Microsoft Defender 扫描需要 Windows。')
        # Exact program path, fixed script; path provided only in environment.
        script = ("$ErrorActionPreference='Stop'; "
                  "Start-MpScan -ScanType CustomScan -ScanPath $env:CSCAN_SCAN_ROOT -ErrorAction Stop; "
                  "Write-Output 'Defender custom scan command finished. Review Windows Security Protection History.'")
        env = dict(os.environ, CSCAN_SCAN_ROOT=str(self.root))
        completed = subprocess.run([powershell_path(), '-NoProfile', '-NonInteractive',
                                    '-EncodedCommand', command_encoded(script)],
                                   capture_output=True, timeout=900, env=env, check=False,
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if completed.returncode:
            raise RuntimeError('Defender 调用失败（退出码 ' + str(completed.returncode) +
                               '）；请检查 Windows 安全中心的保护历史。')
        return ('Defender 自定义扫描命令已结束。请在 Windows 安全中心查看实际检测/隔离结果；'
                '命令成功不等于无病毒认证。')

    def _signatures(self):
        if os.name != 'nt':
            raise RuntimeError('数字签名检查需要 Windows。')
        chosen = []
        for directory in ('Tools', 'Installer_Files', '_runtime'):
            folder = self.root / directory
            if not folder.is_dir() or folder.is_symlink():
                continue
            for candidate in folder.rglob('*.exe'):
                if len(chosen) >= 25:
                    break
                if _safe_under_root(candidate, self.root):
                    chosen.append(str(candidate))
        if not chosen:
            return '当前没有可检查的第三方 EXE；源码版不自带第三方可执行文件。'
        # No file execution: inspect Authenticode metadata only.
        script = ("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; $paths = $env:CSCAN_EXE_LIST | ConvertFrom-Json; "
                  "foreach($path in $paths){ $sig=Get-AuthenticodeSignature -LiteralPath $path; "
                  "$publisher = if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{'Unsigned'}; "
                  "Write-Output ($sig.Status.ToString()+' | '+$publisher+' | '+$path) }")
        env = dict(os.environ, CSCAN_EXE_LIST=json.dumps(chosen))
        cp = subprocess.run([powershell_path(), '-NoProfile', '-NonInteractive',
                             '-EncodedCommand', command_encoded(script)],
                            capture_output=True, timeout=90, env=env, check=False,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if cp.returncode:
            raise RuntimeError('数字签名检查未完成。请通过 Windows 查看签名详细信息。')
        try:
            data = cp.stdout.decode('utf-8').strip()  # Explicit console output encoding above
        except UnicodeError:
            data = cp.stdout.decode('utf-8', errors='replace').strip()
        if not data:
            data = '已查询 ' + str(len(chosen)) + ' 个可执行文件，未返回可见详情。'
        return data[:1600] + '\n注意：有效签名不等于安全保证。'

    def _python_installer(self):
        if os.name != 'nt':
            raise RuntimeError('完整 Python 安装器仅在 Windows 上可用。')
        script = self.root / 'internal' / 'Install_Full_Python_GUI_Optional.cmd'
        if not _safe_under_root(script, self.root):
            raise RuntimeError('正式安装器的人工确认入口缺失或不安全。')
        # Start a NEW console; the official installer requires a second, typed INSTALL.
        subprocess.Popen([os.environ.get('ComSpec', r'C:\Windows\System32\cmd.exe'), '/d', '/c', str(script)],
                         cwd=str(self.root), creationflags=getattr(subprocess, 'CREATE_NEW_CONSOLE', 0))
        return '已打开官方 Python 安装器专用控制台。还需在新窗口输入 INSTALL 才会下载或安装。'


if __name__ == '__main__':
    print('This module is used by the local GUI only. No action was executed.')
