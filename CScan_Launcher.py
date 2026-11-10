#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Portable Windows entry point and a bounded, read-only packaged-app smoke test.

A PyInstaller executable is not a Python interpreter. The legacy ``-I script``
compatibility entry below dispatches only named, bundled application modules;
it never evaluates an arbitrary file, ``-c`` expression, or ``-m`` module.
"""
from __future__ import annotations

import contextlib
import http.client
import importlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import threading

VERSION = "3.7.0-beta.1"
RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
LEGACY_MODULES = {
    "Advanced_Disk_Studio.py": "Advanced_Disk_Studio",
    "C_Drive_Cleanup.py": "C_Drive_Cleanup",
    "Security_Audit.py": "Security_Audit",
    "Everything_Official_Manager.py": "Everything_Official_Manager",
    "Share_Offline_Bundle.py": "Share_Offline_Bundle",
}


def _print_json(data):
    # ASCII JSON remains parseable even in a legacy Windows console code page.
    print(json.dumps(data, ensure_ascii=True, sort_keys=True))


def _legacy_target(raw, root=RESOURCE_ROOT):
    """Require an exact, regular file immediately inside the packaged root."""
    root = Path(root).absolute()
    candidate = Path(raw).absolute()
    if candidate.name not in LEGACY_MODULES or ".." in candidate.parts:
        raise ValueError("Only an exact bundled helper path is supported.")
    for component in (candidate, *candidate.parents):
        info = os.lstat(component)
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Linked helper paths are not supported.")
    if not candidate.is_file():
        raise ValueError("The bundled helper is missing.")
    # Resolve only AFTER rejecting links, to handle Windows long/8.3 spellings
    # of the same runner Temp directory without permitting redirected paths.
    if candidate.parent.resolve(strict=True) != root.resolve(strict=True):
        raise ValueError("Only an exact bundled helper path is supported.")
    return LEGACY_MODULES[candidate.name]


def _run_legacy(arguments):
    if not arguments:
        raise ValueError("The -I compatibility entry requires a bundled script.")
    module_name = _legacy_target(arguments[0])
    module = importlib.import_module(module_name)
    if module_name == "Share_Offline_Bundle":
        if len(arguments) != 1:
            raise ValueError("The share helper does not accept arguments.")
        try:
            module.prepare_share()
            return 0
        except Exception as exc:
            _print_json({"ok": False, "error": "Share preparation refused: " + str(exc)[:400]})
            return 3
    if module_name == "C_Drive_Cleanup":
        return int(module.cli(arguments[1:]) or 0)
    return int(module.main(arguments[1:]) or 0)


@contextlib.contextmanager
def _replacements(entries):
    """Small scoped replacement helper; avoids shipping a test framework."""
    saved = []
    try:
        for owner, name, replacement in entries:
            saved.append((owner, name, getattr(owner, name)))
            setattr(owner, name, replacement)
        yield
    finally:
        for owner, name, previous in reversed(saved):
            setattr(owner, name, previous)


def self_test():
    """Exercise real HTTP routes/resources, without reading user drive contents.

Only the disk-capacity/volume providers are replaced with explicit empty fixture
values. The real Analyzer, LocalHandler, Toolbox and packaged dashboard are used.
No POST is sent. Scan/cleanup/setup entry points and delete functions fail closed
if this smoke test accidentally reaches them.
"""
    import Advanced_Disk_Studio as studio
    import C_Drive_Cleanup as engine
    import Drive_Inspector as inspector
    import Unity_Cache_Manager as unity_cache
    import shutil

    forbidden = []

    def deny(*args, **kwargs):
        forbidden.append("scan_or_mutation_attempt")
        raise RuntimeError("The packaged smoke test must not scan or mutate user data.")

    replacements = [
        (studio.Analyzer, "_disk", lambda self: {"total": 0, "free": 0, "used": 0}),
        (inspector, "available_drives", lambda: []),
        (engine, "make_targets", deny),
        (inspector, "inspect_roots", deny),
        (unity_cache, "audit", deny),
        (os, "unlink", deny),
        (os, "remove", deny),
        (shutil, "rmtree", deny),
    ]
    for name in ("start_scan", "start_clean", "start_large", "start_inspection",
                 "start_everything_setup"):
        replacements.append((studio.Analyzer, name, deny))
    probes = []
    server = None
    worker = None
    with _replacements(replacements):
        analyzer = studio.Analyzer()
        server = studio.ThreadingHTTPServer(("127.0.0.1", 0), studio.LocalHandler)
        server.daemon_threads = True
        server.session_token = secrets.token_urlsafe(32)
        server.analyzer = analyzer
        server.toolbox = studio.Toolbox(root=RESOURCE_ROOT, log=analyzer._record)
        worker = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
        worker.start()

        def get(path, authorized=True):
            query = "?t=" + server.session_token if authorized else ""
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
            try:
                connection.request("GET", path + query)
                response = connection.getresponse()
                body = response.read(2 * 1024 * 1024 + 1)
                if len(body) > 2 * 1024 * 1024:
                    raise RuntimeError("Unexpectedly large smoke-test response.")
                return response.status, response.getheader("Content-Type", ""), body
            finally:
                connection.close()

        try:
            status, kind, body = get("/")
            if status != 200 or "text/html" not in kind or b"C-Scan" not in body or b"Unity" not in body:
                raise RuntimeError("The packaged dashboard did not load with its Unity UI.")
            probes.append({"name": "dashboard", "http_status": status, "passed": True})

            status, kind, body = get("/api/state")
            state = json.loads(body.decode("utf-8"))
            if status != 200 or "application/json" not in kind or state.get("version") != VERSION:
                raise RuntimeError("The packaged state endpoint has an unexpected version or response.")
            if state.get("phase") != "idle" or state.get("scan_complete") is not False or state.get("items") != []:
                raise RuntimeError("The application did not start in an unscanned idle state.")
            probes.append({"name": "state_version", "http_status": status, "passed": True})

            unity = state.get("unity")
            if (not isinstance(unity, dict) or unity.get("items") != []
                    or not isinstance(unity.get("settings"), list)
                    or not isinstance(unity.get("guidance"), list)
                    or state.get("preserve_offline") is not True):
                raise RuntimeError("The initial Unity diagnostic API data or offline protection is missing.")
            probes.append({"name": "unity_idle_data", "http_status": status, "passed": True})

            status, _, _ = get("/api/state", authorized=False)
            if status != 403:
                raise RuntimeError("Unauthenticated state access was not rejected.")
            probes.append({"name": "session_token_required", "http_status": status, "passed": True})
            if forbidden:
                raise RuntimeError("The smoke test attempted a forbidden action.")
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
    if worker.is_alive():
        raise RuntimeError("The smoke-test server did not stop.")
    return {"product": "C-Scan Studio", "version": VERSION, "ok": True,
            "frozen": bool(getattr(sys, "frozen", False)), "python": sys.version.split()[0],
            "http": "real loopback server", "disk_data": "empty smoke-test fixture",
            "physical_disk_scan_performed": False, "deletion_performed": False,
            "forbidden_attempts": forbidden, "probes": probes}


def main(argv=None):
    # PyInstaller isolates CPython startup, so ambient PYTHONIOENCODING alone
    # is not a reliable way to make the legacy JSON helpers use UTF-8.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--version"]:
        _print_json({"product": "C-Scan Studio", "version": VERSION,
                     "frozen": bool(getattr(sys, "frozen", False))})
        return 0
    if args == ["--self-test"]:
        try:
            _print_json(self_test())
            return 0
        except Exception as exc:
            _print_json({"product": "C-Scan Studio", "version": VERSION, "ok": False,
                         "frozen": bool(getattr(sys, "frozen", False)),
                         "error": type(exc).__name__ + ": " + str(exc)[:500]})
            return 1
    if args and args[0] == "-I":
        try:
            return _run_legacy(args[1:])
        except (OSError, ValueError, ImportError) as exc:
            _print_json({"ok": False, "error": str(exc)[:400]})
            return 2
    if args:
        _print_json({"ok": False,
                     "error": "Supported options: --version, --self-test, or -I <exact bundled helper>."})
        return 2
    import Advanced_Disk_Studio as studio
    return studio.main()


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
