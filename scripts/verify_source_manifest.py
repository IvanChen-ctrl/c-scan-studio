#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail CI if the tracked source SHA-256 manifest was not regenerated.

Unlike build_release.py, this is strictly read-only: it must execute BEFORE
any packaging or regression helper has a chance to update the manifest.
"""
from __future__ import annotations

from pathlib import Path
from build_release import ROOT, eligible, manifest_bytes


def verify_source_manifest(root: Path = ROOT) -> bool:
    expected = manifest_bytes(eligible(root))
    actual = (root / "FILE_INTEGRITY_SHA256.csv").read_bytes()
    return actual == expected


if __name__ == "__main__":
    if not verify_source_manifest():
        raise SystemExit("FAIL: tracked FILE_INTEGRITY_SHA256.csv is stale; update it before running CI.")
    print("PASS: committed source SHA-256 manifest matches all eligible files.")
