#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail CI if the tracked source SHA-256 manifest was not regenerated.

Unlike build_release.py, this is strictly read-only: it must execute BEFORE
any packaging or regression helper has a chance to update the manifest.
"""
from __future__ import annotations

from pathlib import Path
import csv
import io
from build_release import ROOT, eligible, manifest_bytes


def verify_source_manifest(root: Path = ROOT) -> bool:
    expected = manifest_bytes(eligible(root))
    actual = (root / "FILE_INTEGRITY_SHA256.csv").read_bytes()
    return actual == expected


if __name__ == "__main__":
    if not verify_source_manifest():
        expected = manifest_bytes(eligible(ROOT)).decode('utf-8-sig')
        actual = (ROOT / 'FILE_INTEGRITY_SHA256.csv').read_text(encoding='utf-8-sig')
        def rows(text):
            return {row[0]: row[1] for row in list(csv.reader(io.StringIO(text)))[1:]}
        have, want = rows(actual), rows(expected)
        changed = [key for key in sorted(have.keys() | want.keys())
                   if have.get(key) != want.get(key)]
        print(f"Manifest mismatch: {len(changed)} changed/missing/extra paths")
        for key in changed[:25]:
            print(f"  {key}: committed={have.get(key,'MISSING')} expected={want.get(key,'EXTRA')}")
        if not changed:
            print("Content hashes match, but CSV ordering, quoting or encoding differs.")
        raise SystemExit("FAIL: tracked FILE_INTEGRITY_SHA256.csv is stale; update it before running CI.")
    print("PASS: committed source SHA-256 manifest matches all eligible files.")
