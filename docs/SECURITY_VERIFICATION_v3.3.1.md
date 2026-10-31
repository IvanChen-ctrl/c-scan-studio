# C-Scan Studio v3.3.1 — security evidence (not a malware-free certificate)

Evidence updated: **2026-10-31**.

## Exact file identity

- Distribution: `C_Scan_Studio_v3.3.1_Source.zip`
- SHA-256: `d6f1adeb0befd9603244aada81882dbaa64ffc120010020afa7e39dc99865362`
- Reproducible source commit: [`2f58ca34`](https://github.com/IvanChen-ctrl/c-scan-studio/commit/2f58ca3415b46a4f87915211cf970671a5d1c09a)
- [VirusTotal file report provided by the project owner](https://www.virustotal.com/gui/file/d6f1adeb0befd9603244aada81882dbaa64ffc120010020afa7e39dc99865362/detection)
- Build log: [GitHub release workflow that printed this exact SHA-256](https://github.com/IvanChen-ctrl/c-scan-studio/actions/runs/41204550943).

**Scope:** The exact file hash in the submitted VirusTotal link matches the archive hash recorded in the GitHub release build log. The independent VirusTotal **engine count, verdict and scan timestamp could not be read here** because the dynamic site was inaccessible. Do not present this as a confirmed 0-detection result.

## Independently observable GitHub checks for the archived source commit

| Check | Result | Evidence |
|---|---|---|
| Windows and Linux CI | Workflow passed on the pinned source commit | [CI run](https://github.com/IvanChen-ctrl/c-scan-studio/actions/runs/41204452459) |
| CodeQL (Python / JavaScript / Actions) | Workflow passed on the pinned source commit; this does not establish zero security alerts | [CodeQL run](https://github.com/IvanChen-ctrl/c-scan-studio/actions/runs/41204452470) |
| Release reconstruction | Requires exact SHA-256 to match the owner-submitted VirusTotal file | [Release workflow](https://github.com/IvanChen-ctrl/c-scan-studio/blob/main/.github/workflows/release.yml) |
| Microsoft Defender | Not independently executed on the user's Windows computer | Not certified |
| Everything / Windows file cleanup | Not independently validated on the user's machine | Not certified |

The repository's main branch contains later workflow and documentation changes. **Download the tagged release ZIP and verify its SHA-256**; do not assume that a newly packed ZIP from `main` has the same VirusTotal report.

## How others can verify

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath ".\\C_Scan_Studio_v3.3.1_Source.zip"
```

The resulting hash must be `d6f1adeb0befd9603244aada81882dbaa64ffc120010020afa7e39dc99865362`. If the published release has a GitHub attestation, verify it with `gh attestation verify C_Scan_Studio_v3.3.1_Source.zip -R IvanChen-ctrl/c-scan-studio`.

VirusTotal scans complement source review, antivirus installed on the actual device and careful review of deletion permissions. A scan link, a passed CI workflow, a CodeQL job and a matching hash **do not prove a file is absolutely safe**.
