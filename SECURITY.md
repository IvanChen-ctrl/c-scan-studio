# Security policy / 安全说明

## How the application works

C-Scan Studio is a local Windows disk-analysis and cache-cleanup application.
The HTTP server binds to `127.0.0.1` using a randomly generated session token.
Scanning and big-file searches are read-only. Deletion is limited to allowlisted
cache file snapshots and requires a separate `DELETE` confirmation. Nothing is
automatically uploaded to VirusTotal, GitHub or any other service.

**This software is not antivirus and cannot certify itself malware-free.**
A matching local SHA-256 manifest alone is not an independent trust anchor.
Compare the whole ZIP hash with a value obtained through a trusted separate
channel, verify the GitHub Actions run and artifact attestation, and run your
own antivirus scanner. A clean detection result is not a guarantee of safety.

## Reporting vulnerabilities

For security-sensitive issues, use GitHub's private **Report a vulnerability**
workflow under the repository Security tab when available. Do not publish
working exploits, private logs, credentials or personal file paths in public
issues. If private reporting is unavailable, open a public issue requesting a
secure contact channel *without disclosing the vulnerability details*.

## Supported versions

| Branch | Status |
| --- | --- |
| 3.3.1 | Latest stable release; use its own ZIP hash and reports |
| 3.4.0-beta.2 | Testing pre-release; not validated for real Windows deletion |
| 3.2.x and earlier | Historical; upgrade advised |

## Trust and limitations

- Third-party Everything, ES CLI and optional Python runtime are NOT embedded
  in the default source package. Download requires explicit action and a pinned
  SHA-256 verification before third-party executables are started.
- Source-integrity checks cover only the explicitly listed manifest entries;
  extra files placed in an extracted directory are not thereby safe.
- Runtime caches and OS components require separate investigation.
- Before sharing diagnostic JSON, remove personal usernames and full paths.
- CodeQL, Defender, VirusTotal and attestations are complementary evidence,
  not an official malware-free certificate.

## v3.4 pre-release controls

No cache categories are preselected. A local session must request a server-issued
read-only deletion preview before a fresh, single-use 120-second ticket and
literal `DELETE` confirmation can initiate deletion. The category IDs must
be identical to those previewed, and each file is revalidated against the
prior snapshot before unlinking. This is not a transactional rollback system.

An `es.exe` discovered on PATH is not automatically executed. Only the
sha256-verified CLI managed by the official Everything downloader is used.

This prerelease's SHA-256 will differ from v3.3.1. VirusTotal detection results
for v3.3.1 must not be attached as a scan certification for this version.

## v3.4 beta2 privacy and preview limits

The `/api/preview-files` endpoint shows up to 100 read-only snapshot paths per request, but only for the currently selected categories, with a valid single-use cleanup ticket and authenticated loopback origin. This is not arbitrary disk browsing. Files are not re-opened or uploaded. An expired, canceled or consumed ticket cannot be used to list files. The browser defaults to 50 rows per page.

The after-clean disk-space delta is a **net observed change** (background disk activity can increase or decrease it) and is not a verified measure of the cleaner's exclusive effect. The source has not undergone real Windows-drive deletion testing.

## Published beta.2 evidence and limitations

The GitHub [v3.4.0-beta.2 pre-release](https://github.com/IvanChen-ctrl/c-scan-studio/releases/tag/v3.4.0-beta.2) has SHA-256 `dc9d63c1e85ae7a7ffb28e3cc695e1c3a2976c0d7b83f9cd76bbf1397e9bee66` and a distinct [GitHub attestation](https://github.com/IvanChen-ctrl/c-scan-studio/attestations/62151837). CI and CodeQL workflows completed for the release source. See [beta.2 verification evidence](docs/SECURITY_VERIFICATION_v3.4.0-beta.2.md).

**No VirusTotal count or zero-detection claim exists for beta.2 here.** Beta source ZIP is not an antivirus-certified executable. Real Windows cleanup, removable-file races, third-party Everything IPC and Microsoft Defender scanning on the user's computer have not been independently validated. Avoid any automatic deletion until a separate Windows safety check is done.

## v3.5 beta — non-C drive inventory boundary

A separate read-only Drive_Inspector module implements explicit opt-in multi-drive
classification and duplicate detection. Its HTTP route accepts ONLY verified
local fixed/removable D:..Z: drive IDs, not file paths, UNC shares or arbitrary
search roots. It skips junctions, symlinks, hard-link aliases and protected trees.

Duplicate detection requires full-file SHA-256 after size/sample candidate
filtering. It has bounded runtime, inventory size and hash byte budgets.
Classification is extension/filename-based, not semantic AI, and only the
explicitly requested local scan reads personal file contents for hashing.

No duplicate deletion/move/quarantine API exists. A "keeper" is a cautious
candidate for manual review, NOT a guarantee that any other copy is disposable.
The category and duplicate reports include private paths; do not post them
publicly. The new beta requires its own malware scans and actual Windows tests.
