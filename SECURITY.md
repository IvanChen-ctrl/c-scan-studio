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
| 3.3.x | Current source line; fix security issues here |
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
