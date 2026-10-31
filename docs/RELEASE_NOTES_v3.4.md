# C-Scan Studio v3.4.0-beta.1 — Safety-first UX preview

This **pre-release** improves the deletion workflow, not the size of the cleanup whitelist. The validated v3.3.1 stable release and its VirusTotal report remain unchanged.

## New controls

1. **No prechecked cleanup boxes.** The user must explicitly select every category (or opt into the green-only bulk checkbox).
2. **Server-side, read-only cleanup preview.** Shows categories, sizes, candidate counts, directory paths and at most 12 sample filenames. No deletion during preview.
3. **Short-lived single-use authorization.** Deletion requires the exact category selection, a valid 120-second preview ticket and an additional literal `DELETE` confirmation. Starting another task invalidates the ticket.
4. **No automatic execution of unverified ES.** The large-file search only starts `es.exe` when SHA-256-validated via the official Everything manager. Otherwise uses bounded, read-only fallback search.
5. Updated safety guidance, clearer four-step guide and an explicit link to GitHub Releases and the historic v3.3.1 verification report.

## Independent evidence

- This release builds a new source-only ZIP with its **own SHA-256**, not the previously scanned v3.3.1 ZIP.
- The v3.3.1 VirusTotal result **does not transfer** to this pre-release; repeat external malware scanning before calling this version independently checked.
- CI uses both Windows and Linux and includes the new v3.4 test suite. CodeQL also runs. A successful workflow is not an antivirus certificate.
- A signed artifact provenance statement is created via GitHub Actions when publishing succeeds.

## Limitations

No local Windows user-drive deletion or Everything IPC has been executed in this CI test environment. File deletion is irreversible and always re-checks saved scan snapshots just before unlinking. The source release contains no bundled third-party executable.
