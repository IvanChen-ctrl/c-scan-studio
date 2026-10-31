# C-Scan Studio v3.4.0-beta.2 — Safety-first UX preview

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

## Beta 2：分页预览与前后容量记录

- 浏览器可按页查看本次被主动勾选的 **全部候选文件路径与逻辑大小**，不再仅限 12 个路径样本；分页仅能访问当前单次预览对应的白名单快照。
- 清理完成后记录并展示磁盘可用容量前后差异、已删除文件逻辑字节、跳过及错误数；明确说明并发写入带来的误差。
- 取消预览需携带对应凭证，旧窗口不能取消新的预览；前端忽略过期的分页响应。
- 原始 v3.3.1 稳定版和旧版 VirusTotal 检测记录维持不变。Beta 2 ZIP 需要新的独立安全扫描。

## Beta 2 验证说明

- 155 项 Python 隔离回归测试已在 Linux 环境执行通过；浏览器模拟交互完成桌面、390px 窄屏和多页候选文件检视。
- GitHub Windows/Linux 自动测试与 CodeQL 以实际对应提交的运行结果为准，尚未取得 beta2 的这些运行结果时不得写为通过。
- 尚未进行真实 Windows C 盘文件删除与第三方在线病毒扫描；此测试版不应替代 v3.3.1 稳定版用于未经备份的磁盘清理。
