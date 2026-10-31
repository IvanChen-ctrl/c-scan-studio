# C-Scan Studio v3.4.0-beta.2 · 独立安全验证证据（不是无病毒证书）

更新：2026-10-31。**记录的是可公开核实的事实，不代表任何软件绝对安全。**

## 1. 固定发行物

- [GitHub 正式 beta.2 预发布版](https://github.com/IvanChen-ctrl/c-scan-studio/releases/tag/v3.4.0-beta.2)
- 文件：`C_Scan_Studio_v3.4.0-beta.2_Source.zip`（142,121 字节）
- SHA-256：`dc9d63c1e85ae7a7ffb28e3cc695e1c3a2976c0d7b83f9cd76bbf1397e9bee66`
- GitHub 合并源码提交：[`6c0f3a8142c41cf2721f446783bce1907eb87f4e`](https://github.com/IvanChen-ctrl/c-scan-studio/commit/6c0f3a8142c41cf2721f446783bce1907eb87f4e)
- [GitHub 构建来源证明（Artifact Attestation）](https://github.com/IvanChen-ctrl/c-scan-studio/attestations/62151837)

注意：这个公开预发布 ZIP 与 PR 合并前产生的同名本地测试 ZIP（SHA-256 `c8aad69e84300d37280c5b28bfd8f7a9f7d53d3a7106cdff6a1198a1e96ef120`）不相同。**已独立重建并完全复现 GitHub 的正式哈希。** 具体原因是 GitHub 发布源码另包含一份 2,792 字节的 `docs/SECURITY_VERIFICATION_v3.3.1.md` 文档；本地预合并包缺少它。程序文件未因这项差异而变动。以后分享、查毒和比对时请只以 GitHub Release ZIP 为准。

## 2. 实际完成的公开自动化检查

| 检查 | 结果 | 可核实证据 |
|---|---|---|
| Windows + Ubuntu CI | 合并提交上通过 | [CI run #41221929190](https://github.com/IvanChen-ctrl/c-scan-studio/actions/runs/41221929190) |
| CodeQL | Python、JavaScript/TypeScript、Actions 三项工作流通过；不保证零告警 | [CodeQL run #41221929233](https://github.com/IvanChen-ctrl/c-scan-studio/actions/runs/41221929233) |
| GitHub Release 构建 | 成功，包含 41 个源码文件及 SHA-256 清单 | [发布执行记录 #41222017161](https://github.com/IvanChen-ctrl/c-scan-studio/actions/runs/41222017161) |
| 回归测试 | 发布工作流运行六组测试，共 155 项成功 | 同上发布执行记录 |
| 发行 ZIP 重建 | 本地独立重建的 SHA-256 与发行附件完全相同；ZIP CRC 通过 | 发布日志及使用仓库 `scripts/build_release.py` 复现 |
| Artifact Attestation | 已生成，对应 GitHub 发行哈希 | [证明编号 62151837](https://github.com/IvanChen-ctrl/c-scan-studio/attestations/62151837) |

软件提供默认零勾选、白名单清理、完整候选文件分页预览、120 秒单次清理凭证和 `DELETE` 人工确认；这些是软件实现/测试的能力，并非 Windows 清理实测通过的证明。

## 3. 尚未验证的事项

- **VirusTotal、MetaDefender Cloud 或 Jotti 对 beta.2 正式发行 ZIP 的真实检出结果未提供。** [v3.3.1 的历史 VirusTotal 报告](https://www.virustotal.com/gui/file/d6f1adeb0befd9603244aada81882dbaa64ffc120010020afa7e39dc99865362/detection)仅适用于旧版 ZIP。
- 尚未在用户真实 Windows C 盘验证删除、故障恢复、文件占用/竞争条件、Everything IPC 与 Microsoft Defender 实机扫描。
- ZIP 哈希匹配仅证明文件身份与完整性，签名/来源证明不是杀毒结果，CodeQL 工作流成功不等于审计没有漏洞。
- 在线杀毒平台的公开上传可能共享样本。不要上传私人数据、日志、API 密钥或内部模型。

## 4. 让朋友自己校验

在 PowerShell 中运行：

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\C_Scan_Studio_v3.4.0-beta.2_Source.zip'
```

如果已经安装并登录 GitHub CLI，可以另外执行：

```powershell
gh attestation verify '.\C_Scan_Studio_v3.4.0-beta.2_Source.zip' -R IvanChen-ctrl/c-scan-studio
```

还应使用本机 Microsoft Defender 扫描发行 ZIP，或主动上传**同一个 SHA-256 的正式 ZIP**到 [VirusTotal](https://www.virustotal.com/gui/home/upload) 获取真实报告。参见 [中文分享核验手册](FRIENDS_VERIFY_CN.md)。
