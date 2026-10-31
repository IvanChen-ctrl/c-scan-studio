# C-Scan Studio · 给朋友的独立安全核验手册

本项目是 **Windows 本地磁盘扫描及缓存清理工具**，**不是杀毒程序**。任何“零检出”都不等于绝对安全。请优先从官方 Release 下载，不要从聊天附件、网盘转发的同名 ZIP 推断哈希相同。

## 第一步：先决定版本

- [v3.3.1 稳定版](https://github.com/IvanChen-ctrl/c-scan-studio/releases/tag/v3.3.1)：历史 VirusTotal 报告只对应它的特定 SHA-256。
- [v3.4.0-beta.2 预发布版](https://github.com/IvanChen-ctrl/c-scan-studio/releases/tag/v3.4.0-beta.2)：功能更新但未经真实 Windows 清理验收；非专业用户建议先进行只读扫描。

## 第二步：核对下载包身份（不需要安装程序）

下载 GitHub Release 中的源码 ZIP，在 PowerShell 执行：

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\Users\你的用户名\Downloads\C_Scan_Studio_v3.4.0-beta.2_Source.zip'
```

beta.2 的正确值应为：

```
dc9d63c1e85ae7a7ffb28e3cc695e1c3a2976c0d7b83f9cd76bbf1397e9bee66
```

如果不一致，**立即停止**，不要运行或清理。不同同名 ZIP 不一定恶意，但必须单独调查，不能借用别人的检测报告。

## 第三步：验证公开发布流程

- [Windows/Linux 测试](https://github.com/IvanChen-ctrl/c-scan-studio/actions/runs/41221929190)
- [CodeQL 代码扫描](https://github.com/IvanChen-ctrl/c-scan-studio/actions/runs/41221929233)
- [GitHub 构建来源证明](https://github.com/IvanChen-ctrl/c-scan-studio/attestations/62151837)

已安装 GitHub CLI 的用户可独立运行：

```powershell
gh attestation verify 'C:\Users\你的用户名\Downloads\C_Scan_Studio_v3.4.0-beta.2_Source.zip' -R IvanChen-ctrl/c-scan-studio
```

## 第四步：用本机和外部平台扫描

1. 对 ZIP 右键，选择「使用 Microsoft Defender 扫描」（选项名称随 Windows 配置变化）。
2. 如需第三方复核，主动将**同一个 ZIP**上传 [VirusTotal](https://www.virustotal.com/gui/home/upload) 或 [MetaDefender](https://metadefender.opswat.com/)；平台不会由本工具自动上传。
3. 记录真实检出数量、检测日期、完整报告链接和 SHA-256。不要仅截图没有文件指纹的绿色图标。

## 第五步：只读试用，再决定清理

先用独立目录解压，启动界面后只进行扫描。查看绿色/黄色/橙色/红色/灰色分类和实际文件路径。**beta.2 尚未验证真实 Windows 清理流程。** 使用前备份重要数据；只对理解用途的缓存项目执行清理。不要上传包含本机用户名或私人文件路径的诊断报告。
