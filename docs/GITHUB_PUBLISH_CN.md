# GitHub 仓库创建与免费安全证据——逐步手册

仓库建议名称：`c-scan-studio`，默认 **Public** 以启用公开项目免费代码扫描及构建证明。

## A. 推荐：直接让脚本创建公开仓库（不要提前在网页新建同名仓库）

1. 先登录 GitHub 账户，确认将要使用的账号。若已经拥有 `c-scan-studio` 仓库，请直接使用 B 节的现有仓库流程，不必创建新仓库。
2. 安装 Git for Windows 与 GitHub CLI（https://cli.github.com/），在 Windows PowerShell 中运行 `gh auth login`，通过浏览器完成身份验证。**不要**把 token 给任何人，也不要写入脚本。
3. 将本 ZIP 解压到新目录，在该目录内打开 PowerShell，运行 `./scripts/Publish_With_GitHub_CLI.ps1`。如因 Windows 文件来源标记阻止脚本，请先核对源码和签名，了解警告原因再自行决定是否解除单个文件的阻止；不要全局关闭 PowerShell 安全设置。
4. 检查屏幕列出的 **即将公开的文件名**。输入大写 `PUBLISH` 后，脚本才会执行提交与 `gh repo create c-scan-studio --public --source . --remote origin --push`。
5. 在仓库 **Actions** 栏查看 `CI tests`、`CodeQL`；在 **Settings → Security** 查看 Dependabot 与 Secret scanning 是否已启用。工作流未真实运行前不要使用“已验证”徽章。
6. v3.3.1 采用自动发行：当 **同一 main 提交**的 Windows/Linux CI 与 CodeQL 均真实成功后，`Release source + provenance` 工作流会生成 `v3.3.1` Release、ZIP、SHA-256 及构建来源证明。不要为了绕过失败检查而手动打 tag。
7. 把发布版 Release URL、SHA-256 和手动获得的 VirusTotal / MetaDefender 报告 URL 发给朋友。每次版本更新都要重新检测。

## B. 如果已经在网页创建了同名仓库

先在源码目录运行 `git init -b main`，再执行：

```powershell
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/c-scan-studio.git
```

请把 `<YOUR_GITHUB_USERNAME>` 换成你的真实用户名（示例不是实际链接）。再运行发布脚本。它会识别已有 `origin`，提交前输入 `PUBLISH`，推送前另需输入 `PUSH`，不会擅自推送其他仓库。仅对你拥有权限的空仓库使用本流程，避免覆盖他人代码。

## C. 朋友自己验证来源

- `Get-FileHash` 核对 ZIP 发行哈希。
- 安装了 GitHub CLI 后，可用 `gh attestation verify <文件路径> --repo <OWNER>/c-scan-studio` 验证工作流生成的构建来源证明；请将 `<OWNER>` 替换为真实仓库所有者。
- GitHub `Security` 中的 CodeQL 和 Secret scanning 仅查找部分已知问题，不能替代手动审计与杀毒检测。
- VirusTotal 等普通上传可能公开分享文件；不要上传任何带个人文件路径或密钥的工作目录。
- 没有“自动免费官方无毒证书”；这里提供免费可核验的证据链。

## D. 发布隐私保护

只发布源码发行包，不公开：`_runtime/`、`Tools/Official_Offline/` 中自带的第三方 ZIP、`Reports/`、`logs/`、`*.env`、个人配置、AI 模型、用户缓存以及安装器。`scripts/build_release.py` 限定固定源码目录和扩展名，不会打包额外的 EXE/ZIP。


## v3.4.0-beta.1 测试版发布

保持 v3.3.1 Release 和已有 VirusTotal 哈希不变。新的 prerelease 由 .github/workflows/release.yml 根据同一 main 提交的 CI+CodeQL 成功结果创建，ZIP 用新版本号和哈希，必须重新交给 VirusTotal 验证。请勿把测试版链接冒充稳定版。
