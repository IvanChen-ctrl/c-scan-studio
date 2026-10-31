# C-Scan Studio v3.4.0-beta.2 / C 盘智能扫描与安全可控清理

**Windows 10 / 11** · 单一启动 BAT · 本地浏览器界面 · 可选 Everything 索引 · 零额外 Python pip 依赖 · 开源可审计

> 这是磁盘扫描与缓存清理工具，不是杀毒软件，也没有“官方无毒认证”。
> 默认只有只读扫描；清理需选中白名单项目、预览提示并键入 `DELETE`。

## 1. 开始使用

1. 从 PR #3 对应的测试包下载 `C_Scan_Studio_v3.4.0-beta.2_Source.zip` 并核对独立 SHA-256；正式 GitHub 预发布版需经 GitHub 检查及发布后才会出现。
2. 解压到例如 `D:\C_Scan_Studio_v3.4.0-beta.2`，不要直接在 ZIP 内运行。
3. 双击根目录唯一的 **`00_启动C-Scan智能清理与安全中心.bat`**。
4. 已有 Python/Anaconda/Miniconda 时直接复用；未找到兼容的 Python 时会按固定 SHA-256 下载官方便携 CPython（需要联网，下载失败则不会清理）。不会修改系统 PATH。
5. 浏览器自动打开 **127.0.0.1** 本地控制台。检查缓存清单和风险颜色；是否清理由你决定。

## 2. 统一界面，原 BAT 功能如何找

| 操作 | v3.4.0-beta.2 图形界面入口 | 说明 |
| --- | --- | --- |
| 扫描 / 详细分析 | 智能缓存清理 | 不删除 |
| 按项目清理 | 智能缓存清理 → 勾选 → `DELETE` | 不能撤销 |
| Python 环境检查 | 工具与高级维护 → Python | 不改环境 |
| 官方完整版 Python | 工具与高级维护 → 可选安装 | 额外两次确认 |
| Everything 与 ES CLI | 工具与高级维护 → Everything | 用户确认、固定官方 SHA-256 |
| 快速查找大文件 | 大文件快速搜索 | 只读，不能删除 |
| Defender、数字签名、离线分享 ZIP | 工具与高级维护 → 安全核验 | 按操作分别确认 |
| 在线检测 / 本地哈希 | 在线安全验证 | 永不自动上传 |
| CSV / JSON 报告 | 首页右上角 / 安全验证 | 报告含本机路径，分享前脱敏 |
| 系统高级清理 | 工具与高级维护 → Windows 存储 | 只打开 Windows 官方设置 |

其他启动细节保留在 `internal/`，根目录不再堆叠重复 BAT。

## 3. 安全边界

- **绿色**低风险缓存：推荐优先核对；**黄色**中风险：由用户勾选。
- **橙色/红色/灰色**：只读建议或明确保护，禁止 GUI 自动清理。
- **P1–P4** 是处理优先级，**不代表删除安全性**；风险与优先级分开。
- 清理的文件必须出现在刚完成的扫描快照中，删除前复核路径、大小、修改时间、文件年龄、进程占用情况；拒绝符号链接/联接点。
- 保护 WinSxS、驱动、Windows Installer、回收站、个人文件、FinGPT/LoRA/模型权重、Conda 环境、CUDA 和 Python 虚拟环境。
- 不会发送扫描结果到云端；仅当用户点击 Everything 下载、官方 Python 下载或外部网页时才发生相关访问。
- 完整性检查不是独立信任源；只覆盖列入文件清单的源码，不检测所有未知文件，不能证明没有恶意软件。
- 第三方 Everything 二进制不在默认发行包中。可自选官方下载并校验。

## 4. 朋友如何独立验证

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\C_Scan_Studio_v3.4.0-beta.2_Source.zip'
```

将 SHA-256 与 GitHub Releases 的发行信息或独立渠道公开的校验值核对。检查 `Actions` 自动测试、`Security` CodeQL 检查、发行附件的 GitHub Artifact Attestation；使用 Microsoft Defender 或 VirusTotal / MetaDefender / Jotti 主动检测发行包。**任何单项通过都不等于软件已认证无毒。**

## 5. 给开发者

无需安装 Python 第三方依赖。测试：

```shell
python -m unittest discover -s tests
python -m unittest discover -s tests_v3
python -m unittest discover -s tests_v31
python -m unittest discover -s tests_v32
python -m unittest discover -s tests_v33
python scripts/build_release.py --outdir ../cscan-dist
```

完整 GitHub 发布步骤见 `docs/GITHUB_PUBLISH_CN.md`，安全披露见 `SECURITY.md`，开源许可见 `LICENSE`，第三方声明见 `NOTICE.md`。

## 6. 尚未完成的真实验证

本项目在隔离环境执行回归测试，但**不宣称已在你的 Windows 电脑上通过真实文件清理、Defender 检测或 Everything 索引联调**。GitHub Actions 绿色状态与病毒扫描 URL 只有在真实执行后才可以公开引用。

## 7. v3.3.1 Windows encoding hotfix

- Windows 启动 BAT 和 GitHub CI 强制使用 UTF-8，避免在 cp1252 控制台输出中文时异常退出。
- GitHub Release 只有当同一主分支提交的 Windows/Linux CI 和 CodeQL **实际成功**后才自动创建；附 SHA-256 和 GitHub Artifact Attestation。
- 任何 GitHub 检查都不是第三方杀毒证书；VirusTotal / MetaDefender 结果必须通过外部实际扫描取得。

## v3.4 测试版安全改进（v3.3.1 稳定版保留）

- **默认零勾选**：绿色缓存是推荐分类，但不自动代替用户选择。
- **强制删除前预览**：只有已完整扫描、在白名单内且未被禁止的类别才可生成预览；服务端返回只读清理清单、样本路径和有效期 120 秒的一次性凭证。`DELETE` 不能绕过该步骤。
- **逐文件再次核对**：预览不等于保证删除；文件元数据、进程状态和路径安全会在删除时再次检查。删除不经回收站。
- **Everything 可信来源**：不再自动从 PATH 或其他目录运行未经本工具 SHA-256 验证的 `es.exe`。
- **公开核验**：已有的 [v3.3.1 稳定版](https://github.com/IvanChen-ctrl/c-scan-studio/releases/tag/v3.3.1) 保持不变，新预发行版产生**新的 SHA-256**，以前的 VirusTotal 报告不能当成新版查毒结果。
- **发布建议**：请先在 Windows 本机只读扫描测试，再进行真实删除测试。当前不能宣称经过实机验证。


## v3.4.0-beta.2 增强：完整候选路径预览 + 清理后净空间比较

- 清理预览窗口新增 **全量候选文件分页**（每页 50 条），来自既有扫描快照；不会从浏览器读取任意路径。
- 分页接口要求本地同源会话和短时预览凭证，分页不会续期。取消、重新扫描或实际执行后，旧凭证立即失效。
- 清理结束后分别展示 **成功删除文件的逻辑大小**、**执行前 C 盘可用空间**及**执行后净空间变化**。后者可能受到其他程序同时写入磁盘影响，不表示独占回收量。
- 初始默认不勾选任何清理项；预览未能成功读取第一页时，最终删除按钮保持不可用。
- 注意：仅通过模拟测试、GitHub CI 和代码扫描的情况，不能代替在真实 Windows 系统上的清理测试。

Windows 实机验收步骤见 `docs/WINDOWS_TEST_CHECKLIST_CN.md`。
