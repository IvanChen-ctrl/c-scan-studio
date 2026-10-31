# C-Scan Studio v3.3.1

## 统一控制台

- 根目录保留一个面向用户的启动 BAT；全部原有扫描、清理、Python、Everything、Defender、安全检测、离线分享等操作整合进浏览器界面。
- 合并冗余 BAT，内部保留 Python 自动发现/下载、签名核验和高级安装的必要启动脚本。
- 使用可解释的 P1–P4 优先级和绿/黄/橙/红/灰风险分类；清理永远需要用户手动确认。

## 安全可核验证据

- 本地会话 token、loopback 限定、固定白名单操作接口。
- 修正源码改动后阻止使用 Defender 的问题：无论源码完整性是否匹配，用户仍可选择杀毒扫描。
- 提供 GitHub Actions 自动测试、CodeQL v4、Dependabot、Release SHA-256 和构建来源证明配置。
- 本地 SHA-256 仅证明清单所列文件一致，**不是无毒认证**。

## 限制

Everything、ES CLI 和 Python 便携运行时在默认源码发行包中不包含二进制，首次使用可能联网下载并核验。尚未在用户 Windows 电脑上验证真实运行或得到任何第三方病毒扫描证书。

## v3.3.1 Windows hotfix

- Fixed UnicodeEncodeError for Chinese text on legacy Windows CI consoles (cp1252) using UTF-8 console environment.
- Added two regression tests; pinned source-only package version to v3.3.1.
- Release publication is gated on CI (Windows + Linux) and CodeQL success at the same commit.
- Third-party antivirus tests remain independent and not implied by CI success.
