# v3.7.0-beta.1 Everything 搜索回归：映射网络盘 O: 等恢复（2026-11-20）

本变更从待合并 PR #13 的 `bae45e9488c8` 派生。它只改动只读大文件搜索、网盘识别、界面与测试；**不会更改已存在的 C 盘/Unity 清理授权、自动修改映射、网络凭据或连接设置**。

## 修复原因
旧 `Drive_Inspector.available_drives()` 仅显示 Windows DRIVE_REMOVABLE=2 与 DRIVE_FIXED=3，刻意排除了 DRIVE_REMOTE=4，导致映射到 O:、P: 等的企业共享盘无法选择。原有“其他盘分类/查重”仍仅允许本地盘，防止远程批量哈希产生网络负载。

## 新行为
* “大文件快速搜索”增加盘符选择器；默认为 C:，只额外列出当前 Windows 会话识别的 DRIVE_REMOTE 盘符 D: 至 Z:。
* 使用 `GetLogicalDrives` 和 `GetDriveTypeW` 只读枚举映射盘；真正启动搜索前重新确认盘符类型。不接受 UNC、任意文件夹或 C: 下的非系统范围。
* 先使用已经验证官方 SHA-256 的 Everything/ES CLI 查询所选网络盘；客户端严格校验结果必须属于该盘，且为可读取的普通文件。最多显示 180 项。
* 对未纳入索引的 O:，明确提示 Everything 1.4 的 `Tools → Options → Folders` 中手工添加 `O:\`，不假装“网盘没有文件”。
* 仅用户额外勾选并确认后才尝试网络盘限额扫描：最多 12 秒或 12,000 条目录项；可能因单个网络 I/O 阻塞而超过预期时间，不保证强制中断。
* 网络共享仅只读列文件名/大小/路径，不做完整网络查重或自动清理。网络结果可能包含公司内部路径，不自动上传。

## 回归检查
* 新增 `tests_v37/test_network_drive_search.py`：盘符白名单与拒绝 UNC、O: 与本地目录隔离、索引空结果绝不默认遍历、确认后的限额、非法参数拒绝、原本地多盘查重继续不接受网络盘。
* 原 Everything 搜索回归在 `tests_v37/test_everything_search_regression.py`；旧测试更新临界值 `>=` 断言。
* 需要 Windows/Linux GitHub CI、Windows EXE 冒烟、CodeQL、真实 O: 用户权限联调。当前没有任何实际公司 O: 共享盘的挂载或实盘测试结果，不应称为已完成 Windows 实机验收。

**注意**：Windows 管理员提升运行时，映射盘符可能不在相同登录会话中可见。应使用原本连接 O: 的普通用户会话启动 C-Scan。NAS/OneDrive 同步文件夹和 WebDAV 并非都被识别为 DRIVE_REMOTE；仅识别 Windows 映射的网络驱动器。
