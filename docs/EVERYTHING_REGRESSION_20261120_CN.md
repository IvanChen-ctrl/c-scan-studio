# Everything 搜索专项回归升级 — 2026-11-20

基线：未合并的 `v3.7.0-beta.1`（PR #13，commit `bae45e9488c8`）。本修复分支从该版本派生，**不会覆盖 main、合并 PR 或触发任何清理**。

## 已检查的问题与修复

1. **搜索门槛等于边界时遗漏**：ES 旧命令使用 `size:>Nb`，但 Python 过滤用 `>=`；现统一为 `size:>=Nb`。
2. **目录混入文件搜索配额**：ES 查询明确增加官方 `-a-d`（仅文件），保留大小倒序和最多 180 项的只读列表；为上限预留一个额外返回位置。
3. **路径边界**：对每一条索引结果做独立 Windows 本地磁盘路径校验，拒绝跨盘、相似前缀、`..\` 上跳和 UNC 路径；继续 `lstat` 校验实际文件、大小、重解析点和索引过期记录。
4. **索引初始化**：使用官方 ES `-timeout 3500` 允许数据库短暂完成加载；命令仍不使用 shell，且仅运行已经过源文件预置 SHA-256 校验的官方 ES。
5. **零结果核对**：ES 成功返回零条有效结果时，不把“无索引结果”当成“C 盘没有大文件”，改用原有 `os.scandir` 预算扫描确认。
6. **完整性诚实标注**：Everything 查询只覆盖其索引和有限结果，因此永不声称完整扫描 C 盘。备用扫描遇到不可读取目录，也不能再标记 `complete=true`。
7. **重解析目录**：普通大文件遍历在进入排队的目录前重新检查目录类型与重解析标记，减少意外跨目录读取的风险；不声称彻底解决原子文件句柄竞态。

## 回归范围与验证门禁

新增 `tests_v37/test_everything_search_regression.py`，覆盖临界值、ES 参数、路径边界、Unicode、重复项、目录和重解析点、无效 scope、IPC 故障、取消、限制数量、索引误报完整性、空索引回退、权限错误与符号链接。同步更新旧版门槛断言。

GitHub CI 应依次执行：源码清单 SHA-256 只读校验；各代 Python 测试；Node 模拟浏览器交互；Windows/Linux 可重现 ZIP 与摘要对比；Windows 便携 EXE 构建和冒烟测试；CodeQL。只有真实运行成功后才能称为通过。

**未实测的部分**：本环境没有 Windows NTFS 实盘和正在运行的 Everything。模拟进程结果不证明 ES 与真实 Everything 的 IPC 配合、实际索引完整度、中文控制台编码或 Windows 文件系统竞态已在实机验收。未执行真实文件删除、盘符拔插或病毒扫描，不提供此类认证结论。

官方接口依据：[voidtools ES 命令行接口](https://www.voidtools.com/en-us/support/everything/command_line_interface/) 与 [Everything 搜索函数](https://www.voidtools.com/en-us/support/everything/search_functions/)。
