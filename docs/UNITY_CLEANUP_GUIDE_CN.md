# Unity 放在 D 盘，C 盘仍变小：专项使用指南

适用版本：C-Scan Studio **3.7.0-beta.1**。程序本身默认只扫描，运行它不会立即清理。

## 一、先用新版看清楚

1. 将整个便携包解压到 D 盘的一个新目录。EXE 包双击 `CScanStudio.exe`；源码包双击 `00_启动C-Scan智能清理与安全中心.bat`。不要在压缩包内直接启动。
2. 保存 Unity 工程并关闭 Unity Editor、Unity Hub 以及正在运行的构建。程序会检查相关进程；不会强制结束它们。
3. 在左侧进入 **Unity 专项**。
4. 第一次保留 **“保留离线包缓存”** 的勾选，点击专项扫描。
5. 先看“C 盘已检测占用”，再看每一项的完整路径、所在盘、扫描状态和处理建议。其他盘占用与 C 盘分开统计。
6. 如需清理，手动选择可处理项目，点击 **“预览已选 Unity 缓存”**。核对完整文件清单和清理代价后，输入 `DELETE` 确认。
7. 清理结束后重新扫描。清理前后 C 盘净空闲变化会受同时运行的其他程序影响；列表中的逻辑字节不等于保证释放的物理字节。

**UPM 包缓存默认不能选。** 如果确认可以联网重新下载、也不需要保留旧包作离线构建，取消“保留离线包缓存”，然后重新扫描。仅取消勾选不会解锁上一次扫描的候选清单。

“不完整”“已取消”“相关程序运行”或“进程检测不可用”不是零占用证明。先排除原因再重扫。进程状态无法确认时不会执行相关清理。

## 二、本版能处理哪些内容

| 项目 | 本版功能 | 清理后的影响 |
| --- | --- | --- |
| Unity 6 UPM 默认全局缓存 | 扫描；解除离线保护并重新扫描后可预览清理 | 可能重新下载、解包；无网络或原包不可获得时可能无法还原依赖 |
| 旧版 UPM npm / packages / git-lfs | 分别扫描；同样受离线保护 | 旧 Unity 工程可能仍在使用，不能因装了 Unity 6 就判作无用 |
| GI 全局光照缓存 | 扫描、手动选择后预览清理 | 后续烘焙重新计算，可能显著变慢；优先考虑限额或改址 |
| Editor / UPM 旧日志 | 仅匹配四个明确日志名，且至少 14 天 | 会失去对应历史诊断记录 |
| Bee 构建缓存 | 只读统计，提供改址和官方处理建议 | 影响跨项目增量构建，程序不进行外部批量删除 |
| Asset Store 下载包 | 只读统计，提供备份和改址建议 | 下架或旧版本资源未必能重新下载 |
| Gradle caches / wrapper 分发包 | 只读统计 | 多个 Android 项目可能共用，离线构建依赖这些文件 |
| Hub 日志、自定义缓存路径、环境变量指定的 SDK | 只读统计 / 路径诊断 | 不加入自动清理白名单 |
| Hub 下载目录、项目 Library / Temp / obj | 提供位置核实与处理指南 | 本版不推断私有配置格式、不自动枚举或删除所有项目 |

旧日志精确范围：`Editor.log`、`Editor-prev.log`、`upm.log`、`upm-prev.log`，只匹配 Editor 日志目录下的直接文件。不会递归清空 Editor 目录。

## 三、为什么 D 盘安装仍占 C 盘

编辑器安装位置、工程位置、全局缓存位置是独立设置。常见 Windows 用户位置如下；用户配置、编辑器版本和运行账户可能改变实际位置。

| 类型 | 常见位置 |
| --- | --- |
| Unity 6 UPM | `%LOCALAPPDATA%\Unity\cache\upm` |
| 旧版 UPM | `%LOCALAPPDATA%\Unity\cache\npm`、`packages`、`git-lfs` |
| GI 候选位置 | `%USERPROFILE%\AppData\LocalLow\Unity\Caches\GiCache`，以 Preferences 实际显示为准 |
| Bee | `%USERPROFILE%\AppData\Local\Unity\Caches\bee` |
| Asset Store | `%APPDATA%\Unity\Asset Store-5.x` |
| Gradle 默认缓存 | `%USERPROFILE%\.gradle\caches`、`.gradle\wrapper\dists` |
| Hub 下载 | Hub → Settings → Installs → Downloads location；默认使用系统 temp |

程序读取当前进程的缓存环境变量，并仅从用户 `.upmconfig.toml` 提取根级 `cacheRoot`。不会把包含 registry 凭据的完整配置写入报告。报告会标注读取范围：**没有读取系统注册表、Unity Preferences、Hub 私有配置或编辑器启动命令行**，因此不能据此保证已经发现所有缓存。

为了不误删用户自定义目录，配置中的路径只用于有界的只读统计。盘根、用户根、系统目录、网络路径、目录联接和符号链接不会被当作可清理目标。

## 四、防止 C 盘再次增长

建议使用有足够空间的本机 SSD，例如 D 盘。以下是候选设置，程序不会擅自修改、复制或删除现有缓存。

### 1. UPM 包缓存

在支持的 Unity 版本中打开 **Edit → Preferences → Package Manager → Packages → Cache Location → Change Location**，选择专用目录，例如 `D:\UnityCache\UPM`。

也可使用官方 `UPM_CACHE_ROOT`。如果旧版工程还设置了 `UPM_NPM_CACHE_PATH`、`UPM_CACHE_PATH` 或 `UPM_GIT_LFS_CACHE_PATH`，需要分别核对；单独改一个根变量不能证明所有版本都已迁移。环境变量变更后应重新启动 Hub、Editor 和本工具，核对实际路径。

Unity 的 `UPM_MAX_CACHE_SIZE` 限制的是 UPM `db` 子缓存，不是全部 Unity 缓存。不要把这个值当作整机缓存总上限。

### 2. GI 光照缓存

打开 **Edit → Preferences → GI Cache**：先检查当前目录和容量上限；按需要设置 **Custom cache location**，例如 `D:\UnityCache\GI`。上限过小会导致反复重算，需要结合项目使用情况调整。

Unity 运行时要使用编辑器提供的 **Clean Cache**。本工具的外部清理要求关闭相关进程。

### 3. Asset Store

打开 **Preferences → Package Manager → My Assets → Cache Location → Change Location**，选择新位置。对于可能下架、难以恢复的包先备份。`ASSETSTORE_CACHE_PATH` 指向父根，其下使用 `Asset Store-5.x`，不要重复拼接该层目录。

### 4. Bee、Gradle 和 Hub

- Bee 可通过官方 `BEE_CACHE_DIRECTORY` 设置位置，修改后验证构建。外部删除增量构建缓存可能使后续构建出现问题。
- Gradle 可配置 `GRADLE_USER_HOME`，它还包含配置和初始化脚本，不能把整个目录当垃圾删掉。
- Hub 的 **Downloads location** 与 **Installs location** 是两项不同设置，都检查一次。只改编辑器安装位置不能改变下载临时位置。

**改缓存位置不等于已释放 C 盘。** 若需要保留缓存，采用“复制并核对 → 修改设置 → 打开项目并完成构建验证 → 再决定如何处理旧副本”的顺序。不要直接剪切、批量创建目录联接，或把项目源文件与缓存混在一起迁移。

## 五、始终保护的内容

`Assets`、`Packages`、`ProjectSettings`、`UserSettings`、`.meta`、源码、备份、导出包、Unity 安装目录、SDK/NDK/OpenJDK、`.android` 中的密钥和设备数据，以及 Unity 许可证均不属于专项清理目标。

尤其不要清空 `%PROGRAMDATA%\Unity`、`%LOCALAPPDATA%\Unity`、`%APPDATA%\UnityHub`、`.gradle` 或 `Unity\cache` 整个父目录。程序仅允许经过验证的缓存叶目录与指定日志文件。

## 六、官方依据

- [Unity 6 UPM 全局缓存位置与离线用途](https://docs.unity.com/en-us/engine/6000.0/manual/packages-list/package-manager-caches/upm-cache)
- [UPM 改址、环境变量和大小限制](https://docs.unity.com/en-us/engine/6000.0/manual/packages-list/package-manager-caches/upm-config-cache)
- [旧版 UPM 缓存配置](https://docs.unity3d.com/2022.3/Documentation/Manual/upm-config-cache.html)
- [GI 缓存偏好与清理限制](https://docs.unity.com/en-us/engine/6000.0/manual/unity-editor/editor-settings-reference/preferences/gi-cache)
- [GI 常见 Windows 路径的官方问题记录](https://issuetracker.unity.com/issues/16226)
- [Bee 与项目构建缓存位置](https://docs.unity.com/en-us/engine/6000.0/manual/building-and-publishing/build-cache-location-reference)
- [Asset Store 缓存改址](https://docs.unity.com/en-us/engine/6000.0/manual/packages-list/package-manager-caches/upm-config-cache-as)
- [Hub 下载和安装位置](https://docs.unity.com/en-us/hub/settings)
- [Gradle 用户目录与缓存](https://docs.gradle.org/current/userguide/directory_layout.html)

文档核对日期：2026-11-10。具体编辑器版本中的菜单名称可能不同，以其实际设置为准。
