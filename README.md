# EZ-Clean - Android 智能清理模块（Magisk/KernelSU）

![EZ-Clean Version](https://img.shields.io/badge/Version-4.0-brightgreen)
![Support](https://img.shields.io/badge/Support-Magisk%20%7C%20KernelSU-blue)
![Android Requirement](https://img.shields.io/badge/Android-7.0%2B-orange)

EZ-Clean模块下载地址:[EZ-Clean](https://github.com/045200/EZ-Clean/releases)

EZ-Clean源码维护:
[Tools-cx-app](https://github.com/Tools-cx-app)

感谢大佬的支持与帮助！

## 版本说明:

## basic:
基础循环清理、MT管理器检测清理、系统感知、系统动态清理

## multi:
基础循环清理、MT管理器检测清理、系统告知、系统动态清理、系统健康报告、系统性能指标清晰、系统自适应

## PS:
由于使用使用同一配置(config.conf)，所有功能存在差异。尽请谅解！

## 项目介绍
EZ-Clean 是一款专为 **Root 后的 Android 设备**设计的智能清理工具，支持通过 **Magisk**（通用 Root 框架）和 **KernelSU**（内核级 Root 框架）以模块形式安装。  
核心功能是自动清理设备冗余文件（如应用缓存、临时文件），同时通过 **系统资源感知** 和 **关键路径保护** 确保清理安全，避免误删系统文件或影响设备稳定性。  

- **程序目录**：模块安装后，核心程序存储于 `/data/adb/modules/EZ-Clean/`（系统级模块目录，不可随意修改或删除）。  
- **数据目录**：配置文件、日志、备份文件统一存储于 `/storage/emulated/0/Android/EZ-Clean/`（用户可访问目录，便于修改配置和查看日志）。  


## 核心功能
### 1. 智能清理触发方式
- **常规定时清理**：按配置间隔（默认 24 小时）自动清理黑名单路径（如 `/data/data/*/cache`、`/storage/emulated/0/Android/data/*/code_cache`），间隔可通过 `config.json` 调整。  
- **MT 管理器触发清理**：实时检测 MT 管理器进程（如 `bin.mt.plus`）或安装包，检测到后自动执行针对性清理（基于 `MT.conf` 配置，不过滤白名单）。  
- **初始清理**：模块安装并重启后，自动执行一次常规清理，快速释放存储空间。  


### 2. 系统资源感知保护
清理行为会根据设备实时状态动态调整，避免占用过多资源导致卡顿：
- **电池保护**：电量低于阈值（默认 20%）且未充电时，自动降低清理强度或暂停清理。  
- **内存/CPU 控制**：内存占用 > 90% 或 CPU 负载 > 90% 时，进入「Critical 紧急状态」，暂停清理以保障设备流畅度；资源恢复后自动恢复。  
- **动态并发调整**：根据系统状态（Optimal → Moderate → Conservative → Critical）自动调整清理线程数（如从 3 线程降至 1 线程）。  


### 3. 安全防护机制
- **关键路径保护**：默认排除 `/system`、`/vendor`、`/data/app` 等系统核心目录，且支持通过 `ExcludeSystem=true` 强化保护，防止误删导致系统异常。  
- **黑白名单控制**：
  - 黑名单（`blacklist.conf`）：定义需要清理的路径，支持通配符 `*`（如 `*cache*` 匹配所有含 cache 的路径）。  
  - 白名单（`whitelist.conf`）：保护重要用户目录（如 `/storage/emulated/0/Download`、`/storage/emulated/0/DCIM`），优先级高于黑名单。  
- **安全模式**：开启后（`SafeMode=true`）仅清理预设的安全路径，适合新手用户，避免误删自定义目录。  


### 4. 灵活配置与日志管理
- **自定义配置**：所有参数通过 `/storage/emulated/0/Android/EZ-Clean/config.conf` 调整，无需修改程序本身，支持调整清理间隔、日志级别、资源阈值等（详见「配置详解」）。  
- **日志系统**：日志文件存储于 `/storage/emulated/0/Android/EZ-Clean/Clean.log`，支持自动压缩旧日志（`LogCompress=true`），可查看清理记录（删除文件数量、释放空间、执行时间）。  


## 支持环境
| 框架类型       | 最低版本要求 | 安装方式                     |
|----------------|--------------|------------------------------|
| Magisk         | v24.0+       | Magisk Manager 刷入 ZIP 模块 |
| KernelSU       | v0.5.0+      | KernelSU Manager 上传模块    |
| Android 系统   | 7.0（API 24）+ | -                            |
| Root 权限      | 必须（KernelSU/Magisk 提供） | -                            |


## 安装步骤
### 1. 准备工作
- 设备已解锁 Bootloader，且成功安装 Magisk 或 KernelSU 并获取 Root 权限。  
- 下载 EZ-Clean 模块 ZIP 包（从 GitHub Release 或指定渠道获取，区分 Magisk/KernelSU 版本）。  


### 2. Magisk 安装
1. 打开 **Magisk Manager** → 切换至「模块」标签页 → 点击底部「从存储安装」。  
2. 在文件浏览器中找到下载的 `EZ-Clean.zip`，选择并确认刷入（无需额外勾选选项）。  
3. 刷入完成后，点击「重启设备」，模块自动激活，核心程序部署至 `/data/adb/modules/EZ-Clean/`，数据目录自动创建。  


### 3. KernelSU 安装
1. 打开 **KernelSU Manager** → 切换至「模块」标签页 → 点击右上角「+」号（上传模块）。  
2. 选择下载的 `EZ-Clean.zip`，等待上传并安装（KernelSU 会自动验证模块兼容性）。  
3. 重启设备，模块通过 KernelSU 加载，数据目录 `/storage/emulated/0/Android/EZ-Clean/` 自动生成。  


### 4. 安装后目录结构
```
/data/adb/modules/EZ-Clean/          # 模块核心目录（系统级，不可修改）
└── EZ                         # EZ-Clean 主程序（二进制文件）
/storage/emulated/0/Android/EZ-Clean/ # 数据目录（用户可访问）
├── config.conf                      # 核心配置文件（可自定义参数）
├── blacklist.conf                   # 清理黑名单（定义需清理路径）
├── whitelist.conf                   # 保护白名单（定义不清理路径）
├── MT.conf                          # MT 触发清理名单（针对性清理规则）
├── Clean.log                        # 清理日志（记录执行过程与结果）
└── backup/                          # 备份目录（启用备份时存储备份文件）
```


## 配置详解
所有可自定义的配置文件均存储于 **`/storage/emulated/0/Android/EZ-Clean/`**，可通过 MT 管理器、Termux 或 Root 文件浏览器编辑（推荐用 MT 管理器，支持语法高亮）。

### 1. 核心配置（`config.conf`）
| 参数名               | 类型    | 默认值       | 说明                                                                 |
|----------------------|---------|--------------|----------------------------------------------------------------------|
| `interval_min`       | int     | 1440         | 定时清理间隔（分钟），默认 24 小时（1440 分钟），可改为 60（1 小时）、300（5 小时）等。 |
| `timed_cleaning`     | bool    | true         | 是否启用定时自动清理：`true` 启用，`false` 仅保留 MT 触发和初始清理。 |
| `mt_cleaning`        | bool    | true         | 是否启用「MT 管理器触发清理」：`true` 检测到 MT 时自动清理，`false` 关闭。 |
| `mt_packages`        | string  | `bin.mt.plus,bin.mt.plus9,bin.mt.plus.debug` | 需要触发清理的 MT 相关包名，多个包用英文逗号分隔，可自行添加。 |
| `safe_mode`          | bool    | true         | 安全模式开关：`true` 仅清理预设安全路径，`false` 允许清理自定义黑名单（需谨慎）。 |
| `battery_threshold`  | int     | 20           | 电池电量阈值（%）：低于此值且未充电时，降低清理强度。                |
| `log_level`          | int     | 3            | 日志级别：0（仅错误）→ 1（基础信息）→ 2（详细信息）→ 3（调试信息）。 |
| `max_concurrent`     | int     | 3            | 最大并发清理线程数：资源感知模式下会根据设备状态动态调整。           |
| `log_compress`       | bool    | false        | 日志压缩开关：`true` 自动压缩 7 天前的日志（生成 `.log.gz`），节省空间。 |
| `backup_enabled`     | bool    | false        | 备份开关：`true` 清理前备份文件至 `backup/` 目录，需确保存储空间充足。 |


### 2. 黑白名单配置
- **黑名单（`blacklist.conf`）**：定义需要清理的路径，每行一条规则，支持通配符 `*` 和注释（`#` 开头的行）。  
  示例（默认规则）：
  ```ini
  # 应用缓存目录（常规清理重点）
  /data/data/*/cache/*
  /storage/emulated/0/Android/data/*/cache/*
  /storage/emulated/0/Android/data/*/code_cache/*
  # 系统临时文件目录
  /data/local/tmp/*
  /storage/emulated/0/tmp/*
  ```

- **白名单（`whitelist.conf`）**：定义需要保护的路径，匹配的路径不会被清理，优先级高于黑名单。  
  示例（默认规则）：
  ```ini
  # 重要用户目录（照片、下载、文档）
  /storage/emulated/0/Download/
  /storage/emulated/0/DCIM/
  /storage/emulated/0/Pictures/
  /storage/emulated/0/Documents/
  # 音乐与视频目录（避免误删媒体文件）
  /storage/emulated/0/Music/
  /storage/emulated/0/Movies/
  ```

- **MT 清理名单（`MT.conf`）**：仅当检测到 MT 管理器时生效，针对性清理 MT 相关冗余路径，不过滤白名单。  
  示例：
  ```ini
  # MT 管理器临时文件
  /storage/emulated/0/MT2/backup/tmp/*
  /storage/emulated/0/MT2/temp/*
  # 常见应用冗余路径
  /storage/emulated/0/QQBrowser/tmp/*
  /storage/emulated/0/com.tencent.mm/MicroMsg/*/cache/
  ```


## 使用指南
### 1. 查看清理日志
日志记录了清理的详细过程（路径、文件数、释放空间、执行时间），便于排查问题：
#### 方式 1：MT 管理器查看
1. 打开 **MT 管理器**，进入路径 `/storage/emulated/0/Android/EZ-Clean/`。  
2. 找到 `Clean.log` 文件，长按选择「打开方式」→「文本查看器」，即可查看最新清理记录。

#### 方式 2：Termux 查看
1. 打开 **Termux**，输入 `su` 并授予 Root 权限（终端提示 `#` 表示已获取 Root）。  
2. 执行命令查看日志：
   ```bash
   cat /storage/emulated/0/Android/EZ-Clean/Clean.log
   ```

### 2. 暂停/恢复清理
#### 临时暂停清理
1. 打开 `config.json`，将 `timed_cleaning` 和 `mt_cleaning` 均改为 `false`。  
2. 保存文件后，模块会在下一次检测周期（约 30 秒）内暂停清理。

#### 恢复自动清理
1. 重新将 `timed_cleaning` 和 `mt_cleaning` 改回 `true`。  
2. 保存文件，模块恢复定时和 MT 触发清理功能。


## 常见问题（FAQ）
### Q1：安装后模块不生效，无日志生成？
A1：
1. 确认模块已激活：Magisk/KernelSU 管理器的「模块」列表中，EZ-Clean 状态为「已启用」，若为「未激活」，重启设备重试。  
2. 检查 Root 权限：打开 Termux 输入 `su`，确认能正常获取 Root（终端显示 `#`），若提示「权限被拒绝」，需重新安装 Magisk/KernelSU 并授予完整 Root 权限。  
3. 验证数据目录：确认 `/storage/emulated/0/Android/EZ-Clean/` 已生成，若未生成，手动创建并授予 755 权限（MT 管理器长按目录 → 「属性」→ 「权限」设置）。

### Q2：清理后发现重要文件丢失？
A3：
1. 检查白名单配置：确认丢失文件的目录是否已加入 `whitelist.conf`，若未加入，补充后重新触发清理可避免后续误删。  
2. 启用备份功能：编辑 `config.json`，将 `backup_enabled` 改为 `true`，模块会在清理前备份文件至 `/storage/emulated/0/Android/EZ-Clean/backup/`，可从中恢复误删文件。  
3. 查看日志定位：通过 `Clean.log` 搜索丢失文件路径，确认是否被模块删除，若为误删且未备份，需通过数据恢复工具（如 DiskDigger）尝试恢复。


### Q3：日志文件过大，占用存储空间？
A4：
1. 开启日志压缩：编辑 `config.json`，将 `LogCompress` 改为 `true`，模块会自动压缩旧日志（生成 `.log.gz` 文件，体积仅为原日志的 10%-20%）。  
2. 手动删除旧日志：通过 MT 管理器进入 `/storage/emulated/0/Android/EZ-Clean/`，删除 `Clean.log` 或过期的 `.log.gz` 文件（保留最新 1-2 个日志文件即可）。


## 免责声明
1. 本模块仅适用于 **合法 Root 的 Android 设备**，使用前请确保已充分了解 Root 可能带来的风险（如设备保修失效、系统稳定性影响）。  
2. 请勿随意修改 `/data/adb/modules/EZ-Clean/` 下的核心程序文件，或删除 `criticalSystemPaths` 定义的系统保护路径，否则可能导致设备无法启动或数据丢失。  
3. 作者不对因误用、配置错误、设备兼容性问题或 Root 环境异常导致的设备损坏、数据丢失承担任何责任。


## 致谢
- 感谢 **Magisk**（Topjohnwu）和 **KernelSU**（tiann）提供的 Root 框架支持，为模块运行提供基础环境。  
- 感谢 MT 管理器团队，其便捷的 Root 文件管理和文本编辑功能，简化了模块的配置与日志查看。  
- 感谢所有贡献者对 EZ-Clean 功能优化、Bug 修复的支持。
- 感谢deepseek/豆包/grok提供编程技术支持。

## 源码与更新
- 源码地址：[GitHub Repository](https://github.com/045200/EZ-Clean)（替换为实际仓库地址）  
- 更新渠道：GitHub Release 同步发布最新版本，支持 Magisk/KernelSU 双框架，建议定期查看日志确认更新内容。