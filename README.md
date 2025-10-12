# EZ-Clean - Android 智能清理模块（Magisk/KernelSU）

![EZ-Clean Version](https://img.shields.io/badge/Version-4.0-brightgreen)
![Support](https://img.shields.io/badge/Support-Magisk%20%7C%20KernelSU-blue)
![Android Requirement](https://img.shields.io/badge/Android-7.0%2B-orange)

EZ-Clean模块下载地址:[EZ-Clean](https://github.com/045200/EZ-Clean/releases)

## 项目介绍
EZ-Clean 是一款专为 **Root 后的 Android 设备**设计的智能清理工具，支持通过 **Magisk**（通用 Root 框架）和 **KernelSU**（内核级 Root 框架）以模块形式安装。  
核心功能是自动清理设备冗余文件（如应用缓存、临时文件），同时通过**关键路径保护** 确保清理安全，避免误删系统文件或影响设备稳定性。  

- **程序目录**：模块安装后，核心程序存储于 `/data/adb/modules/EZ-Clean/`（系统级模块目录，不可随意修改或删除）。  
- **数据目录**：配置文件、日志、备份文件统一存储于 `/storage/emulated/0/Android/EZ-Clean/`（用户可访问目录，便于修改配置和查看日志）。  

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
├── App.conf                          # MT 触发清理名单（针对性清理规则）
├── Clean.log                        # 清理日志（记录执行过程与结果）
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


## 常见问题（FAQ）
### Q1：安装后模块不生效，无日志生成？
A1：
1. 确认模块已激活：Magisk/KernelSU 管理器的「模块」列表中，EZ-Clean 状态为「已启用」，若为「未激活」，重启设备重试。  
2. 检查 Root 权限：打开 Termux 输入 `su`，确认能正常获取 Root（终端显示 `#`），若提示「权限被拒绝」，需重新安装 Magisk/KernelSU 并授予完整 Root 权限。  
3. 验证数据目录：确认 `/storage/emulated/0/Android/EZ-Clean/` 已生成，若未生成，手动创建并授予 755 权限（MT 管理器长按目录 → 「属性」→ 「权限」设置）。

### Q2：清理后发现重要文件丢失？
A3：
1. 检查白名单配置：确认丢失文件的目录是否已加入 `whitelist.conf`，若未加入，补充后重新触发清理可避免后续误删。    
3. 查看日志定位：通过 `Clean.log` 搜索丢失文件路径，确认是否被模块删除，若为误删且未备份，需通过数据恢复工具（如 DiskDigger）尝试恢复。


### Q3：日志文件过大，占用存储空间？
A4：  
日志轮转：通过 MT 管理器进入 `/storage/emulated/0/Android/EZ-Clean/`，删除过期的 `.log.gz` 文件（默认保留三条）。


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
- 源码地址：[GitHub Repository](https://github.com/045200/EZ-Clean)  
- 更新渠道：GitHub Release 同步发布最新版本，支持 Magisk/KernelSU 双框架，建议定期查看日志确认更新内容。