#!/system/bin/sh

SKIPUNZIP=1

# 使用 MODPATH 变量，这是 KernelSU/Magisk 提供的标准模块路径
MODULE_PATH="$MODPATH"
TARGET_PATH="/storage/emulated/0/Android/EZ-Clean"
LOCK_FILE="/data/adb/modules/EZ-Clean/ez_service.pid"
PROCESS_NAME="EZ"

# 输出日志
ui_print ""
ui_print "         正在安装 EZ-Clean 模块"
ui_print ""

# 正确检测 KernelSU 环境
if [ "$KSU" = "true" ]; then
    ui_print "- 检测到 KernelSU 环境"
    IS_KSU=true
elif [ -d "/data/adb/ksu" ]; then
    ui_print "- 检测到 KernelSU 环境（通过目录检测）"
    IS_KSU=true
    KSU=true
else
    ui_print "- 检测到 Magisk 环境"
    IS_KSU=false
    KSU=false
fi

# 检查用户存储路径是否可用
ui_print "- 检查用户存储路径..."
if [ ! -d "/storage/emulated/0" ]; then
    ui_print "  - 错误: 未找到标准用户存储路径"
    ui_print "  - 模块安装失败"
    abort
else
    ui_print "  - 用户存储路径可用"
fi

# 停止正在运行的 EZ 进程
ui_print "- 检查并停止正在运行的 EZ 进程..."

# 检查旧版本中的锁文件
OLD_LOCK_FILE="/data/adb/modules/EZ-Clean/ez_service.pid"
if [ -f "$OLD_LOCK_FILE" ]; then
    ui_print "  - 发现旧版本进程锁文件，读取PID..."
    TARGET_PID=$(cat "$OLD_LOCK_FILE")

    if [ -n "$TARGET_PID" ] && [ "$TARGET_PID" -gt 0 ] 2>/dev/null; then
        ui_print "  - 正在停止进程 PID: $TARGET_PID"

        # 首先尝试优雅终止
        kill -TERM "$TARGET_PID" 2>/dev/null
        sleep 1

        # 检查进程是否仍然存在，如果存在则强制杀死
        if ps -p "$TARGET_PID" > /dev/null 2>&1; then
            ui_print "  - 进程未正常退出，强制终止..."
            kill -KILL "$TARGET_PID" 2>/dev/null
            sleep 1
        fi

        # 再次确认进程已被杀死
        if ! ps -p "$TARGET_PID" > /dev/null 2>&1; then
            ui_print "  - 成功终止 PID: $TARGET_PID"
        else
            ui_print "  - 警告: 可能未能完全终止进程"
        fi
    else
        ui_print "  - 锁文件中的PID无效: $TARGET_PID"
    fi
    
    # 清理旧的锁文件
    rm -f "$OLD_LOCK_FILE"
    ui_print "  - 清理旧锁文件"
else
    ui_print "  - 未找到进程锁文件，可能首次安装或进程未运行"
fi

# 使用进程名查找并终止 (备用方法)
ui_print "  - 使用进程名二次检查..."
PIDs=$(ps -A -o pid,args | grep -v "grep" | grep "$PROCESS_NAME" | awk '{print $1}')

if [ -n "$PIDs" ]; then
    ui_print "  - 发现残留进程，正在清理: $PIDs"
    echo "$PIDs" | while read -r PID; do
        kill -9 "$PID" 2>/dev/null
    done
    sleep 1
else
    ui_print "  - 确认无残留 EZ 进程"
fi

# 创建目标目录（确保路径存在）
ui_print "- 创建目标目录: $TARGET_PATH..."
mkdir -p "$TARGET_PATH"

# 提取模块中指定文件到目标路径
ui_print "- 提取核心文件到目标目录..."
unzip -o "$ZIPFILE" "blacklist.conf" "whitelist.conf" "MT.conf" "config.json" "reload.sh" -d "$TARGET_PATH" >&2

# 提取模块其他必要文件到标准模块路径
ui_print "- 提取模块基础文件到模块路径..."
unzip -o "$ZIPFILE" -x 'META-INF/*' 'blacklist.conf' 'whitelist.conf' 'MT.conf' 'config.json' 'reload.sh' -d "$MODULE_PATH" >&2

# 设置模块路径文件权限
ui_print "- 设置模块路径文件权限..."
set_perm_recursive "$MODULE_PATH" 0 0 0755 0644

# 确保 EZ 二进制文件有执行权限
if [ -f "$MODULE_PATH/EZ" ]; then
    chmod 0755 "$MODULE_PATH/EZ"
    ui_print "  - 设置 EZ 二进制文件执行权限"
fi

# 设置模块服务脚本权限
if [ -f "$MODULE_PATH/service.sh" ]; then
    chmod 0755 "$MODULE_PATH/service.sh"
    ui_print "  - 设置 service.sh 执行权限"
fi
if [ -f "$MODULE_PATH/post-fs-data.sh" ]; then
    chmod 0755 "$MODULE_PATH/post-fs-data.sh"
    ui_print "  - 设置 post-fs-data.sh 执行权限"
fi

# 设置目标路径下文件权限
ui_print "- 设置目标目录文件权限..."

# 由于用户存储区的权限限制，使用 chmod 设置权限
chmod 0755 "$TARGET_PATH" 2>/dev/null
chmod 0644 "$TARGET_PATH"/*.conf 2>/dev/null
chmod 0644 "$TARGET_PATH"/*.json 2>/dev/null

# 单独设置 reload.sh 执行权限
if [ -f "$TARGET_PATH/reload.sh" ]; then
    chmod 0755 "$TARGET_PATH/reload.sh"
    ui_print "  - 设置 reload.sh 执行权限"
fi

# 创建备份目录和日志目录
mkdir -p "$TARGET_PATH/backup"
mkdir -p "$TARGET_PATH/logs"
chmod 0755 "$TARGET_PATH/backup" 2>/dev/null
chmod 0755 "$TARGET_PATH/logs" 2>/dev/null

# 模块功能说明
ui_print "- 模块功能说明:"
ui_print "  • 核心配置文件位于: $TARGET_PATH/"
ui_print "  • 直接编辑 $TARGET_PATH/ 下的文件即可修改模块配置"
ui_print "  • 执行 $TARGET_PATH/reload.sh 可即时重载配置"
ui_print "  • 日志文件保存在: $TARGET_PATH/logs/"

ui_print "- 安装完成!"
ui_print ""
ui_print "模块安装路径: $MODULE_PATH"
ui_print "核心配置目录: $TARGET_PATH"
ui_print ""