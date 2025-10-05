#!/system/bin/sh

# 重载配置脚本
TARGET_PATH="/storage/emulated/0/Android/EZ-Clean"
LOCK_FILE="/data/adb/modules/EZ-Clean/ez_service.pid"
LOG_DIR="/data/adb/modules/EZ-Clean/logs"
LOG_FILE="$LOG_DIR/ez_service.log"
EZ_BINARY="/data/adb/modules/EZ-Clean/EZ"

# 创建日志目录（如果不存在）
mkdir -p "$LOG_DIR"

# 日志函数
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [RELOAD] $1" >> "$LOG_FILE"
}

log_message "开始重载配置..."

# 检查服务是否在运行
if [ ! -f "$LOCK_FILE" ]; then
    echo "警告: EZ 服务未运行，直接启动服务"
    log_message "警告: EZ 服务未运行，直接启动服务"
else
    # 读取服务 PID
    EZ_PID=$(cat "$LOCK_FILE")
    
    if [ -n "$EZ_PID" ] && [ -d "/proc/$EZ_PID" ]; then
        echo "停止运行中的 EZ 服务 (PID: $EZ_PID)"
        log_message "停止运行中的 EZ 服务 (PID: $EZ_PID)"
        
        # 杀死进程
        kill "$EZ_PID" 2>/dev/null
        
        # 等待进程结束
        sleep 2
        
        # 强制杀死（如果普通kill无效）
        if [ -d "/proc/$EZ_PID" ]; then
            echo "进程未正常退出，强制杀死"
            log_message "进程未正常退出，强制杀死 (PID: $EZ_PID)"
            kill -9 "$EZ_PID" 2>/dev/null
        fi
    else
        echo "警告: EZ 服务进程不存在 (PID: $EZ_PID)"
        log_message "警告: EZ 服务进程不存在 (PID: $EZ_PID)"
    fi
    
    # 删除锁文件
    rm -f "$LOCK_FILE"
fi

# 检查EZ二进制文件是否存在
if [ ! -f "$EZ_BINARY" ]; then
    echo "错误: EZ 二进制文件不存在: $EZ_BINARY"
    log_message "错误: EZ 二进制文件不存在: $EZ_BINARY"
    exit 1
fi

# 检查EZ二进制文件是否可执行
if [ ! -x "$EZ_BINARY" ]; then
    echo "设置 EZ 二进制文件为可执行"
    log_message "设置 EZ 二进制文件为可执行"
    chmod +x "$EZ_BINARY"
fi

# 启动EZ服务
echo "启动 EZ 服务..."
log_message "启动 EZ 服务: $EZ_BINARY"

# 在后台运行EZ二进制文件，并保存PID
"$EZ_BINARY" &
NEW_PID=$!

# 验证新进程是否启动成功
sleep 1
if [ -d "/proc/$NEW_PID" ]; then
    # 保存新的PID到锁文件
    echo "$NEW_PID" > "$LOCK_FILE"
    echo "EZ 服务启动成功 (PID: $NEW_PID)"
    log_message "EZ 服务启动成功 (PID: $NEW_PID)"
    log_message "配置重载完成"
else
    echo "错误: EZ 服务启动失败"
    log_message "错误: EZ 服务启动失败"
    exit 1
fi