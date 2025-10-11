#!/system/bin/sh

# 模块路径
MODDIR="${0%/*}"
LOCK_FILE="$MODDIR/ez_service.pid"
LOG_FILE="$MODDIR/logs/ez_service.log"  # 修正了这行的语法错误
MAX_LOG_SIZE=$((3 * 1024 * 1024)) # 3MB

# 日志函数
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# 日志轮替
perform_log_rotation() {
    if [ -f "$LOG_FILE" ] && [ "$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)" -ge "$MAX_LOG_SIZE" ]; then
        mv "$LOG_FILE" "$LOG_FILE.old"
        log_message "=== 日志文件已轮替 ==="
    fi
}

# 等待系统启动完成
wait_for_boot_complete() {
    log_message "等待系统启动完成..."
    while [ "$(getprop sys.boot_completed)" != "1" ]; do
        sleep 5
    done
    sleep 10 # 额外等待时间确保系统完全就绪
}

# 清理之前的PID文件
cleanup_old_pid() {
    if [ -f "$LOCK_FILE" ]; then
        old_pid=$(cat "$LOCK_FILE")
        if [ -n "$old_pid" ] && [ -d "/proc/$old_pid" ]; then
            log_message "发现已有EZ进程运行 (PID: $old_pid)，正在停止..."
            kill "$old_pid" 2>/dev/null
            sleep 2
        fi
        rm -f "$LOCK_FILE"
    fi
}

# 主要启动逻辑
main() {
    # 创建日志目录
    mkdir -p "$(dirname "$LOG_FILE")"
    perform_log_rotation
    
    log_message "=== 开始启动 EZ 服务 ==="
    log_message "模块目录: $MODDIR"

    # 等待系统启动
    wait_for_boot_complete
    log_message "系统启动完成，继续执行..."

    # 检查 EZ 二进制文件是否存在
    if [ ! -f "$MODDIR/EZ" ]; then
        log_message "错误: EZ 二进制文件不存在于 $MODDIR/"
        exit 1
    fi

    # 确保 EZ 有执行权限
    chmod 0755 "$MODDIR/EZ" 2>/dev/null
    if [ $? -ne 0 ]; then
        log_message "警告: 设置 EZ 可执行权限失败"
    fi

    # 清理之前的进程
    cleanup_old_pid

    # 启动 EZ
    log_message "启动 EZ 进程..."
    "$MODDIR/EZ" >> "$LOG_FILE" 2>&1 &
    ez_pid=$!

    # 记录 PID
    echo $ez_pid > "$LOCK_FILE"
    log_message "EZ 服务启动成功 (PID: $ez_pid)"
    log_message "启动脚本执行完成"

    exit 0
}

# 执行主函数
main