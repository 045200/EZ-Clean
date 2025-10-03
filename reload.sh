#!/system/bin/sh

# 重载配置脚本
TARGET_PATH="/storage/emulated/0/Android/EZ-Clean"
LOCK_FILE="/data/adb/modules/EZ-Clean/ez_service.pid"
LOG_DIR="/data/adb/modules/EZ-Clean/logs"
LOG_FILE="$LOG_DIR/ez_service.log"

# 创建日志目录（如果不存在）
mkdir -p "$LOG_DIR"

# 日志函数
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [RELOAD] $1" >> "$LOG_FILE"
}

log_message "开始重载配置..."

# 检查服务是否在运行
if [ ! -f "$LOCK_FILE" ]; then
    echo "错误: EZ 服务未运行"
    log_message "错误: EZ 服务未运行"
    exit 1
fi

# 读取服务 PID
EZ_PID=$(cat "$LOCK_FILE")

if [ -z "$EZ_PID" ] || [ ! -d "/proc/$EZ_PID" ]; then
    echo "错误: EZ 服务进程不存在 (PID: $EZ_PID)"
    log_message "错误: EZ 服务进程不存在 (PID: $EZ_PID)"
    rm -f "$LOCK_FILE"
    exit 1
fi

# 发送重载信号 (假设 EZ 程序监听 USR1 信号进行重载)
kill -USR1 "$EZ_PID" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "配置重载信号已发送"
    log_message "配置重载信号已发送给进程 $EZ_PID"
else
    echo "错误: 无法发送重载信号"
    log_message "错误: 无法发送重载信号给进程 $EZ_PID"
    exit 1
fi

# 等待配置重载完成
sleep 2

# 验证服务是否仍然运行
if [ -d "/proc/$EZ_PID" ]; then
    echo "配置重载完成"
    log_message "配置重载完成"
else
    echo "警告: 服务进程在重载后退出"
    log_message "警告: 服务进程在重载后退出"
fi