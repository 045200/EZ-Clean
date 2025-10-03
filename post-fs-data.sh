#!/system/bin/sh

# 模块路径
MODDIR="${0%/*}"
MODULE_NAME="EZ-Clean"
TARGET_PATH="/storage/emulated/0/Android/EZ-Clean"
LOG_FILE="$TARGET_PATH/logs/ez_service.log"

# 创建日志目录
mkdir -p "$TARGET_PATH/logs"

# 日志函数
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# 启动日志
log_message "=== EZ-Clean post-fs-data.sh 启动 ==="

# 检查必要目录
if [ ! -d "$TARGET_PATH" ]; then
    log_message "错误: 目标路径不存在: $TARGET_PATH"
    mkdir -p "$TARGET_PATH"
    log_message "已重新创建目标路径"
fi

# 检查配置文件是否存在，如果不存在则创建默认配置
if [ ! -f "$TARGET_PATH/blacklist.conf" ]; then
    log_message "创建默认 blacklist.conf"
    echo "# 黑名单配置" > "$TARGET_PATH/blacklist.conf"
    echo "# 每行一个条目" >> "$TARGET_PATH/blacklist.conf"
fi

if [ ! -f "$TARGET_PATH/whitelist.conf" ]; then
    log_message "创建默认 whitelist.conf"
    echo "# 白名单配置" > "$TARGET_PATH/whitelist.conf"
    echo "# 每行一个条目" >> "$TARGET_PATH/whitelist.conf"
fi

if [ ! -f "$TARGET_PATH/config.json" ]; then
    log_message "创建默认 config.json"
    echo '{"enable": true, "interval": 300, "debug": false}' > "$TARGET_PATH/config.json"
fi

# 设置文件权限
chmod 0755 "$TARGET_PATH" 2>/dev/null
chmod 0644 "$TARGET_PATH"/*.conf 2>/dev/null
chmod 0644 "$TARGET_PATH"/*.json 2>/dev/null

if [ -f "$TARGET_PATH/reload.sh" ]; then
    chmod 0755 "$TARGET_PATH/reload.sh"
fi

log_message "=== EZ-Clean post-fs-data.sh 完成 ==="

# 在 post-fs-data 阶段不启动服务，只在 service.sh 中启动
exit 0