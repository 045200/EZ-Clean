##########################################################################################
# Config Flags
##########################################################################################
SKIPMOUNT=false
PROPFILE=true
POSTFSDATA=true
LATESTARTSERVICE=true

# 设备信息
Manufacturer=$(getprop ro.product.vendor.manufacturer 2>/dev/null || getprop ro.product.manufacturer 2>/dev/null)
Codename=$(getprop ro.product.device 2>/dev/null)
Model=$(getprop ro.product.vendor.model 2>/dev/null || getprop ro.product.model 2>/dev/null)
Build=$(getprop ro.build.version.incremental 2>/dev/null)
Android=$(getprop ro.build.version.release 2>/dev/null)
API=$(getprop ro.build.version.sdk 2>/dev/null)
MIUI=$(getprop ro.miui.ui.version.code 2>/dev/null)

getVolumeKey() {
    ui_print "- 监听音量键 按[+]选择是 按[-]选择否"
    local key
    while true; do
        key=$(getevent -qlc 1 2>/dev/null | awk '{ print $3 }' 2>/dev/null)
        case "$key" in
            KEY_VOLUMEUP) return 0 ;;
            KEY_VOLUMEDOWN) return 1 ;;
        esac
    done
}

print_modname() {
    ui_print "===================================================="
    ui_print "- 设备: $Model"
    ui_print "- 制造商: $Manufacturer"
    ui_print "- SDK 平台: API level $API"
    ui_print "- 安卓版本: Android $Android"
    [ -n "$MIUI" ] && ui_print "- 系统版本: MIUI $MIUI"
    ui_print "- 构建版本: $Build"
    ui_print "===================================================="
    ui_print " "
    ui_print " - Magisk Modules Author : 045200"
    ui_print " - Magisk Modules Name: EZ-Clean"
    ui_print " - Magisk Modules Version: 1.0.0"
    ui_print " - 更新时间: 2025-10-04"
    ui_print " "
    ui_print "————————————————————————————————————————————————————————————————"
    ui_print " "
    ui_print " - 欢迎使用 【EZ-Clean】"
    ui_print " - 模块默认启动时间：每天 12 小时运行一次"
    ui_print " - 模块配置目录位于: /storage/emulated/0/Android/EZ-Clean/"
    ui_print " - 模块配置文件包含: *.conf *.json reload.sh"
    ui_print " "
    ui_print "————————————————————————————————————————————————————————————————"
    
    ui_print " "
    ui_print "- 暂停10秒，请详细阅读模块配置路径"
    sleep 10
    ui_print " "

    ui_print "- 是否已阅读并熟知模块配置目录？"
    if getVolumeKey; then
        ui_print "- 您已熟知模块配置目录，为您继续刷入"
    else
        ui_print "- 您未详细阅读模块配置信息，刷入程序终止"
        abort "- 安装中止"
    fi
}

# 安装函数
on_install() {
    ui_print " "
    ui_print "- 开始安装 EZ-Clean 模块..."
    
    # 配置目录路径
    CONFIG_DIR="/storage/emulated/0/Android/EZ-Clean"
    
    # 创建配置目录
    ui_print "- 创建配置目录: $CONFIG_DIR"
    mkdir -p "$CONFIG_DIR" 2>/dev/null
    
    # 检查目录是否创建成功
    if [ ! -d "$CONFIG_DIR" ]; then
        ui_print "- 错误: 无法创建配置目录"
        abort "- 安装失败"
    fi
    
    # 复制配置文件
    ui_print "- 复制配置文件到 $CONFIG_DIR"
    
    # 复制所有.conf文件
    for conf_file in "$MODPATH"/*.conf; do
        if [ -f "$conf_file" ]; then
            filename=$(basename "$conf_file")
            ui_print "- 复制配置文件: $filename"
            cp "$conf_file" "$CONFIG_DIR/" 2>/dev/null
        fi
    done
    
    # 复制.json文件
    for json_file in "$MODPATH"/*.json; do
        if [ -f "$json_file" ]; then
            filename=$(basename "$json_file")
            ui_print "- 复制配置文件: $filename"
            cp "$json_file" "$CONFIG_DIR/" 2>/dev/null
        fi
    done
    
    # 复制 reload.sh 脚本
    if [ -f "$MODPATH/reload.sh" ]; then
        ui_print "- 复制脚本: reload.sh"
        cp "$MODPATH/reload.sh" "$CONFIG_DIR/" 2>/dev/null
    fi
    
    # 设置配置文件权限
    ui_print "- 设置配置文件权限"
    find "$CONFIG_DIR" -type f -name "*.conf" -exec chmod 644 {} + 2>/dev/null
    find "$CONFIG_DIR" -type f -name "*.json" -exec chmod 644 {} + 2>/dev/null
    find "$CONFIG_DIR" -type f -name "reload.sh" -exec chmod 755 {} + 2>/dev/null
    
    # 验证安装
    ui_print "- 验证安装..."
    config_file_count=0
    if [ -d "$CONFIG_DIR" ]; then
        config_file_count=$(ls "$CONFIG_DIR" | wc -l)
        ui_print "- 配置目录中的文件 ($config_file_count 个):"
        ls -la "$CONFIG_DIR" | while read line; do
            ui_print "  $line"
        done
    fi
    
    if [ $config_file_count -gt 0 ]; then
        ui_print "- 安装成功! 共复制 $config_file_count 个配置文件"
        ui_print "- 配置文件位于: $CONFIG_DIR"
    else
        ui_print "- 警告: 配置目录为空"
    fi
    
    ui_print " "
    ui_print "- EZ-Clean 模块安装完成!"
}

# 设置权限函数
set_permissions() {
    # 设置模块文件权限
    set_perm_recursive "$MODPATH" 0 0 0755 0644
    
    # 设置 EZ 二进制程序的执行权限
    if [ -f "$MODPATH/EZ" ]; then
        set_perm "$MODPATH/EZ" 0 0 0755
    fi
    
    # 设置服务脚本权限
    if [ -f "$MODPATH/service.sh" ]; then
        set_perm "$MODPATH/service.sh" 0 0 0755
    fi
    
    ui_print "- 权限设置完成"
}

# KernelSU 特定的安装处理
if [ -n "$KSU" ]; then
    ui_print "- 检测到 KernelSU 环境"
    # 在KernelSU中，MODPATH可能已经设置
    if [ -z "$MODPATH" ]; then
        MODPATH="$1"
    fi
    print_modname
    on_install
    set_permissions
else
    # Magisk 环境
    ui_print "- 检测到 Magisk 环境"
    print_modname
fi