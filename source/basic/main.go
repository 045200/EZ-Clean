package main

import (
    "context"
    "fmt"
    "log"
    "os"

    "ez-clean/pkg/core"
)

func main() {
    // 解析配置文件
    config, err := core.ParseConfig()
    if err != nil {
        if os.IsNotExist(err) {
            log.Printf("配置文件不存在，使用默认配置")
            config = &core.Config{
                CleanTime:        "02:00", // 默认每天凌晨2点执行
                LogLevel:         1,
                LogMaxSize:       10,
                LogMaxAge:        7,
                LoopCleanEnable:  true,
                AppCleanEnable:   true,
            }
            // 创建配置目录
            os.MkdirAll("/storage/emulated/0/Android/EZ-Clean/", 0755)
        } else {
            log.Fatalf("解析配置失败: %v", err)
        }
    }
    
    // 初始化日志系统
    logger, err := core.SetupLogger(config)
    if err != nil {
        log.Fatalf("初始化日志系统失败: %v", err)
    }
    
    // 创建基础版清理器
    cleaner := core.NewBasicCleaner(config, logger)
    
    // 精简的INFO日志输出
    core.LogMessage(logger, 1, "EZ-Clean 基础版启动", config)
    core.LogMessage(logger, 1, fmt.Sprintf("循环清理: %t (%s)", config.LoopCleanEnable, config.CleanTime), config)
    core.LogMessage(logger, 1, fmt.Sprintf("App触发: %t (%d个App)", config.AppCleanEnable, len(config.AppPackages)), config)
    
    // 创建上下文用于优雅停止
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // 启动清理协程
    go cleaner.StartLoopCleaner(ctx)
    go cleaner.StartAppTrigger(ctx)
    
    // 保持主程序运行
    core.LogMessage(logger, 1, "基础版程序运行中...", config)
    select {}
}