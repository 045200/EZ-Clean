package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    "ez-clean/pkg/core"
    "ez-clean/pkg/multi"
)

func main() {
    // 解析多功能版配置文件
    multiConfig, err := multi.ParseMultiConfig()
    if err != nil {
        if os.IsNotExist(err) {
            log.Printf("多功能配置文件不存在，使用默认配置")
            
            // 创建基础配置
            baseConfig := &core.Config{
                CleanTime:       "02:00", // 默认每天凌晨2点执行
                LogLevel:        1,
                LogMaxSize:      10,
                LogMaxAge:       7,
                LoopCleanEnable: true,
                AppCleanEnable:  true,
            }
            
            // 创建多功能配置
            multiConfig = &multi.MultiConfig{
                Config: baseConfig,
                // 多功能版默认配置
                AIAdaptiveEnable:  true,
                AILearningRate:    0.1,
                MaxCPULimit:       80.0,
                MaxMemoryLimit:    85.0,
                BatteryThreshold:  20.0,
                SystemAdaptEnable: true,
                SamplingEnable:    true,
                SamplingInterval:  60,
                ReportRetention:   30,
            }
            
            // 创建配置目录并保存默认配置
            os.MkdirAll("/storage/emulated/0/Android/EZ-Clean/", 0755)
            if err := multi.SaveMultiConfig(multiConfig); err != nil {
                log.Printf("保存默认配置失败: %v", err)
            }
        } else {
            log.Fatalf("解析多功能配置失败: %v", err)
        }
    }
    
    // 初始化日志系统
    logger, err := core.SetupLogger(multiConfig.Config)
    if err != nil {
        log.Fatalf("初始化日志系统失败: %v", err)
    }
    
    // 创建基础版清理器
    cleaner := core.NewBasicCleaner(multiConfig.Config, logger)
    
    // 创建多功能版增强管理器
    multiManager := multi.NewMultiManager(multiConfig, logger)
    
    // 精简的INFO日志输出
    core.LogMessage(logger, 1, "EZ-Clean 多功能版启动", multiConfig.Config)
    core.LogMessage(logger, 1, fmt.Sprintf("循环清理: %t (%s)", 
        multiConfig.LoopCleanEnable, multiConfig.CleanTime), multiConfig.Config)
    core.LogMessage(logger, 1, fmt.Sprintf("App触发: %t (%d个App)", 
        multiConfig.AppCleanEnable, len(multiConfig.AppPackages)), multiConfig.Config)
    
    // 多功能版增强功能日志
    if multiConfig.AIAdaptiveEnable {
        core.LogMessage(logger, 1, "AI自适应调整: 启用", multiConfig.Config)
    }
    if multiConfig.SystemAdaptEnable {
        core.LogMessage(logger, 1, "系统动态自适应: 启用", multiConfig.Config)
    }
    if multiConfig.SamplingEnable {
        core.LogMessage(logger, 1, "性能采样报告: 启用", multiConfig.Config)
    }
    
    // 创建上下文用于优雅停止
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // 启动基础版功能协程
    go cleaner.StartLoopCleaner(ctx)
    go cleaner.StartAppTrigger(ctx)
    
    // 启动多功能版增强功能协程
    if multiConfig.SystemAdaptEnable {
        go multiManager.StartSystemAdapter(ctx)
        core.LogMessage(logger, 1, "系统自适应模块已启动", multiConfig.Config)
    }
    
    if multiConfig.AIAdaptiveEnable {
        go multiManager.StartAILearning(ctx)
        core.LogMessage(logger, 1, "AI学习模块已启动", multiConfig.Config)
    }
    
    if multiConfig.SamplingEnable {
        go multiManager.StartSampling(ctx)
        core.LogMessage(logger, 1, "性能采样模块已启动", multiConfig.Config)
    }
    
    // 启动多功能版协调器
    go multiManager.StartCoordinator(ctx)
    core.LogMessage(logger, 1, "多功能协调器已启动", multiConfig.Config)
    
    // 保持主程序运行
    core.LogMessage(logger, 1, "多功能版程序运行中...", multiConfig.Config)
    
    // 添加优雅关闭处理
    <-ctx.Done()
    core.LogMessage(logger, 1, "收到停止信号，正在关闭...", multiConfig.Config)
    
    // 给协程一些时间进行清理
    time.Sleep(2 * time.Second)
    core.LogMessage(logger, 1, "EZ-Clean 多功能版已安全退出", multiConfig.Config)
}