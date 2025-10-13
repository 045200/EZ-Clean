package core

import (
    "context"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"

    "github.com/IGLOU-EU/go-wildcard"
    "ez-clean/pkg/constants"
)

// BasicCleaner 基础版清理器
type BasicCleaner struct {
    config     *Config
    logger     *log.Logger
    cleanMutex sync.Mutex
    appCleanMutex sync.Mutex
}

// NewBasicCleaner 创建基础版清理器
func NewBasicCleaner(config *Config, logger *log.Logger) *BasicCleaner {
    return &BasicCleaner{
        config: config,
        logger: logger,
    }
}

// StartLoopCleaner 启动循环清理定时任务（每天固定时间执行）
func (b *BasicCleaner) StartLoopCleaner(ctx context.Context) {
    if !b.config.LoopCleanEnable {
        LogMessage(b.logger, 1, "循环清理已禁用", b.config)
        return
    }
    
    // 解析清理时间
    cleanTime, err := time.Parse("15:04", b.config.CleanTime)
    if err != nil {
        LogMessage(b.logger, 3, fmt.Sprintf("解析清理时间失败: %v，使用默认时间02:00", err), b.config)
        cleanTime, _ = time.Parse("15:04", "02:00")
    }
    
    LogMessage(b.logger, 1, fmt.Sprintf("循环清理时间: 每天 %s", cleanTime.Format("15:04")), b.config)
    
    // 立即执行一次清理
    go b.PerformLoopCleanup()
    
    for {
        // 计算下一次清理的时间
        now := time.Now()
        nextClean := time.Date(now.Year(), now.Month(), now.Day(), 
            cleanTime.Hour(), cleanTime.Minute(), 0, 0, now.Location())
        
        // 如果今天的时间已经过了，就安排到明天
        if now.After(nextClean) {
            nextClean = nextClean.Add(24 * time.Hour)
        }
        
        durationUntilNextClean := nextClean.Sub(now)
        
        LogMessage(b.logger, 0, fmt.Sprintf("下一次清理将在 %v 后执行", durationUntilNextClean), b.config)
        
        timer := time.NewTimer(durationUntilNextClean)
        
        select {
        case <-timer.C:
            // 执行清理任务
            go b.PerformLoopCleanup()
        case <-ctx.Done():
            timer.Stop()
            LogMessage(b.logger, 1, "循环清理器已停止", b.config)
            return
        }
    }
}

// StartAppTrigger 启动App触发监控
func (b *BasicCleaner) StartAppTrigger(ctx context.Context) {
    if !b.config.AppCleanEnable {
        LogMessage(b.logger, 1, "App触发清理已禁用", b.config)
        return
    }
    
    if len(b.config.AppPackages) == 0 {
        LogMessage(b.logger, 2, "App触发清理: 未配置App包名", b.config)
        return
    }
    
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            if b.isTargetAppRunning() {
                LogMessage(b.logger, 1, "检测到目标App运行，触发清理", b.config)
                go b.PerformAppCleanup()
            }
        case <-ctx.Done():
            LogMessage(b.logger, 1, "App触发监控已停止", b.config)
            return
        }
    }
}

// PerformLoopCleanup 执行循环清理
func (b *BasicCleaner) PerformLoopCleanup() {
    if !b.cleanMutex.TryLock() {
        LogMessage(b.logger, 0, "循环清理: 已有清理任务在进行中，跳过", b.config)
        return
    }
    defer b.cleanMutex.Unlock()
    
    LogMessage(b.logger, 1, "开始循环清理任务", b.config)
    
    blacklist, err := ReadListFile(constants.BlacklistFile)
    if err != nil {
        LogMessage(b.logger, 3, fmt.Sprintf("循环清理: 读取黑名单失败: %v", err), b.config)
        return
    }
    
    whitelist, err := ReadListFile(constants.WhitelistFile)
    if err != nil {
        LogMessage(b.logger, 3, fmt.Sprintf("循环清理: 读取白名单失败: %v", err), b.config)
        return
    }
    
    var totalResult CleanResult
    
    for _, path := range blacklist {
        result := b.cleanPathWithWhitelist(path, whitelist)
        totalResult.DirsRemoved += result.DirsRemoved
        totalResult.FilesRemoved += result.FilesRemoved
        totalResult.SpaceFreed += result.SpaceFreed
    }
    
    // 记录清理结果
    LogMessage(b.logger, 1, fmt.Sprintf(
        "循环清理完成: 删除文件夹%d个, 删除文件%d个, 释放空间%.2f MB",
        totalResult.DirsRemoved,
        totalResult.FilesRemoved,
        float64(totalResult.SpaceFreed)/(1024*1024),
    ), b.config)
}

// PerformAppCleanup 执行App触发清理
func (b *BasicCleaner) PerformAppCleanup() {
    if !b.appCleanMutex.TryLock() {
        LogMessage(b.logger, 0, "App触发清理: 已有清理任务在进行中，跳过", b.config)
        return
    }
    defer b.appCleanMutex.Unlock()
    
    LogMessage(b.logger, 1, "开始App触发清理任务", b.config)
    
    appCleanList, err := ReadListFile(constants.AppConfigFile)
    if err != nil {
        LogMessage(b.logger, 3, fmt.Sprintf("App触发清理: 读取清理名单失败: %v", err), b.config)
        return
    }
    
    var totalResult CleanResult
    
    for _, path := range appCleanList {
        result := b.cleanPath(path)
        totalResult.DirsRemoved += result.DirsRemoved
        totalResult.FilesRemoved += result.FilesRemoved
        totalResult.SpaceFreed += result.SpaceFreed
    }
    
    // 记录清理结果
    LogMessage(b.logger, 1, fmt.Sprintf(
        "App触发清理完成: 删除文件夹%d个, 删除文件%d个, 释放空间%.2f MB",
        totalResult.DirsRemoved,
        totalResult.FilesRemoved,
        float64(totalResult.SpaceFreed)/(1024*1024),
    ), b.config)
}

// ========== 私有清理方法 ==========

func (b *BasicCleaner) cleanPathWithWhitelist(path string, whitelist []string) CleanResult {
    var result CleanResult
    
    if b.isWhitelisted(path, whitelist) {
        LogMessage(b.logger, 0, fmt.Sprintf("循环清理: 跳过白名单路径: %s", path), b.config)
        return result
    }
    
    if strings.Contains(path, "*") {
        // 通配符路径清理
        result = b.cleanWildcardPathWithWhitelist(path, whitelist)
    } else {
        // 具体路径清理
        files, dirs, space, err := removePath(path, b.logger, b.config)
        if err != nil {
            LogMessage(b.logger, 0, fmt.Sprintf("循环清理: 路径不存在或无法删除: %s, 错误: %v", path, err), b.config)
            return result
        }
        result.FilesRemoved = files
        result.DirsRemoved = dirs
        result.SpaceFreed = space
    }
    
    return result
}

func (b *BasicCleaner) cleanPath(path string) CleanResult {
    var result CleanResult
    
    if strings.Contains(path, "*") {
        // 通配符路径清理
        result = b.cleanWildcardPath(path)
    } else {
        // 具体路径清理
        files, dirs, space, err := removePath(path, b.logger, b.config)
        if err != nil {
            LogMessage(b.logger, 0, fmt.Sprintf("App触发清理: 路径不存在或无法删除: %s, 错误: %v", path, err), b.config)
            return result
        }
        result.FilesRemoved = files
        result.DirsRemoved = dirs
        result.SpaceFreed = space
    }
    
    return result
}

func (b *BasicCleaner) cleanWildcardPathWithWhitelist(pattern string, whitelist []string) CleanResult {
    var result CleanResult
    
    baseDir := getBaseDir(pattern)
    
    err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }
        
        if wildcard.Match(pattern, path) {
            if b.isWhitelisted(path, whitelist) {
                LogMessage(b.logger, 0, fmt.Sprintf("循环清理: 跳过白名单路径: %s", path), b.config)
                return nil
            }
            
            files, dirs, space, err := removePath(path, b.logger, b.config)
            if err == nil {
                result.FilesRemoved += files
                result.DirsRemoved += dirs
                result.SpaceFreed += space
            }
        }
        return nil
    })
    
    if err != nil {
        LogMessage(b.logger, 3, fmt.Sprintf("遍历目录失败: %s, 错误: %v", baseDir, err), b.config)
    }
    
    return result
}

func (b *BasicCleaner) cleanWildcardPath(pattern string) CleanResult {
    var result CleanResult
    
    baseDir := getBaseDir(pattern)
    
    err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }
        
        if wildcard.Match(pattern, path) {
            files, dirs, space, err := removePath(path, b.logger, b.config)
            if err == nil {
                result.FilesRemoved += files
                result.DirsRemoved += dirs
                result.SpaceFreed += space
            }
        }
        return nil
    })
    
    if err != nil {
        LogMessage(b.logger, 3, fmt.Sprintf("遍历目录失败: %s, 错误: %v", baseDir, err), b.config)
    }
    
    return result
}

func (b *BasicCleaner) isWhitelisted(path string, whitelist []string) bool {
    for _, pattern := range whitelist {
        if wildcard.Match(pattern, path) {
            return true
        }
    }
    return false
}

func (b *BasicCleaner) isTargetAppRunning() bool {
    for _, app := range b.config.AppPackages {
        if checkProcessRunning(app) {
            LogMessage(b.logger, 0, fmt.Sprintf("检测到App运行: %s", app), b.config)
            return true
        }
    }
    return false
}