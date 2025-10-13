package core

import (
    "log"
    "os"
    "fmt"
    "time"
    "io"
    "encoding/json"
    "strings"
    "gopkg.in/natefinch/lumberjack.v2"
    "ez-clean/pkg/constants"
)

// SetupLogger 初始化日志系统
func SetupLogger(config *Config) (*log.Logger, error) {
    // 关键修改：通过Android命令获取默认时区并设置
    if err := setAndroidLocalTimeZone(); err != nil {
        return nil, fmt.Errorf("设置Android时区失败: %v", err)
    }

    if err := os.MkdirAll(constants.ConfigDir, 0755); err != nil {
        return nil, fmt.Errorf("创建配置目录失败: %v", err)
    }

    lumberjackLogger := &lumberjack.Logger{
        Filename:   constants.LogFile,
        MaxSize:    config.LogMaxSize,
        MaxBackups: 3,
        MaxAge:     config.LogMaxAge,
        Compress:   true,
    }

    // 创建自定义的writer来添加时间戳
    customWriter := &timestampWriter{writer: lumberjackLogger}
    
    // 创建logger，不使用任何标准前缀
    logger := log.New(customWriter, "", 0)
    return logger, nil
}

// timestampWriter 自定义writer，在每条日志前添加时间戳
type timestampWriter struct {
    writer io.Writer
}

func (tw *timestampWriter) Write(p []byte) (n int, err error) {
    timestamp := time.Now().Format("2006-01-02 15:04:05")
    formatted := fmt.Sprintf("%s %s", timestamp, p)
    return tw.writer.Write([]byte(formatted))
}

// LogMessage 根据日志等级记录日志
func LogMessage(logger *log.Logger, level int, message string, config *Config) {
    if shouldLog(level, config) {
        levelStr := "DEBUG"
        switch level {
        case 0:
            levelStr = "DEBUG"
        case 1:
            levelStr = "INFO"
        case 2:
            levelStr = "WARN"
        case 3:
            levelStr = "ERROR"
        }
        
        // 记录到文件日志
        logger.Printf("[%s] %s", levelStr, message)
        
        // 对于WARN和ERROR级别，同时输出到标准错误
        if level >= 2 {
            // 使用标准错误输出，确保在控制台可见
            log.Printf("[%s] %s", levelStr, message)
            
            // 如果是ERROR级别，还可以考虑其他告警机制
            if level == 3 {
                // 这里可以添加错误告警逻辑，比如发送通知等
                logErrorToStderr(levelStr, message)
            }
        }
    }
}

// shouldLog 判断是否应该记录该等级的日志
func shouldLog(level int, config *Config) bool {
    return level >= config.LogLevel
}

// logErrorToStderr 专门处理ERROR级别的日志输出
func logErrorToStderr(level, message string) {
    // 使用ANSI颜色代码在控制台突出显示错误（如果支持）
    red := "\033[31m"
    reset := "\033[0m"
    
    // 检查是否在终端环境中（支持颜色）
    if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
        // 在终端中，使用红色突出显示错误
        fmt.Fprintf(os.Stderr, "%s[%s] %s%s\n", red, level, message, reset)
    } else {
        // 不在终端中，正常输出
        fmt.Fprintf(os.Stderr, "[%s] %s\n", level, message)
    }
}

// LogMultiMessage 多功能版专用日志函数，包含模块标识
func LogMultiMessage(logger *log.Logger, level int, module, message string, config *Config) {
    if shouldLog(level, config) {
        levelStr := "DEBUG"
        switch level {
        case 0:
            levelStr = "DEBUG"
        case 1:
            levelStr = "INFO"
        case 2:
            levelStr = "WARN"
        case 3:
            levelStr = "ERROR"
        }
        
        formattedMessage := fmt.Sprintf("[%s][%s] %s", levelStr, module, message)
        
        // 记录到文件日志
        logger.Printf("%s", formattedMessage)
        
        // 对于WARN和ERROR级别，同时输出到标准错误
        if level >= 2 {
            // 使用标准错误输出，确保在控制台可见
            log.Printf("%s", formattedMessage)
            
            // 如果是ERROR级别，使用特殊格式
            if level == 3 {
                logErrorToStderr(levelStr, fmt.Sprintf("[%s] %s", module, message))
            }
        }
    }
}

// SetupEnhancedLogger 多功能版增强日志系统
func SetupEnhancedLogger(config *Config, logFile string) (*log.Logger, error) {
    // 设置时区
    if err := setAndroidLocalTimeZone(); err != nil {
        return nil, fmt.Errorf("设置Android时区失败: %v", err)
    }

    // 确保日志目录存在
    logDir := "/storage/emulated/0/Android/EZ-Clean/"
    if err := os.MkdirAll(logDir, 0755); err != nil {
        return nil, fmt.Errorf("创建日志目录失败: %v", err)
    }

    // 配置日志轮转
    lumberjackLogger := &lumberjack.Logger{
        Filename:   logDir + logFile,
        MaxSize:    config.LogMaxSize,
        MaxBackups: 5,  // 多功能版保留更多备份
        MaxAge:     config.LogMaxAge,
        Compress:   true,
    }

    // 创建增强的时间戳writer
    enhancedWriter := &enhancedTimestampWriter{
        writer: lumberjackLogger,
    }
    
    // 创建logger
    logger := log.New(enhancedWriter, "", 0)
    return logger, nil
}

// enhancedTimestampWriter 增强的时间戳writer，包含更详细的时间信息
type enhancedTimestampWriter struct {
    writer io.Writer
}

func (etw *enhancedTimestampWriter) Write(p []byte) (n int, err error) {
    now := time.Now()
    timestamp := now.Format("2006-01-02 15:04:05.000")
    formatted := fmt.Sprintf("%s %s", timestamp, p)
    return etw.writer.Write([]byte(formatted))
}

// LogPerformanceMetrics 记录性能指标日志
func LogPerformanceMetrics(logger *log.Logger, metrics map[string]interface{}, config *Config) {
    if shouldLog(0, config) { // DEBUG级别记录性能指标
        metricsJSON, err := json.Marshal(metrics)
        if err == nil {
            logger.Printf("[PERF] %s", string(metricsJSON))
        }
    }
}

// LogSystemInfo 记录系统信息日志
func LogSystemInfo(logger *log.Logger, systemInfo map[string]string, config *Config) {
    if shouldLog(1, config) { // INFO级别记录系统信息
        infoStr := ""
        for key, value := range systemInfo {
            infoStr += fmt.Sprintf("%s=%s ", key, value)
        }
        logger.Printf("[SYSINFO] %s", strings.TrimSpace(infoStr))
    }
}

// 添加必要的导入
// LogCleanResult 记录清理结果日志
func LogCleanResult(logger *log.Logger, result CleanResult, cleanType string, config *Config) {
    message := fmt.Sprintf("清理完成 - 类型: %s, 删除文件: %d, 删除目录: %d, 释放空间: %.2fMB",
        cleanType,
        result.FilesRemoved,
        result.DirsRemoved,
        float64(result.SpaceFreed)/(1024*1024))
    
    LogMessage(logger, 1, message, config)
}

// LogModuleStatus 记录模块状态日志
func LogModuleStatus(logger *log.Logger, module string, status string, details map[string]interface{}, config *Config) {
    if shouldLog(1, config) {
        detailsStr := ""
        if len(details) > 0 {
            detailsJSON, err := json.Marshal(details)
            if err == nil {
                detailsStr = fmt.Sprintf(" - 详情: %s", string(detailsJSON))
            }
        }
        logger.Printf("[MODULE][%s] %s%s", module, status, detailsStr)
    }
}