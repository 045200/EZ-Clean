package core

import (
    "log"
    "os"
    
    "gopkg.in/natefinch/lumberjack.v2"
    "ez-clean/pkg/constants"
)

// SetupLogger 初始化日志系统
func SetupLogger(config *Config) (*log.Logger, error) {
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
    
    // 直接使用 lumberjack.Logger，它会自动添加时间戳
    logger := log.New(lumberjackLogger, "", log.LstdFlags)
    return logger, nil
}

// LogMessage 根据日志等级记录日志
func LogMessage(logger *log.Logger, level int, message string, config *Config) {
    if shouldLog(level, config) {
        levelStr := "DEBUG"
        switch level {
        case 1:
            levelStr = "INFO"
        case 2:
            levelStr = "WARN"
        case 3:
            levelStr = "ERROR"
        }
        logger.Printf("[%s] %s", levelStr, message)
    }
}

// shouldLog 判断是否应该记录该等级的日志
func shouldLog(level int, config *Config) bool {
    return level >= config.LogLevel
}