package core

import (
    "fmt"
    "log"
    "os"
    "time"
    
    "gopkg.in/natefinch/lumberjack.v2"
    "ez-clean/pkg/constants"
)

// 自定义Writer实现本地时间戳
type localTimeWriter struct {
    logger *lumberjack.Logger
}

func (w *localTimeWriter) Write(p []byte) (n int, err error) {
    localTime := time.Now().Format("2006/01/02 15:04:05")
    logEntry := fmt.Sprintf("%s %s", localTime, string(p))
    return w.logger.Write([]byte(logEntry))
}

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
    
    customWriter := &localTimeWriter{logger: lumberjackLogger}
    logger := log.New(customWriter, "", 0)
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
        logger.Printf("[%s] %s\n", levelStr, message)
    }
}

// shouldLog 判断是否应该记录该等级的日志
func shouldLog(level int, config *Config) bool {
    return level >= config.LogLevel
}