package core

// Config 主配置结构体
type Config struct {
    CleanTime       string   `json:"clean_time"`        // 清理时间，格式 "HH:MM"
    LogLevel        int      `json:"log_level"`         // 日志级别
    LogMaxSize      int      `json:"log_max_size"`      // 日志文件最大大小(MB)
    LogMaxAge       int      `json:"log_max_age"`       // 日志文件保留天数
    LoopCleanEnable bool     `json:"loop_clean_enable"` // 是否启用循环清理
    AppCleanEnable  bool     `json:"app_clean_enable"`  // 是否启用App触发清理
    AppPackages     []string `json:"app_packages"`      // 触发清理的App包名列表
}

// CleanResult 清理结果统计
type CleanResult struct {
    DirsRemoved  int64
    FilesRemoved int64
    SpaceFreed   int64
}