package core

// Config 主配置结构体
type Config struct {
    CleanInterval   int      `json:"clean_interval"`
    LogLevel        int      `json:"log_level"`
    LogMaxSize      int      `json:"log_max_size"`
    LogMaxAge       int      `json:"log_max_age"`
    LoopCleanEnable bool     `json:"loop_clean_enable"`
    AppCleanEnable  bool     `json:"app_clean_enable"`
    AppPackages     []string `json:"app_packages"`
}

// CleanResult 清理结果统计
type CleanResult struct {
    DirsRemoved  int64
    FilesRemoved int64
    SpaceFreed   int64
}