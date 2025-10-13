package multi

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "time"

    "ez-clean/pkg/constants"
    "ez-clean/pkg/core"
)

// OutputManager 输出管理器
type OutputManager struct {
    config *MultiConfig
    logger *log.Logger
}

// NewOutputManager 创建输出管理器
func NewOutputManager(config *MultiConfig, logger *log.Logger) *OutputManager {
    return &OutputManager{
        config: config,
        logger: logger,
    }
}

// EnsureOutputDirs 确保输出目录存在
func (o *OutputManager) EnsureOutputDirs() error {
    dirs := []string{
        constants.ReportsDir,
        filepath.Dir(constants.AILearningDataFile),
        filepath.Dir(constants.SystemProfileFile),
        filepath.Dir(constants.PerformanceDataFile),
    }
    
    for _, dir := range dirs {
        if err := os.MkdirAll(dir, 0755); err != nil {
            return fmt.Errorf("创建目录 %s 失败: %v", dir, err)
        }
    }
    
    core.LogMessage(o.logger, 1, "输出目录初始化完成", o.config.Config)
    return nil
}

// WriteSystemProfile 写入系统配置文件
func (o *OutputManager) WriteSystemProfile(profile *SystemInfo) error {
    data, err := json.MarshalIndent(profile, "", "  ")
    if err != nil {
        return fmt.Errorf("序列化系统配置失败: %v", err)
    }
    
    if err := os.WriteFile(constants.SystemProfileFile, data, 0644); err != nil {
        return fmt.Errorf("写入系统配置失败: %v", err)
    }
    
    core.LogMessage(o.logger, 1, fmt.Sprintf("系统配置文件已生成: %s", constants.SystemProfileFile), o.config.Config)
    return nil
}

// WritePerformanceReport 写入性能报告
func (o *OutputManager) WritePerformanceReport(metrics *PerformanceMetrics, history *PerformanceHistory) error {
    report := map[string]interface{}{
        "timestamp":     time.Now().Format(time.RFC3339),
        "current_stats": metrics,
        "history_stats": history,
        "system_info":   "性能采样报告",
    }
    
    data, err := json.MarshalIndent(report, "", "  ")
    if err != nil {
        return fmt.Errorf("序列化性能报告失败: %v", err)
    }
    
    reportFile := fmt.Sprintf("%s/performance_%s.json", constants.ReportsDir, time.Now().Format("20060102_150405"))
    if err := os.WriteFile(reportFile, data, 0644); err != nil {
        return fmt.Errorf("写入性能报告失败: %v", err)
    }
    
    core.LogMessage(o.logger, 1, fmt.Sprintf("性能报告已生成: %s", reportFile), o.config.Config)
    return nil
}

// WriteAdaptiveConfig 写入自适应配置
func (o *OutputManager) WriteAdaptiveConfig(params *AdaptiveParams) error {
    config := map[string]interface{}{
        "timestamp":       time.Now().Format(time.RFC3339),
        "adaptive_params": params,
        "description":     "AI自适应配置参数",
    }
    
    data, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        return fmt.Errorf("序列化自适应配置失败: %v", err)
    }
    
    if err := os.WriteFile(constants.AdaptiveConfigFile, data, 0644); err != nil {
        return fmt.Errorf("写入自适应配置失败: %v", err)
    }
    
    core.LogMessage(o.logger, 1, fmt.Sprintf("自适应配置文件已生成: %s", constants.AdaptiveConfigFile), o.config.Config)
    return nil
}

// WriteModuleStatus 写入模块状态报告
func (o *OutputManager) WriteModuleStatus(manager *MultiManager) error {
    status := map[string]interface{}{
        "timestamp":        time.Now().Format(time.RFC3339),
        "manager_status":   manager.GetStatus(),
        "system_uptime":    manager.GetUptime().String(),
        "coordinator_data": manager.coordinator.GetDecisions(),
        "modules": map[string]bool{
            "system_adapter": manager.adaptive != nil,
            "ai_learner":     manager.aiLearner != nil,
            "sampler":        manager.sampler != nil,
            "coordinator":    manager.coordinator != nil,
        },
    }
    
    data, err := json.MarshalIndent(status, "", "  ")
    if err != nil {
        return fmt.Errorf("序列化模块状态失败: %v", err)
    }
    
    statusFile := fmt.Sprintf("%s/module_status_%s.json", constants.ReportsDir, time.Now().Format("20060102_150405"))
    if err := os.WriteFile(statusFile, data, 0644); err != nil {
        return fmt.Errorf("写入模块状态失败: %v", err)
    }
    
    core.LogMessage(o.logger, 1, fmt.Sprintf("模块状态报告已生成: %s", statusFile), o.config.Config)
    return nil
}

// CleanupOldOutputs 清理旧输出文件
func (o *OutputManager) CleanupOldOutputs() error {
    cutoffTime := time.Now().AddDate(0, 0, -o.config.ReportRetention)
    
    // 清理报告目录
    entries, err := os.ReadDir(constants.ReportsDir)
    if err != nil && !os.IsNotExist(err) {
        return err
    }
    
    for _, entry := range entries {
        if entry.IsDir() {
            continue
        }
        
        info, err := entry.Info()
        if err != nil {
            continue
        }
        
        if info.ModTime().Before(cutoffTime) {
            oldFile := filepath.Join(constants.ReportsDir, entry.Name())
            if err := os.Remove(oldFile); err == nil {
                core.LogMessage(o.logger, 0, fmt.Sprintf("清理旧报告: %s", oldFile), o.config.Config)
            }
        }
    }
    
    return nil
}