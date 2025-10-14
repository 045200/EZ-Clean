package multi

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "os/exec"
    "strconv"
    "strings"
    "sync"
    "time"

    "ez-clean/pkg/core"
    "ez-clean/pkg/constants"
)

// PerformanceSampler 性能采样模块
type PerformanceSampler struct {
    config    *MultiConfig
    logger    *log.Logger
    mu        sync.RWMutex
    metrics   *PerformanceMetrics
    history   *PerformanceHistory
}

// PerformanceHistory 性能历史数据
type PerformanceHistory struct {
    Timestamps   []time.Time        `json:"timestamps"`
    CPULoad      []float64          `json:"cpu_load"`
    MemoryUsage  []float64          `json:"memory_usage"`
    BatteryLevel []float64          `json:"battery_level"`
    ThermalState []string           `json:"thermal_state"`
    StartTime    time.Time          `json:"start_time"`
    SampleCount  int                `json:"sample_count"`
}

// NewPerformanceSampler 创建性能采样模块
func NewPerformanceSampler(config *MultiConfig, logger *log.Logger) *PerformanceSampler {
    sampler := &PerformanceSampler{
        config: config,
        logger: logger,
        metrics: &PerformanceMetrics{
            Timestamp: time.Now(),
        },
        history: &PerformanceHistory{
            Timestamps:   make([]time.Time, 0),
            CPULoad:      make([]float64, 0),
            MemoryUsage:  make([]float64, 0),
            BatteryLevel: make([]float64, 0),
            ThermalState: make([]string, 0),
            StartTime:    time.Now(),
        },
    }
    
    // 加载历史数据
    sampler.loadHistoryData()
    
    return sampler
}

// CollectMetrics 收集性能指标
func (p *PerformanceSampler) CollectMetrics() error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    core.LogMessage(p.logger, 0, "开始性能采样", p.config.Config)
    
    // 收集CPU负载
    cpuLoad, err := p.getCPULoad()
    if err != nil {
        return fmt.Errorf("获取CPU负载失败: %v", err)
    }
    p.metrics.CPULoad = cpuLoad
    
    // 收集内存使用
    memoryUsage, err := p.getMemoryUsage()
    if err != nil {
        return fmt.Errorf("获取内存使用失败: %v", err)
    }
    p.metrics.MemoryUsage = memoryUsage
    
    // 收集电池电量
    batteryLevel, err := p.getBatteryLevel()
    if err != nil {
        return fmt.Errorf("获取电池电量失败: %v", err)
    }
    p.metrics.BatteryLevel = batteryLevel
    
    // 收集温度状态
    thermalState, err := p.getThermalState()
    if err != nil {
        return fmt.Errorf("获取温度状态失败: %v", err)
    }
    p.metrics.ThermalState = thermalState
    
    p.metrics.Timestamp = time.Now()
    
    // 添加到历史记录
    p.addToHistory(p.metrics)
    
    // 定期保存历史数据
    if p.history.SampleCount%10 == 0 {
        if err := p.saveHistoryData(); err != nil {
            core.LogMessage(p.logger, 2, fmt.Sprintf("保存历史数据失败: %v", err), p.config.Config)
        }
    }
    
    core.LogMessage(p.logger, 0, fmt.Sprintf("性能采样完成: CPU=%.1f%%, 内存=%.1f%%, 电池=%.1f%%, 温度=%s", 
        cpuLoad, memoryUsage, batteryLevel, thermalState), p.config.Config)
    
    return nil
}

// GetCurrentMetrics 获取当前性能指标
func (p *PerformanceSampler) GetCurrentMetrics() (*PerformanceMetrics, error) {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    // 返回当前指标的副本
    metrics := *p.metrics
    return &metrics, nil
}

// GenerateDailyReport 生成日报
func (p *PerformanceSampler) GenerateDailyReport() error {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    core.LogMessage(p.logger, 1, "生成性能日报", p.config.Config)
    
    report := p.generateReportData()
    
    // 确保报告目录存在
    if err := os.MkdirAll(constants.ReportsDir, 0755); err != nil {
        return fmt.Errorf("创建报告目录失败: %v", err)
    }
    
    // 生成报告文件
    reportFile := fmt.Sprintf("%s/report_%s.json", constants.ReportsDir, time.Now().Format("20060102"))
    data, err := json.MarshalIndent(report, "", "  ")
    if err != nil {
        return fmt.Errorf("序列化报告失败: %v", err)
    }
    
    if err := os.WriteFile(reportFile, data, 0644); err != nil {
        return fmt.Errorf("保存报告失败: %v", err)
    }
    
    // 清理旧报告
    p.cleanupOldReports()
    
    core.LogMessage(p.logger, 1, fmt.Sprintf("日报已生成: %s", reportFile), p.config.Config)
    
    return nil
}

// GetPerformanceHistory 获取性能历史数据
func (p *PerformanceSampler) GetPerformanceHistory() *PerformanceHistory {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    return p.history
}

// ========== 私有方法 ==========

func (p *PerformanceSampler) getCPULoad() (float64, error) {
    // 通过读取/proc/stat获取CPU使用率
    data, err := os.ReadFile("/proc/stat")
    if err != nil {
        return 0, err
    }
    
    lines := strings.Split(string(data), "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, "cpu ") {
            fields := strings.Fields(line)
            if len(fields) >= 8 {
                // 解析CPU时间
                user, _ := strconv.ParseUint(fields[1], 10, 64)
                nice, _ := strconv.ParseUint(fields[2], 10, 64)
                system, _ := strconv.ParseUint(fields[3], 10, 64)
                idle, _ := strconv.ParseUint(fields[4], 10, 64)
                iowait, _ := strconv.ParseUint(fields[5], 10, 64)
                irq, _ := strconv.ParseUint(fields[6], 10, 64)
                softirq, _ := strconv.ParseUint(fields[7], 10, 64)
                
                total := user + nice + system + idle + iowait + irq + softirq
                used := total - idle
                
                // 计算使用率百分比
                if total > 0 {
                    return float64(used) / float64(total) * 100, nil
                }
            }
            break
        }
    }
    
    return 0, fmt.Errorf("无法解析CPU统计信息")
}

func (p *PerformanceSampler) getMemoryUsage() (float64, error) {
    // 通过读取/proc/meminfo获取内存使用情况
    data, err := os.ReadFile("/proc/meminfo")
    if err != nil {
        return 0, err
    }
    
    var memTotal, memAvailable uint64
    
    lines := strings.Split(string(data), "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, "MemTotal:") {
            fields := strings.Fields(line)
            if len(fields) >= 2 {
                memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
            }
        } else if strings.HasPrefix(line, "MemAvailable:") {
            fields := strings.Fields(line)
            if len(fields) >= 2 {
                memAvailable, _ = strconv.ParseUint(fields[1], 10, 64)
            }
        }
    }
    
    if memTotal > 0 && memAvailable <= memTotal {
        used := memTotal - memAvailable
        return float64(used) / float64(memTotal) * 100, nil
    }
    
    return 0, fmt.Errorf("无法解析内存信息")
}

func (p *PerformanceSampler) getBatteryLevel() (float64, error) {
    // 尝试通过Android系统文件获取电池信息
    batteryFiles := []string{
        "/sys/class/power_supply/battery/capacity",
        "/sys/class/power_supply/batt_capacity",
        "/sys/class/power_supply/battery/charge_counter",
    }
    
    for _, file := range batteryFiles {
        if data, err := os.ReadFile(file); err == nil {
            if level, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil {
                return level, nil
            }
        }
    }
    
    // 如果无法读取系统文件，尝试使用dumpsys命令
    cmd := exec.Command("dumpsys", "battery")
    output, err := cmd.Output()
    if err == nil {
        lines := strings.Split(string(output), "\n")
        for _, line := range lines {
            if strings.Contains(line, "level:") {
                fields := strings.Fields(line)
                if len(fields) >= 2 {
                    if level, err := strconv.ParseFloat(fields[1], 64); err == nil {
                        return level, nil
                    }
                }
            }
        }
    }
    
    return 100.0, nil // 默认返回100%
}

func (p *PerformanceSampler) getThermalState() (string, error) {
    // 读取温度信息
    thermalFiles := []string{
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/class/thermal/thermal_zone1/temp",
        "/sys/devices/virtual/thermal/thermal_zone0/temp",
    }
    
    for _, file := range thermalFiles {
        if data, err := os.ReadFile(file); err == nil {
            if temp, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
                tempC := float64(temp) / 1000.0
                
                if tempC > 80 {
                    return "critical", nil
                } else if tempC > 70 {
                    return "hot", nil
                } else if tempC > 60 {
                    return "warm", nil
                } else {
                    return "normal", nil
                }
            }
        }
    }
    
    return "unknown", nil
}

func (p *PerformanceSampler) addToHistory(metrics *PerformanceMetrics) {
    p.history.Timestamps = append(p.history.Timestamps, metrics.Timestamp)
    p.history.CPULoad = append(p.history.CPULoad, metrics.CPULoad)
    p.history.MemoryUsage = append(p.history.MemoryUsage, metrics.MemoryUsage)
    p.history.BatteryLevel = append(p.history.BatteryLevel, metrics.BatteryLevel)
    p.history.ThermalState = append(p.history.ThermalState, metrics.ThermalState)
    p.history.SampleCount++
    
    // 限制历史数据大小
    if len(p.history.Timestamps) > 1000 {
        p.history.Timestamps = p.history.Timestamps[100:]
        p.history.CPULoad = p.history.CPULoad[100:]
        p.history.MemoryUsage = p.history.MemoryUsage[100:]
        p.history.BatteryLevel = p.history.BatteryLevel[100:]
        p.history.ThermalState = p.history.ThermalState[100:]
    }
}

func (p *PerformanceSampler) generateReportData() map[string]interface{} {
    report := make(map[string]interface{})
    
    // 基础信息
    report["generated_at"] = time.Now().Format(time.RFC3339)
    report["sample_count"] = p.history.SampleCount
    report["duration_hours"] = time.Since(p.history.StartTime).Hours()
    
    // 统计信息
    if len(p.history.CPULoad) > 0 {
        stats := p.calculateStats(p.history.CPULoad)
        report["cpu_stats"] = stats
    }
    
    if len(p.history.MemoryUsage) > 0 {
        stats := p.calculateStats(p.history.MemoryUsage)
        report["memory_stats"] = stats
    }
    
    if len(p.history.BatteryLevel) > 0 {
        stats := p.calculateStats(p.history.BatteryLevel)
        report["battery_stats"] = stats
    }
    
    // 温度状态分布
    thermalDist := make(map[string]int)
    for _, state := range p.history.ThermalState {
        thermalDist[state]++
    }
    report["thermal_distribution"] = thermalDist
    
    // 性能趋势
    report["performance_trend"] = p.calculateTrend()
    
    return report
}

func (p *PerformanceSampler) calculateStats(data []float64) map[string]interface{} {
    if len(data) == 0 {
        return nil
    }
    
    stats := make(map[string]interface{})
    
    var sum float64
    min := data[0]
    max := data[0]
    
    for _, value := range data {
        sum += value
        if value < min {
            min = value
        }
        if value > max {
            max = value
        }
    }
    
    stats["average"] = sum / float64(len(data))
    stats["min"] = min
    stats["max"] = max
    stats["samples"] = len(data)
    
    return stats
}

func (p *PerformanceSampler) calculateTrend() map[string]interface{} {
    trend := make(map[string]interface{})
    
    // 简单的趋势分析
    if len(p.history.CPULoad) >= 10 {
        recent := p.history.CPULoad[len(p.history.CPULoad)-10:]
        older := p.history.CPULoad[len(p.history.CPULoad)-20 : len(p.history.CPULoad)-10]
        
        recentAvg := p.calculateAverage(recent)
        olderAvg := p.calculateAverage(older)
        
        if recentAvg > olderAvg+5 {
            trend["cpu"] = "increasing"
        } else if recentAvg < olderAvg-5 {
            trend["cpu"] = "decreasing"
        } else {
            trend["cpu"] = "stable"
        }
    }
    
    return trend
}

func (p *PerformanceSampler) calculateAverage(data []float64) float64 {
    var sum float64
    for _, value := range data {
        sum += value
    }
    return sum / float64(len(data))
}

func (p *PerformanceSampler) cleanupOldReports() {
    entries, err := os.ReadDir(constants.ReportsDir)
    if err != nil {
        return
    }
    
    cutoffTime := time.Now().AddDate(0, 0, -p.config.ReportRetention)
    
    for _, entry := range entries {
        if entry.IsDir() {
            continue
        }
        
        info, err := entry.Info()
        if err != nil {
            continue
        }
        
        if info.ModTime().Before(cutoffTime) {
            oldFile := constants.ReportsDir + entry.Name()
            os.Remove(oldFile)
            core.LogMessage(p.logger, 0, fmt.Sprintf("清理旧报告: %s", oldFile), p.config.Config)
        }
    }
}

func (p *PerformanceSampler) loadHistoryData() {
    data, err := os.ReadFile(constants.PerformanceDataFile)
    if err != nil {
        if os.IsNotExist(err) {
            // 文件不存在，使用空历史
            return
        }
        core.LogMessage(p.logger, 2, fmt.Sprintf("读取性能历史数据失败: %v", err), p.config.Config)
        return
    }
    
    var history PerformanceHistory
    if err := json.Unmarshal(data, &history); err != nil {
        core.LogMessage(p.logger, 2, fmt.Sprintf("解析性能历史数据失败: %v", err), p.config.Config)
        return
    }
    
    p.history = &history
}

func (p *PerformanceSampler) saveHistoryData() error {
    data, err := json.MarshalIndent(p.history, "", "  ")
    if err != nil {
        return fmt.Errorf("序列化性能历史数据失败: %v", err)
    }
    
    if err := os.WriteFile(constants.PerformanceDataFile, data, 0644); err != nil {
        return fmt.Errorf("保存性能历史数据失败: %v", err)
    }
    
    return nil
}