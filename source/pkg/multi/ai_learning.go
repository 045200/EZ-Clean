package multi

import (
    "encoding/json"
    "fmt"
    "log"
    "math"
    "os"
    "sync"
    "time"

    "ez-clean/pkg/core"
    "ez-clean/pkg/constants"
)

// AILearner AI学习模块
type AILearner struct {
    config     *MultiConfig
    logger     *log.Logger
    mu         sync.RWMutex
    learningData *LearningData
    adaptiveParams *AdaptiveParams
}

// LearningData 学习数据
type LearningData struct {
    TotalCleanCycles    int       `json:"total_clean_cycles"`
    SuccessfulCleans    int       `json:"successful_cleans"`
    AverageCleanTime    float64   `json:"average_clean_time"`
    AverageSpaceFreed   float64   `json:"average_space_freed"`
    PeakUsageTimes      []string  `json:"peak_usage_times"`
    OptimalCleanTimes   []string  `json:"optimal_clean_times"`
    LearningHistory     []LearningRecord `json:"learning_history"`
    LastUpdated         time.Time `json:"last_updated"`
}

// LearningRecord 学习记录
type LearningRecord struct {
    Timestamp       time.Time     `json:"timestamp"`
    CPULoad         float64       `json:"cpu_load"`
    MemoryUsage     float64       `json:"memory_usage"`
    BatteryLevel    float64       `json:"battery_level"`
    CleanDuration   time.Duration `json:"clean_duration"`
    SpaceFreed      int64         `json:"space_freed"`
    Success         bool          `json:"success"`
    AdaptiveParams  AdaptiveParams `json:"adaptive_params"`
}

// AdaptiveParams 自适应参数
type AdaptiveParams struct {
    CleanInterval    time.Duration `json:"clean_interval"`
    Aggressiveness   float64       `json:"aggressiveness"` // 0.0-1.0
    CPUThreshold     float64       `json:"cpu_threshold"`
    MemoryThreshold  float64       `json:"memory_threshold"`
    BatteryThreshold float64       `json:"battery_threshold"`
    LearningRate     float64       `json:"learning_rate"`
}

// PerformanceMetrics 性能指标
type PerformanceMetrics struct {
    Timestamp    time.Time `json:"timestamp"`
    CPULoad      float64   `json:"cpu_load"`      // CPU负载百分比
    MemoryUsage  float64   `json:"memory_usage"`  // 内存使用百分比
    BatteryLevel float64   `json:"battery_level"` // 电池电量百分比
    ThermalState string    `json:"thermal_state"` // 温度状态
}

// NewAILearner 创建AI学习模块
func NewAILearner(config *MultiConfig, logger *log.Logger) *AILearner {
    learner := &AILearner{
        config: config,
        logger: logger,
        learningData: &LearningData{
            PeakUsageTimes:    []string{},
            OptimalCleanTimes: []string{},
            LearningHistory:   []LearningRecord{},
        },
        adaptiveParams: &AdaptiveParams{
            CleanInterval:    1 * time.Hour,
            Aggressiveness:   0.5,
            CPUThreshold:     config.MaxCPULimit,
            MemoryThreshold:  config.MaxMemoryLimit,
            BatteryThreshold: config.BatteryThreshold,
            LearningRate:     config.AILearningRate,
        },
    }
    
    // 加载历史学习数据
    learner.loadLearningData()
    
    return learner
}

// InitialLearning 初始学习
func (a *AILearner) InitialLearning() error {
    core.LogMessage(a.logger, 1, "开始AI初始学习", a.config.Config)
    
    // 分析系统使用模式
    if err := a.analyzeUsagePatterns(); err != nil {
        return fmt.Errorf("分析使用模式失败: %v", err)
    }
    
    // 计算初始优化参数
    a.calculateInitialParams()
    
    // 保存学习数据
    if err := a.saveLearningData(); err != nil {
        return fmt.Errorf("保存学习数据失败: %v", err)
    }
    
    core.LogMessage(a.logger, 1, "AI初始学习完成", a.config.Config)
    return nil
}

// AdaptiveLearning 自适应学习
func (a *AILearner) AdaptiveLearning(metrics *PerformanceMetrics) error {
    a.mu.Lock()
    defer a.mu.Unlock()
    
    core.LogMessage(a.logger, 0, "执行AI自适应学习", a.config.Config)
    
    // 创建学习记录
    record := LearningRecord{
        Timestamp:    metrics.Timestamp,
        CPULoad:      metrics.CPULoad,
        MemoryUsage:  metrics.MemoryUsage,
        BatteryLevel: metrics.BatteryLevel,
        AdaptiveParams: *a.adaptiveParams,
    }
    
    // 添加学习记录
    a.learningData.LearningHistory = append(a.learningData.LearningHistory, record)
    
    // 限制历史记录数量
    if len(a.learningData.LearningHistory) > 1000 {
        a.learningData.LearningHistory = a.learningData.LearningHistory[100:]
    }
    
    // 根据性能指标调整参数
    a.adjustParameters(metrics)
    
    // 更新学习数据
    a.learningData.LastUpdated = time.Now()
    
    // 定期保存学习数据
    if time.Since(a.learningData.LastUpdated) > 10*time.Minute {
        if err := a.saveLearningData(); err != nil {
            return fmt.Errorf("保存学习数据失败: %v", err)
        }
    }
    
    return nil
}

// GetOptimalCleanTime 获取最佳清理时间
func (a *AILearner) GetOptimalCleanTime() string {
    a.mu.RLock()
    defer a.mu.RUnlock()
    
    if len(a.learningData.OptimalCleanTimes) > 0 {
        // 返回最近学习到的最佳时间
        return a.learningData.OptimalCleanTimes[len(a.learningData.OptimalCleanTimes)-1]
    }
    
    // 默认返回配置的时间
    return a.config.CleanTime
}

// GetAdaptiveParams 获取自适应参数
func (a *AILearner) GetAdaptiveParams() *AdaptiveParams {
    a.mu.RLock()
    defer a.mu.RUnlock()
    
    return a.adaptiveParams
}

// RecordCleanResult 记录清理结果
func (a *AILearner) RecordCleanResult(duration time.Duration, spaceFreed int64, success bool) {
    a.mu.Lock()
    defer a.mu.Unlock()
    
    a.learningData.TotalCleanCycles++
    if success {
        a.learningData.SuccessfulCleans++
    }
    
    // 更新平均清理时间
    if a.learningData.AverageCleanTime == 0 {
        a.learningData.AverageCleanTime = duration.Seconds()
    } else {
        a.learningData.AverageCleanTime = (a.learningData.AverageCleanTime + duration.Seconds()) / 2
    }
    
    // 更新平均释放空间
    if a.learningData.AverageSpaceFreed == 0 {
        a.learningData.AverageSpaceFreed = float64(spaceFreed)
    } else {
        a.learningData.AverageSpaceFreed = (a.learningData.AverageSpaceFreed + float64(spaceFreed)) / 2
    }
    
    // 更新最近的学习记录
    if len(a.learningData.LearningHistory) > 0 {
        lastRecord := &a.learningData.LearningHistory[len(a.learningData.LearningHistory)-1]
        lastRecord.CleanDuration = duration
        lastRecord.SpaceFreed = spaceFreed
        lastRecord.Success = success
    }
}

// ========== 私有方法 ==========

func (a *AILearner) analyzeUsagePatterns() error {
    // 分析历史数据以发现使用模式
    // 这里可以集成更复杂的机器学习算法
    
    // 简单的基于时间的学习
    currentHour := time.Now().Hour()
    
    // 假设系统使用高峰在白天，低谷在深夜
    if currentHour >= 8 && currentHour <= 22 {
        // 白天时段，清理间隔稍长
        a.adaptiveParams.CleanInterval = 2 * time.Hour
        a.adaptiveParams.Aggressiveness = 0.3 // 较低的侵略性
    } else {
        // 夜间时段，可以更积极清理
        a.adaptiveParams.CleanInterval = 30 * time.Minute
        a.adaptiveParams.Aggressiveness = 0.8 // 较高的侵略性
    }
    
    // 记录最佳清理时间（当前时间+1小时）
    optimalTime := time.Now().Add(time.Hour).Format("15:04")
    a.learningData.OptimalCleanTimes = append(a.learningData.OptimalCleanTimes, optimalTime)
    
    return nil
}

func (a *AILearner) calculateInitialParams() {
    // 基于系统配置计算初始参数
    a.adaptiveParams.CPUThreshold = a.config.MaxCPULimit
    a.adaptiveParams.MemoryThreshold = a.config.MaxMemoryLimit
    a.adaptiveParams.BatteryThreshold = a.config.BatteryThreshold
    a.adaptiveParams.LearningRate = a.config.AILearningRate
    
    // 根据系统时间调整初始清理间隔
    hour := time.Now().Hour()
    if hour >= 23 || hour <= 6 {
        // 夜间时段，缩短清理间隔
        a.adaptiveParams.CleanInterval = 30 * time.Minute
    } else {
        // 日间时段，延长清理间隔
        a.adaptiveParams.CleanInterval = 1 * time.Hour
    }
}

func (a *AILearner) adjustParameters(metrics *PerformanceMetrics) {
    // 根据当前性能指标动态调整参数
    
    // CPU负载调整
    if metrics.CPULoad > a.adaptiveParams.CPUThreshold {
        // CPU负载高，降低清理频率和侵略性
        a.adaptiveParams.CleanInterval = time.Duration(float64(a.adaptiveParams.CleanInterval) * 1.5)
        a.adaptiveParams.Aggressiveness = math.Max(0.1, a.adaptiveParams.Aggressiveness-0.1)
        core.LogMessage(a.logger, 0, fmt.Sprintf("CPU负载高(%0.1f%%)，调整清理参数", metrics.CPULoad), a.config.Config)
    } else if metrics.CPULoad < a.adaptiveParams.CPUThreshold*0.5 {
        // CPU负载低，提高清理频率和侵略性
        a.adaptiveParams.CleanInterval = time.Duration(float64(a.adaptiveParams.CleanInterval) * 0.7)
        a.adaptiveParams.Aggressiveness = math.Min(0.9, a.adaptiveParams.Aggressiveness+0.1)
        core.LogMessage(a.logger, 0, fmt.Sprintf("CPU负载低(%0.1f%%)，提高清理频率", metrics.CPULoad), a.config.Config)
    }
    
    // 内存使用调整
    if metrics.MemoryUsage > a.adaptiveParams.MemoryThreshold {
        // 内存使用高，积极清理
        a.adaptiveParams.Aggressiveness = math.Min(0.9, a.adaptiveParams.Aggressiveness+0.2)
        core.LogMessage(a.logger, 0, fmt.Sprintf("内存使用高(%0.1f%%)，提高清理侵略性", metrics.MemoryUsage), a.config.Config)
    }
    
    // 电池电量调整
    if metrics.BatteryLevel < a.adaptiveParams.BatteryThreshold {
        // 电池电量低，降低清理频率
        a.adaptiveParams.CleanInterval = time.Duration(float64(a.adaptiveParams.CleanInterval) * 2.0)
        a.adaptiveParams.Aggressiveness = math.Max(0.1, a.adaptiveParams.Aggressiveness-0.2)
        core.LogMessage(a.logger, 0, fmt.Sprintf("电池电量低(%0.1f%%)，降低清理频率", metrics.BatteryLevel), a.config.Config)
    }
    
    // 温度状态调整
    if metrics.ThermalState == "hot" || metrics.ThermalState == "critical" {
        // 温度高，显著降低清理频率
        a.adaptiveParams.CleanInterval = time.Duration(float64(a.adaptiveParams.CleanInterval) * 3.0)
        a.adaptiveParams.Aggressiveness = 0.1
        core.LogMessage(a.logger, 0, "系统温度高，大幅降低清理频率", a.config.Config)
    }
}

func (a *AILearner) loadLearningData() error {
    data, err := os.ReadFile(constants.AILearningDataFile)
    if err != nil {
        if os.IsNotExist(err) {
            // 文件不存在，使用默认值
            return nil
        }
        return fmt.Errorf("读取学习数据失败: %v", err)
    }
    
    var learningData LearningData
    if err := json.Unmarshal(data, &learningData); err != nil {
        return fmt.Errorf("解析学习数据失败: %v", err)
    }
    
    a.learningData = &learningData
    return nil
}

func (a *AILearner) saveLearningData() error {
    data, err := json.MarshalIndent(a.learningData, "", "  ")
    if err != nil {
        return fmt.Errorf("序列化学习数据失败: %v", err)
    }
    
    // 确保目录存在
    if err := os.MkdirAll("/storage/emulated/0/Android/EZ-Clean/", 0755); err != nil {
        return fmt.Errorf("创建目录失败: %v", err)
    }
    
    if err := os.WriteFile(constants.AILearningDataFile, data, 0644); err != nil {
        return fmt.Errorf("保存学习数据失败: %v", err)
    }
    
    return nil
}