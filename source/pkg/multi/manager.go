package multi

import (
    "context"
    "fmt"
    "log"
    "sync"
    "time"

    "ez-clean/pkg/core"
)

// MultiManager 多功能版管理器
type MultiManager struct {
    config     *MultiConfig
    logger     *log.Logger
    adaptive   *SystemAdapter
    aiLearner  *AILearner
    sampler    *PerformanceSampler
    coordinator *Coordinator
    output     *OutputManager
    
    // 状态管理
    mu             sync.RWMutex
    status         ManagerStatus
    startTime      time.Time
    lastOutputTime time.Time
}

// ManagerStatus 管理器状态
type ManagerStatus struct {
    SystemAdapterRunning bool      `json:"system_adapter_running"`
    AILearningRunning    bool      `json:"ai_learning_running"`
    SamplingRunning      bool      `json:"sampling_running"`
    CoordinatorRunning   bool      `json:"coordinator_running"`
    OutputManagerReady   bool      `json:"output_manager_ready"`
    LastHealthCheck      time.Time `json:"last_health_check"`
    ErrorCount           int       `json:"error_count"`
}

// NewMultiManager 创建多功能管理器
func NewMultiManager(config *MultiConfig, logger *log.Logger) *MultiManager {
    manager := &MultiManager{
        config:    config,
        logger:    logger,
        startTime: time.Now(),
        status:    ManagerStatus{},
    }
    
    // 初始化输出管理器
    manager.output = NewOutputManager(config, logger)
    
    // 确保输出目录存在
    if err := manager.output.EnsureOutputDirs(); err != nil {
        core.LogMessage(logger, 3, fmt.Sprintf("初始化输出目录失败: %v", err), config.Config)
    } else {
        manager.status.OutputManagerReady = true
        core.LogMessage(logger, 1, "输出管理器初始化完成", config.Config)
    }
    
    // 初始化各模块
    if config.SystemAdaptEnable {
        manager.adaptive = NewSystemAdapter(config, logger)
    }
    
    if config.AIAdaptiveEnable {
        manager.aiLearner = NewAILearner(config, logger)
    }
    
    if config.SamplingEnable {
        manager.sampler = NewPerformanceSampler(config, logger)
    }
    
    manager.coordinator = NewCoordinator(config, logger, manager)
    
    return manager
}

// StartSystemAdapter 启动系统自适应模块
func (m *MultiManager) StartSystemAdapter(ctx context.Context) {
    if m.adaptive == nil {
        core.LogMessage(m.logger, 2, "系统自适应模块未初始化", m.config.Config)
        return
    }
    
    m.mu.Lock()
    m.status.SystemAdapterRunning = true
    m.mu.Unlock()
    
    defer func() {
        m.mu.Lock()
        m.status.SystemAdapterRunning = false
        m.mu.Unlock()
    }()
    
    core.LogMessage(m.logger, 1, "系统自适应模块启动", m.config.Config)
    
    // 初始系统检测
    if err := m.adaptive.DetectSystem(); err != nil {
        core.LogMessage(m.logger, 3, fmt.Sprintf("系统检测失败: %v", err), m.config.Config)
    } else {
        // 生成系统配置文件
        if m.status.OutputManagerReady {
            if systemInfo := m.adaptive.GetSystemInfo(); systemInfo.SystemType != "" {
                if err := m.output.WriteSystemProfile(&systemInfo); err != nil {
                    core.LogMessage(m.logger, 2, fmt.Sprintf("生成系统配置失败: %v", err), m.config.Config)
                }
            }
        }
    }
    
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            // 定期系统检测和适配
            if err := m.adaptive.AdaptSystem(); err != nil {
                core.LogMessage(m.logger, 2, fmt.Sprintf("系统适配失败: %v", err), m.config.Config)
                m.incrementErrorCount()
            }
            
        case <-ctx.Done():
            core.LogMessage(m.logger, 1, "系统自适应模块停止", m.config.Config)
            return
        }
    }
}

// StartAILearning 启动AI学习模块
func (m *MultiManager) StartAILearning(ctx context.Context) {
    if m.aiLearner == nil {
        core.LogMessage(m.logger, 2, "AI学习模块未初始化", m.config.Config)
        return
    }
    
    m.mu.Lock()
    m.status.AILearningRunning = true
    m.mu.Unlock()
    
    defer func() {
        m.mu.Lock()
        m.status.AILearningRunning = false
        m.mu.Unlock()
    }()
    
    core.LogMessage(m.logger, 1, "AI学习模块启动", m.config.Config)
    
    // 初始学习
    if err := m.aiLearner.InitialLearning(); err != nil {
        core.LogMessage(m.logger, 3, fmt.Sprintf("AI初始学习失败: %v", err), m.config.Config)
    }
    
    ticker := time.NewTicker(2 * time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            // 获取当前性能数据
            var metrics *PerformanceMetrics
            if m.sampler != nil {
                var err error
                metrics, err = m.sampler.GetCurrentMetrics()
                if err != nil {
                    core.LogMessage(m.logger, 2, fmt.Sprintf("获取性能指标失败: %v", err), m.config.Config)
                    continue
                }
            } else {
                // 如果采样器未启用，创建基础指标
                metrics = &PerformanceMetrics{
                    Timestamp:    time.Now(),
                    CPULoad:      0,
                    MemoryUsage:  0,
                    BatteryLevel: 100,
                    ThermalState: "unknown",
                }
            }
            
            // AI学习调整
            if err := m.aiLearner.AdaptiveLearning(metrics); err != nil {
                core.LogMessage(m.logger, 2, fmt.Sprintf("AI学习调整失败: %v", err), m.config.Config)
                m.incrementErrorCount()
            }
            
            // 生成自适应配置
            if m.status.OutputManagerReady && time.Since(m.lastOutputTime) > 10*time.Minute {
                if params := m.aiLearner.GetAdaptiveParams(); params != nil {
                    if err := m.output.WriteAdaptiveConfig(params); err != nil {
                        core.LogMessage(m.logger, 2, fmt.Sprintf("生成自适应配置失败: %v", err), m.config.Config)
                    }
                    m.lastOutputTime = time.Now()
                }
            }
            
        case <-ctx.Done():
            core.LogMessage(m.logger, 1, "AI学习模块停止", m.config.Config)
            return
        }
    }
}

// StartSampling 启动性能采样模块
func (m *MultiManager) StartSampling(ctx context.Context) {
    if m.sampler == nil {
        core.LogMessage(m.logger, 2, "性能采样模块未初始化", m.config.Config)
        return
    }
    
    m.mu.Lock()
    m.status.SamplingRunning = true
    m.mu.Unlock()
    
    defer func() {
        m.mu.Lock()
        m.status.SamplingRunning = false
        m.mu.Unlock()
    }()
    
    core.LogMessage(m.logger, 1, "性能采样模块启动", m.config.Config)
    
    interval := time.Duration(m.config.SamplingInterval) * time.Second
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            // 执行性能采样
            if err := m.sampler.CollectMetrics(); err != nil {
                core.LogMessage(m.logger, 2, fmt.Sprintf("性能采样失败: %v", err), m.config.Config)
                m.incrementErrorCount()
            }
            
            // 生成性能报告
            if m.status.OutputManagerReady && time.Since(m.lastOutputTime) > 5*time.Minute {
                if metrics, err := m.sampler.GetCurrentMetrics(); err == nil {
                    if history := m.sampler.GetPerformanceHistory(); history != nil {
                        if err := m.output.WritePerformanceReport(metrics, history); err != nil {
                            core.LogMessage(m.logger, 2, fmt.Sprintf("生成性能报告失败: %v", err), m.config.Config)
                        }
                        m.lastOutputTime = time.Now()
                    }
                }
            }
            
            // 定期生成日报
            if time.Now().Hour() == 0 && time.Now().Minute() == 0 {
                if err := m.sampler.GenerateDailyReport(); err != nil {
                    core.LogMessage(m.logger, 2, fmt.Sprintf("生成日报失败: %v", err), m.config.Config)
                }
            }
            
        case <-ctx.Done():
            core.LogMessage(m.logger, 1, "性能采样模块停止", m.config.Config)
            return
        }
    }
}

// StartCoordinator 启动协调器
func (m *MultiManager) StartCoordinator(ctx context.Context) {
    m.mu.Lock()
    m.status.CoordinatorRunning = true
    m.mu.Unlock()
    
    defer func() {
        m.mu.Lock()
        m.status.CoordinatorRunning = false
        m.mu.Unlock()
    }()
    
    core.LogMessage(m.logger, 1, "多功能协调器启动", m.config.Config)
    
    healthTicker := time.NewTicker(30 * time.Second)
    defer healthTicker.Stop()
    
    outputTicker := time.NewTicker(15 * time.Minute)
    defer outputTicker.Stop()
    
    for {
        select {
        case <-healthTicker.C:
            // 健康检查
            m.healthCheck()
            
        case <-outputTicker.C:
            // 定期生成模块状态报告
            if m.status.OutputManagerReady {
                if err := m.output.WriteModuleStatus(m); err != nil {
                    core.LogMessage(m.logger, 2, fmt.Sprintf("生成模块状态报告失败: %v", err), m.config.Config)
                }
                
                // 清理旧输出文件
                if err := m.output.CleanupOldOutputs(); err != nil {
                    core.LogMessage(m.logger, 2, fmt.Sprintf("清理旧输出文件失败: %v", err), m.config.Config)
                }
            }
            
        case <-ctx.Done():
            core.LogMessage(m.logger, 1, "多功能协调器停止", m.config.Config)
            return
        }
    }
}

// healthCheck 执行健康检查
func (m *MultiManager) healthCheck() {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    m.status.LastHealthCheck = time.Now()
    
    // 检查各模块状态
    if m.config.SystemAdaptEnable && !m.status.SystemAdapterRunning {
        core.LogMessage(m.logger, 2, "系统自适应模块异常停止", m.config.Config)
    }
    
    if m.config.AIAdaptiveEnable && !m.status.AILearningRunning {
        core.LogMessage(m.logger, 2, "AI学习模块异常停止", m.config.Config)
    }
    
    if m.config.SamplingEnable && !m.status.SamplingRunning {
        core.LogMessage(m.logger, 2, "性能采样模块异常停止", m.config.Config)
    }
    
    if !m.status.OutputManagerReady {
        core.LogMessage(m.logger, 2, "输出管理器未就绪", m.config.Config)
    }
    
    // 重置错误计数（如果最近没有错误）
    if m.status.ErrorCount > 0 && time.Since(m.status.LastHealthCheck) > 10*time.Minute {
        m.status.ErrorCount = 0
    }
}

// incrementErrorCount 增加错误计数
func (m *MultiManager) incrementErrorCount() {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    m.status.ErrorCount++
    
    // 如果错误过多，可能需要重启模块
    if m.status.ErrorCount > 10 {
        core.LogMessage(m.logger, 3, "错误计数过高，建议检查系统状态", m.config.Config)
    }
}

// GetStatus 获取管理器状态
func (m *MultiManager) GetStatus() ManagerStatus {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    return m.status
}

// GetUptime 获取运行时间
func (m *MultiManager) GetUptime() time.Duration {
    return time.Since(m.startTime)
}

// NotifyCleanCompleted 通知清理完成
func (m *MultiManager) NotifyCleanCompleted(duration time.Duration, spaceFreed int64, success bool) {
    // 通知协调器清理完成
    if m.coordinator != nil {
        m.coordinator.NotifyCleanCompleted(duration, spaceFreed, success)
    }
    
    // 记录清理结果到AI学习模块
    if m.aiLearner != nil {
        m.aiLearner.RecordCleanResult(duration, spaceFreed, success)
    }
    
    if success {
        core.LogMessage(m.logger, 1, fmt.Sprintf("清理完成: 耗时%s, 释放空间%.2fMB", 
            duration, float64(spaceFreed)/(1024*1024)), m.config.Config)
    } else {
        core.LogMessage(m.logger, 2, "清理任务失败", m.config.Config)
    }
}