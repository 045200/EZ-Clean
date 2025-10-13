package multi

import (
    "context"
    "fmt"
    "log"
    "sync"
    "time"

    "ez-clean/pkg/core"
)

// Coordinator 多功能协调器
type Coordinator struct {
    config    *MultiConfig
    logger    *log.Logger
    manager   *MultiManager
    mu        sync.RWMutex
    decisions *CoordinatorDecisions
}

// CoordinatorDecisions 协调器决策
type CoordinatorDecisions struct {
    LastCleanTime      time.Time              `json:"last_clean_time"`
    NextCleanTime      time.Time              `json:"next_clean_time"`
    CleanPriority      CleanPriority          `json:"clean_priority"`
    SystemState        SystemState            `json:"system_state"`
    AdaptiveActions    []AdaptiveAction       `json:"adaptive_actions"`
    LastDecisionTime   time.Time              `json:"last_decision_time"`
}

// CleanPriority 清理优先级
type CleanPriority int

const (
    PriorityLow CleanPriority = iota
    PriorityNormal
    PriorityHigh
    PriorityCritical
)

// SystemState 系统状态
type SystemState string

const (
    StateOptimal    SystemState = "optimal"
    StateNormal     SystemState = "normal"
    StateStressed   SystemState = "stressed"
    StateCritical   SystemState = "critical"
)

// AdaptiveAction 自适应动作
type AdaptiveAction struct {
    Timestamp time.Time `json:"timestamp"`
    Action    string    `json:"action"`
    Reason    string    `json:"reason"`
    Impact    string    `json:"impact"`
}

// NewCoordinator 创建协调器
func NewCoordinator(config *MultiConfig, logger *log.Logger, manager *MultiManager) *Coordinator {
    return &Coordinator{
        config: config,
        logger: logger,
        manager: manager,
        decisions: &CoordinatorDecisions{
            CleanPriority:    PriorityNormal,
            SystemState:      StateNormal,
            AdaptiveActions:  make([]AdaptiveAction, 0),
            LastDecisionTime: time.Now(),
        },
    }
}

// StartCoordinator 启动协调器
func (c *Coordinator) StartCoordinator(ctx context.Context) {
    core.LogMessage(c.logger, 1, "多功能协调器启动", c.config.Config)

    decisionTicker := time.NewTicker(30 * time.Second)
    defer decisionTicker.Stop()

    healthTicker := time.NewTicker(2 * time.Minute)
    defer healthTicker.Stop()

    for {
        select {
        case <-decisionTicker.C:
            // 执行协调决策
            c.makeCoordinatedDecisions()

        case <-healthTicker.C:
            // 系统健康检查
            c.performSystemHealthCheck()

        case <-ctx.Done():
            core.LogMessage(c.logger, 1, "多功能协调器停止", c.config.Config)
            return
        }
    }
}

// makeCoordinatedDecisions 执行协调决策
func (c *Coordinator) makeCoordinatedDecisions() {
    c.mu.Lock()
    defer c.mu.Unlock()

    core.LogMessage(c.logger, 0, "执行协调决策", c.config.Config)

    // 获取各模块状态
    systemInfo := c.manager.adaptive.GetSystemInfo()
    aiParams := c.manager.aiLearner.GetAdaptiveParams()
    metrics, err := c.manager.sampler.GetCurrentMetrics()
    if err != nil {
        core.LogMessage(c.logger, 2, "获取性能指标失败，使用默认决策", c.config.Config)
        c.applyDefaultDecisions()
        return
    }

    // 分析系统状态
    systemState := c.analyzeSystemState(metrics, systemInfo)
    c.decisions.SystemState = systemState

    // 计算清理优先级
    cleanPriority := c.calculateCleanPriority(metrics, systemInfo, aiParams)
    c.decisions.CleanPriority = cleanPriority

    // 确定下一次清理时间
    nextCleanTime := c.determineNextCleanTime(metrics, aiParams)
    c.decisions.NextCleanTime = nextCleanTime

    // 执行自适应调整
    c.executeAdaptiveActions(metrics, systemInfo, aiParams)

    c.decisions.LastDecisionTime = time.Now()

    core.LogMessage(c.logger, 0, fmt.Sprintf("协调决策: 状态=%s, 优先级=%d, 下次清理=%s", 
        systemState, cleanPriority, nextCleanTime.Format("15:04")), c.config.Config)
}

// performSystemHealthCheck 执行系统健康检查
func (c *Coordinator) performSystemHealthCheck() {
    status := c.manager.GetStatus()
    
    // 检查各模块健康状态
    if c.config.SystemAdaptEnable && !status.SystemAdapterRunning {
        core.LogMessage(c.logger, 2, "系统自适应模块异常", c.config.Config)
        c.recordAdaptiveAction("restart_system_adapter", "模块异常停止", "尝试恢复系统检测")
    }
    
    if c.config.AIAdaptiveEnable && !status.AILearningRunning {
        core.LogMessage(c.logger, 2, "AI学习模块异常", c.config.Config)
        c.recordAdaptiveAction("restart_ai_learner", "模块异常停止", "尝试恢复学习功能")
    }
    
    if c.config.SamplingEnable && !status.SamplingRunning {
        core.LogMessage(c.logger, 2, "性能采样模块异常", c.config.Config)
        c.recordAdaptiveAction("restart_sampler", "模块异常停止", "尝试恢复性能监控")
    }
    
    // 检查错误计数
    if status.ErrorCount > 20 {
        core.LogMessage(c.logger, 3, "系统错误计数过高，建议检查系统状态", c.config.Config)
        c.recordAdaptiveAction("system_warning", "错误计数过高", "系统稳定性可能受影响")
    }
}

// analyzeSystemState 分析系统状态
func (c *Coordinator) analyzeSystemState(metrics *PerformanceMetrics, systemInfo SystemInfo) SystemState {
    criticalCount := 0
    warningCount := 0

    // CPU状态检查
    if metrics.CPULoad > 90 {
        criticalCount++
    } else if metrics.CPULoad > 70 {
        warningCount++
    }

    // 内存状态检查
    if metrics.MemoryUsage > 95 {
        criticalCount++
    } else if metrics.MemoryUsage > 85 {
        warningCount++
    }

    // 电池状态检查
    if metrics.BatteryLevel < 10 {
        criticalCount++
    } else if metrics.BatteryLevel < 20 {
        warningCount++
    }

    // 温度状态检查
    if metrics.ThermalState == "critical" {
        criticalCount++
    } else if metrics.ThermalState == "hot" {
        warningCount++
    }

    // 确定系统状态
    if criticalCount >= 2 {
        return StateCritical
    } else if criticalCount >= 1 || warningCount >= 2 {
        return StateStressed
    } else if warningCount >= 1 {
        return StateNormal
    } else {
        return StateOptimal
    }
}

// calculateCleanPriority 计算清理优先级
func (c *Coordinator) calculateCleanPriority(metrics *PerformanceMetrics, systemInfo SystemInfo, aiParams *AdaptiveParams) CleanPriority {
    priorityScore := 0

    // 基于系统状态
    switch c.decisions.SystemState {
    case StateCritical:
        priorityScore += 30
    case StateStressed:
        priorityScore += 20
    case StateNormal:
        priorityScore += 10
    case StateOptimal:
        priorityScore += 5
    }

    // 基于内存使用
    if metrics.MemoryUsage > 90 {
        priorityScore += 25
    } else if metrics.MemoryUsage > 80 {
        priorityScore += 15
    } else if metrics.MemoryUsage > 70 {
        priorityScore += 10
    }

    // 基于CPU负载
    if metrics.CPULoad > 80 {
        priorityScore += 20
    } else if metrics.CPULoad > 60 {
        priorityScore += 10
    }

    // 基于电池状态
    if metrics.BatteryLevel < 15 {
        priorityScore -= 10 // 低电量时降低优先级
    }

    // 基于AI学习参数
    priorityScore += int(aiParams.Aggressiveness * 20)

    // 确定优先级
    if priorityScore >= 50 {
        return PriorityCritical
    } else if priorityScore >= 35 {
        return PriorityHigh
    } else if priorityScore >= 20 {
        return PriorityNormal
    } else {
        return PriorityLow
    }
}

// determineNextCleanTime 确定下一次清理时间
func (c *Coordinator) determineNextCleanTime(metrics *PerformanceMetrics, aiParams *AdaptiveParams) time.Time {
    baseTime := time.Now()
    
    // 根据系统状态调整清理间隔
    var intervalMultiplier float64
    
    switch c.decisions.SystemState {
    case StateCritical:
        intervalMultiplier = 0.3 // 紧急状态，大幅缩短间隔
    case StateStressed:
        intervalMultiplier = 0.6 // 压力状态，缩短间隔
    case StateNormal:
        intervalMultiplier = 1.0 // 正常状态，标准间隔
    case StateOptimal:
        intervalMultiplier = 1.5 // 最佳状态，延长间隔
    }
    
    // 根据清理优先级进一步调整
    switch c.decisions.CleanPriority {
    case PriorityCritical:
        intervalMultiplier *= 0.5
    case PriorityHigh:
        intervalMultiplier *= 0.8
    case PriorityLow:
        intervalMultiplier *= 1.8
    }
    
    // 应用AI学习到的间隔
    adaptiveInterval := time.Duration(float64(aiParams.CleanInterval) * intervalMultiplier)
    
    // 确保间隔在合理范围内
    minInterval := 5 * time.Minute
    maxInterval := 6 * time.Hour
    
    if adaptiveInterval < minInterval {
        adaptiveInterval = minInterval
    } else if adaptiveInterval > maxInterval {
        adaptiveInterval = maxInterval
    }
    
    return baseTime.Add(adaptiveInterval)
}

// executeAdaptiveActions 执行自适应动作
func (c *Coordinator) executeAdaptiveActions(metrics *PerformanceMetrics, systemInfo SystemInfo, aiParams *AdaptiveParams) {
    // 根据系统状态执行相应动作
    switch c.decisions.SystemState {
    case StateCritical:
        c.executeCriticalActions(metrics)
    case StateStressed:
        c.executeStressedActions(metrics)
    case StateNormal:
        c.executeNormalActions(metrics)
    case StateOptimal:
        c.executeOptimalActions(metrics)
    }
    
    // 特定系统类型的优化
    c.executeSystemSpecificActions(systemInfo)
}

func (c *Coordinator) executeCriticalActions(metrics *PerformanceMetrics) {
    c.recordAdaptiveAction("emergency_clean", "系统状态危急", "立即执行紧急清理")
    
    // 降低采样频率以节省资源
    if c.config.SamplingEnable {
        c.recordAdaptiveAction("reduce_sampling", "系统资源紧张", "降低性能采样频率")
    }
    
    // 暂停非核心功能
    if c.config.AIAdaptiveEnable {
        c.recordAdaptiveAction("pause_ai_learning", "系统资源紧张", "暂停AI学习以节省资源")
    }
}

func (c *Coordinator) executeStressedActions(metrics *PerformanceMetrics) {
    c.recordAdaptiveAction("aggressive_clean", "系统压力较大", "执行积极清理")
    
    // 调整AI学习参数
    if c.config.AIAdaptiveEnable {
        c.recordAdaptiveAction("adjust_ai_params", "系统压力状态", "优化AI学习参数")
    }
}

func (c *Coordinator) executeNormalActions(metrics *PerformanceMetrics) {
    // 正常状态下的优化动作
    if metrics.MemoryUsage > 75 {
        c.recordAdaptiveAction("memory_optimize", "内存使用较高", "执行内存优化清理")
    }
}

func (c *Coordinator) executeOptimalActions(metrics *PerformanceMetrics) {
    // 最佳状态下的维护动作
    c.recordAdaptiveAction("maintenance_clean", "系统状态最佳", "执行维护性清理")
    
    // 可以进行更详细的学习和分析
    if c.config.AIAdaptiveEnable {
        c.recordAdaptiveAction("deep_learning", "系统资源充足", "执行深度学习分析")
    }
}

func (c *Coordinator) executeSystemSpecificActions(systemInfo SystemInfo) {
    // 针对不同系统类型的优化
    switch systemInfo.SystemType {
    case "custom":
        c.recordAdaptiveAction("custom_rom_optimize", "检测到定制系统", "应用定制系统优化")
    case "aosp":
        c.recordAdaptiveAction("aosp_optimize", "检测到类原生系统", "应用AOSP优化策略")
    case "stock":
        c.recordAdaptiveAction("stock_optimize", "检测到原生系统", "应用原生系统优化")
    }
}

// applyDefaultDecisions 应用默认决策
func (c *Coordinator) applyDefaultDecisions() {
    c.decisions.SystemState = StateNormal
    c.decisions.CleanPriority = PriorityNormal
    c.decisions.NextCleanTime = time.Now().Add(1 * time.Hour)
}

// recordAdaptiveAction 记录自适应动作
func (c *Coordinator) recordAdaptiveAction(action, reason, impact string) {
    adaptiveAction := AdaptiveAction{
        Timestamp: time.Now(),
        Action:    action,
        Reason:    reason,
        Impact:    impact,
    }
    
    c.decisions.AdaptiveActions = append(c.decisions.AdaptiveActions, adaptiveAction)
    
    // 限制动作记录数量
    if len(c.decisions.AdaptiveActions) > 100 {
        c.decisions.AdaptiveActions = c.decisions.AdaptiveActions[50:]
    }
    
    core.LogMessage(c.logger, 0, fmt.Sprintf("自适应动作: %s - %s (%s)", action, reason, impact), c.config.Config)
}

// GetDecisions 获取当前决策
func (c *Coordinator) GetDecisions() *CoordinatorDecisions {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    return c.decisions
}

// NotifyCleanCompleted 通知清理完成
func (c *Coordinator) NotifyCleanCompleted(duration time.Duration, spaceFreed int64, success bool) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    c.decisions.LastCleanTime = time.Now()
    
    // 记录清理结果到AI学习模块
    if c.manager.aiLearner != nil {
        c.manager.aiLearner.RecordCleanResult(duration, spaceFreed, success)
    }
    
    if success {
        c.recordAdaptiveAction("clean_completed", "清理任务完成", fmt.Sprintf("释放空间: %.2fMB", float64(spaceFreed)/(1024*1024)))
    } else {
        c.recordAdaptiveAction("clean_failed", "清理任务失败", "需要检查系统状态")
    }
}