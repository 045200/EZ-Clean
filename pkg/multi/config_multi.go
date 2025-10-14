package multi

import (
    "bufio"
    "fmt"
    "os"
    "strconv"
    "strings"
    
    "ez-clean/pkg/constants"
    "ez-clean/pkg/core"
)

// MultiConfig 多功能版配置扩展
type MultiConfig struct {
    *core.Config
    // AI自适应配置
    AIAdaptiveEnable  bool    `json:"ai_adaptive_enable"`
    AILearningRate    float64 `json:"ai_learning_rate"`
    MaxCPULimit       float64 `json:"max_cpu_limit"`
    MaxMemoryLimit    float64 `json:"max_memory_limit"`
    BatteryThreshold  float64 `json:"battery_threshold"`
    
    // 系统自适应配置
    SystemAdaptEnable bool   `json:"system_adapt_enable"`
    SystemType        string `json:"system_type"` // 自动检测或手动指定
    
    // 采样配置
    SamplingEnable    bool `json:"sampling_enable"`
    SamplingInterval  int  `json:"sampling_interval"` // 采样间隔(秒)
    ReportRetention   int  `json:"report_retention"`  // 报告保留天数
}

// ParseMultiConfig 解析多功能版配置
func ParseMultiConfig() (*MultiConfig, error) {
    baseConfig, err := core.ParseConfig()
    if err != nil {
        return nil, err
    }
    
    multiConfig := &MultiConfig{
        Config: baseConfig,
        // 设置默认值
        AIAdaptiveEnable:  true,
        AILearningRate:    0.1,
        MaxCPULimit:       80.0,
        MaxMemoryLimit:    85.0,
        BatteryThreshold:  20.0,
        SystemAdaptEnable: true,
        SamplingEnable:    true,
        SamplingInterval:  60,
        ReportRetention:   30,
    }
    
    // 读取多功能版特定配置
    file, err := os.Open(constants.MultiConfigFile)
    if err != nil {
        if os.IsNotExist(err) {
            // 配置文件不存在，使用默认值
            return multiConfig, nil
        }
        return nil, fmt.Errorf("打开多功能配置文件失败: %v", err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        
        // 跳过注释和空行
        if strings.HasPrefix(line, "#") || line == "" {
            continue
        }
        
        // 解析配置项
        parts := strings.SplitN(line, "=", 2)
        if len(parts) != 2 {
            continue
        }
        
        key := strings.TrimSpace(parts[0])
        value := strings.TrimSpace(parts[1])
        
        switch key {
        case "ai_adaptive_enable":
            multiConfig.AIAdaptiveEnable = strings.ToLower(value) == "true"
        case "ai_learning_rate":
            if val, err := strconv.ParseFloat(value, 64); err == nil {
                multiConfig.AILearningRate = val
            }
        case "max_cpu_limit":
            if val, err := strconv.ParseFloat(value, 64); err == nil {
                multiConfig.MaxCPULimit = val
            }
        case "max_memory_limit":
            if val, err := strconv.ParseFloat(value, 64); err == nil {
                multiConfig.MaxMemoryLimit = val
            }
        case "battery_threshold":
            if val, err := strconv.ParseFloat(value, 64); err == nil {
                multiConfig.BatteryThreshold = val
            }
        case "system_adapt_enable":
            multiConfig.SystemAdaptEnable = strings.ToLower(value) == "true"
        case "system_type":
            multiConfig.SystemType = value
        case "sampling_enable":
            multiConfig.SamplingEnable = strings.ToLower(value) == "true"
        case "sampling_interval":
            if val, err := strconv.Atoi(value); err == nil {
                multiConfig.SamplingInterval = val
            }
        case "report_retention":
            if val, err := strconv.Atoi(value); err == nil {
                multiConfig.ReportRetention = val
            }
        }
    }
    
    return multiConfig, scanner.Err()
}

// SaveMultiConfig 保存多功能版配置
func SaveMultiConfig(config *MultiConfig) error {
    // 确保配置目录存在
    os.MkdirAll("/storage/emulated/0/Android/EZ-Clean/", 0755)
    
    file, err := os.Create(constants.MultiConfigFile)
    if err != nil {
        return fmt.Errorf("创建多功能配置文件失败: %v", err)
    }
    defer file.Close()
    
    writer := bufio.NewWriter(file)
    
    // 写入配置头
    writer.WriteString("# EZ-Clean 多功能版配置\n")
    writer.WriteString("# 自动生成，请勿手动修改\n\n")
    
    // AI自适应配置
    writer.WriteString("# AI自适应配置\n")
    writer.WriteString(fmt.Sprintf("ai_adaptive_enable=%t\n", config.AIAdaptiveEnable))
    writer.WriteString(fmt.Sprintf("ai_learning_rate=%.2f\n", config.AILearningRate))
    writer.WriteString(fmt.Sprintf("max_cpu_limit=%.1f\n", config.MaxCPULimit))
    writer.WriteString(fmt.Sprintf("max_memory_limit=%.1f\n", config.MaxMemoryLimit))
    writer.WriteString(fmt.Sprintf("battery_threshold=%.1f\n\n", config.BatteryThreshold))
    
    // 系统自适应配置
    writer.WriteString("# 系统自适应配置\n")
    writer.WriteString(fmt.Sprintf("system_adapt_enable=%t\n", config.SystemAdaptEnable))
    writer.WriteString(fmt.Sprintf("system_type=%s\n\n", config.SystemType))
    
    // 采样配置
    writer.WriteString("# 性能采样配置\n")
    writer.WriteString(fmt.Sprintf("sampling_enable=%t\n", config.SamplingEnable))
    writer.WriteString(fmt.Sprintf("sampling_interval=%d\n", config.SamplingInterval))
    writer.WriteString(fmt.Sprintf("report_retention=%d\n", config.ReportRetention))
    
    return writer.Flush()
}