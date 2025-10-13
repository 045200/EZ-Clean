package multi

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "os/exec"
    "path/filepath"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "time"

    "ez-clean/pkg/core"
)

// SystemAdapter 系统自适应模块
type SystemAdapter struct {
    config      *MultiConfig
    logger      *log.Logger
    mu          sync.RWMutex
    systemInfo  *SystemInfo
    features    *SystemFeatures
    cleanParams map[string]interface{} // 独立的清理参数
}

// SystemInfo 系统信息
type SystemInfo struct {
    SystemType     string            `json:"system_type"`     // 系统类型: hyperos/miui/coloros/harmony/originos/flyme/oneui/stock/aosp
    Manufacturer   string            `json:"manufacturer"`    // 制造商
    Model          string            `json:"model"`           // 型号
    AndroidVersion string            `json:"android_version"` // Android版本
    ROMVersion     string            `json:"rom_version"`     // ROM版本
    CPUArch        string            `json:"cpu_arch"`        // CPU架构
    StorageInfo    *StorageInfo      `json:"storage_info"`    // 存储信息
    ProcessCount   int               `json:"process_count"`   // 进程数量
    SystemProps    map[string]string `json:"system_props"`    // 系统属性
    HyperOSInfo    *HyperOSInfo      `json:"hyperos_info"`    // HyperOS特定信息
    MIUIInfo       *MIUIInfo         `json:"miui_info"`       // MIUI特定信息
    HarmonyOSInfo  *HarmonyOSInfo    `json:"harmonyos_info"`  // 鸿蒙OS特定信息
}

// HyperOSInfo HyperOS特定信息
type HyperOSInfo struct {
    Version          string `json:"version"`
    BuildNumber      string `json:"build_number"`
    Edition          string `json:"edition"` // China/Global
    IsHyperOS        bool   `json:"is_hyperos"`
    BaseMIUIVersion  string `json:"base_miui_version"`
    HyperMindEnabled bool   `json:"hyper_mind_enabled"` // AI学习能力
}

// MIUIInfo MIUI特定信息
type MIUIInfo struct {
    Version     string `json:"version"`
    BuildNumber string `json:"build_number"`
    Edition     string `json:"edition"` // China/Global
    IsMIUI      bool   `json:"is_miui"`
    PhotonEngine bool `json:"photon_engine"` // 光子引擎
}

// HarmonyOSInfo 鸿蒙OS特定信息
type HarmonyOSInfo struct {
    Version       string `json:"version"`
    BuildNumber   string `json:"build_number"`
    IsHarmonyOS   bool   `json:"is_harmonyos"`
    Distributed   bool   `json:"distributed"` // 分布式架构
    ArkEngine     bool   `json:"ark_engine"`  // 方舟引擎
}

// StorageInfo 存储信息
type StorageInfo struct {
    TotalSize    string `json:"total_size"`
    FreeSpace    string `json:"free_space"`
    UsedSpace    string `json:"used_space"`
    UsagePercent string `json:"usage_percent"`
}

// SystemFeatures 系统特性
type SystemFeatures struct {
    HasRootAccess      bool     `json:"has_root_access"`
    HasAdbDebug        bool     `json:"has_adb_debug"`
    SELinuxStatus      string   `json:"selinux_status"`
    SupportedABIs      []string `json:"supported_abis"`
    KernelVersion      string   `json:"kernel_version"`
    BuildFlavor        string   `json:"build_flavor"`
    SecurityPatch      string   `json:"security_patch"`
    AnimationLevel     string   `json:"animation_level"`      // 动画等级: high/medium/low
    MemoryManagement   string   `json:"memory_management"`   // 内存管理策略
}

// 系统常量定义
const (
    SystemTypeHyperOS   = "hyperos"
    SystemTypeMIUI      = "miui"
    SystemColorOS       = "coloros"
    SystemHarmonyOS     = "harmony"
    SystemOriginOS      = "originos"
    SystemFlyme         = "flyme"
    SystemOneUI         = "oneui"
    SystemAOSP          = "aosp"
    SystemStock         = "stock"
)

// NewSystemAdapter 创建系统自适应模块
func NewSystemAdapter(config *MultiConfig, logger *log.Logger) *SystemAdapter {
    adapter := &SystemAdapter{
        config: config,
        logger: logger,
        systemInfo: &SystemInfo{
            SystemProps: make(map[string]string),
        },
        features: &SystemFeatures{
            SupportedABIs: make([]string, 0),
        },
        cleanParams: make(map[string]interface{}), // 初始化清理参数
    }
    return adapter
}

// DetectSystem 检测系统类型
func (s *SystemAdapter) DetectSystem() error {
    s.mu.Lock()
    defer s.mu.Unlock()

    core.LogMessage(s.logger, 1, "开始深度系统探测", s.config.Config)

    // 收集基础系统属性
    if err := s.collectSystemProperties(); err != nil {
        core.LogMessage(s.logger, 3, fmt.Sprintf("收集系统属性失败: %v", err), s.config.Config)
        return err
    }

    // 检测系统特性
    if err := s.detectSystemFeatures(); err != nil {
        core.LogMessage(s.logger, 3, fmt.Sprintf("检测系统特性失败: %v", err), s.config.Config)
    }

    // 检测各厂商系统
    s.detectManufacturerSystems()

    // 判断系统类型
    s.determineSystemType()

    // 生成系统配置文件
    if err := s.generateSystemProfile(); err != nil {
        core.LogMessage(s.logger, 2, fmt.Sprintf("生成系统配置文件失败: %v", err), s.config.Config)
    }

    core.LogMessage(s.logger, 1, fmt.Sprintf("系统探测完成: %s %s (%s)", 
        s.systemInfo.Manufacturer, s.systemInfo.Model, s.systemInfo.SystemType), s.config.Config)

    // 记录系统特定信息
    if s.systemInfo.HyperOSInfo != nil && s.systemInfo.HyperOSInfo.IsHyperOS {
        core.LogMessage(s.logger, 1, fmt.Sprintf("HyperOS版本: %s (基于MIUI %s)", 
            s.systemInfo.HyperOSInfo.Version, s.systemInfo.HyperOSInfo.BaseMIUIVersion), s.config.Config)
    }
    if s.systemInfo.MIUIInfo != nil && s.systemInfo.MIUIInfo.IsMIUI {
        core.LogMessage(s.logger, 1, fmt.Sprintf("MIUI版本: %s", 
            s.systemInfo.MIUIInfo.Version), s.config.Config)
    }
    if s.systemInfo.HarmonyOSInfo != nil && s.systemInfo.HarmonyOSInfo.IsHarmonyOS {
        core.LogMessage(s.logger, 1, fmt.Sprintf("HarmonyOS版本: %s", 
            s.systemInfo.HarmonyOSInfo.Version), s.config.Config)
    }

    return nil
}

// AdaptSystem 自适应系统
func (s *SystemAdapter) AdaptSystem() error {
    s.mu.RLock()
    defer s.mu.RUnlock()

    core.LogMessage(s.logger, 0, "执行系统自适应调整", s.config.Config)

    // 根据系统类型调整清理策略
    switch s.systemInfo.SystemType {
    case SystemTypeHyperOS:
        s.adaptHyperOS()
    case SystemTypeMIUI:
        s.adaptMIUI()
    case SystemHarmonyOS:
        s.adaptHarmonyOS()
    case SystemColorOS:
        s.adaptColorOS()
    case SystemOriginOS:
        s.adaptOriginOS()
    case SystemOneUI:
        s.adaptOneUI()
    case SystemFlyme:
        s.adaptFlyme()
    case SystemAOSP:
        s.adaptAOSP()
    default:
        s.adaptStockROM()
    }

    return nil
}

// GetSystemInfo 获取系统信息
func (s *SystemAdapter) GetSystemInfo() SystemInfo {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    return *s.systemInfo
}

// GetSystemFeatures 获取系统特性
func (s *SystemAdapter) GetSystemFeatures() SystemFeatures {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    return *s.features
}

// GetCleanParams 获取清理参数
func (s *SystemAdapter) GetCleanParams() map[string]interface{} {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    // 返回副本以避免外部修改
    params := make(map[string]interface{})
    for k, v := range s.cleanParams {
        params[k] = v
    }
    return params
}

// SetCleanParam 设置清理参数
func (s *SystemAdapter) SetCleanParam(key string, value interface{}) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    s.cleanParams[key] = value
}

// ========== 私有方法 ==========

// collectSystemProperties 收集系统属性
func (s *SystemAdapter) collectSystemProperties() error {
    properties := []string{
        "ro.product.manufacturer",
        "ro.product.model", 
        "ro.product.brand",
        "ro.build.version.release",
        "ro.build.display.id",
        "ro.build.version.sdk",
        "ro.product.cpu.abi",
        "ro.product.cpu.abilist",
        "ro.build.type",
        "ro.build.flavor",
        "ro.build.version.security_patch",
        "ro.bootimage.build.fingerprint",
        "ro.system.build.fingerprint",
        "ro.vendor.build.fingerprint",
        "ro.build.description",
        "ro.miui.ui.version.name",
        "ro.miui.ui.version.code",
        "ro.miui.version.code_time",
        "ro.system.build.version.incremental",
        "ro.build.version.incremental",
        "ro.product.mod_device",
        "ro.build.tags",
        "ro.build.user",
        "ro.build.host",
        "ro.hyperos.version",
        "ro.harmony.version",
        "ro.build.harmony.version",
        "ro.oppo.version",
        "ro.vivo.version",
        "ro.oneplus.version",
        "ro.samsung.version",
        "ro.build.oppo.version",
        "ro.build.vivo.version",
    }

    for _, prop := range properties {
        value, err := s.getSystemProperty(prop)
        if err == nil && value != "" {
            s.systemInfo.SystemProps[prop] = value
            
            // 设置特定字段
            switch prop {
            case "ro.product.manufacturer":
                s.systemInfo.Manufacturer = strings.ToLower(value)
            case "ro.product.model":
                s.systemInfo.Model = value
            case "ro.build.version.release":
                s.systemInfo.AndroidVersion = value
            case "ro.build.display.id":
                s.systemInfo.ROMVersion = value
            case "ro.product.cpu.abi":
                s.systemInfo.CPUArch = value
            }
        }
    }

    // 获取存储信息
    s.detectStorageInfo()

    // 获取进程信息
    s.detectProcessInfo()

    return nil
}

// detectSystemFeatures 检测系统特性
func (s *SystemAdapter) detectSystemFeatures() error {
    // 检测root权限
    s.features.HasRootAccess = s.checkRootAccess()
    
    // 检测ADB调试
    s.features.HasAdbDebug = s.checkAdbDebug()
    
    // 检测SELinux状态
    s.features.SELinuxStatus = s.getSELinuxStatus()
    
    // 检测支持的ABI
    s.detectSupportedABIs()
    
    // 获取内核版本
    s.features.KernelVersion = s.getKernelVersion()
    
    // 获取构建类型
    if buildType, exists := s.systemInfo.SystemProps["ro.build.type"]; exists {
        s.features.BuildFlavor = buildType
    }
    
    // 获取安全补丁
    if securityPatch, exists := s.systemInfo.SystemProps["ro.build.version.security_patch"]; exists {
        s.features.SecurityPatch = securityPatch
    }

    // 检测动画等级
    s.detectAnimationLevel()

    // 检测内存管理策略
    s.detectMemoryManagement()

    return nil
}

// detectManufacturerSystems 检测各厂商系统
func (s *SystemAdapter) detectManufacturerSystems() {
    manufacturer := strings.ToLower(s.systemInfo.Manufacturer)
    
    // 根据制造商调用相应的检测方法
    switch manufacturer {
    case "xiaomi", "redmi", "poco":
        s.detectXiaomiSystem()
    case "huawei", "honor":
        s.detectHarmonyOS()
    case "oppo", "realme", "oneplus":
        s.detectColorOS()
    case "vivo", "iqoo":
        s.detectOriginOS()
    case "samsung":
        s.detectOneUI()
    case "meizu":
        s.detectFlyme()
    default:
        // 通用检测逻辑
        s.detectGenericSystem()
    }
}

// detectXiaomiSystem 检测小米系统信息
func (s *SystemAdapter) detectXiaomiSystem() {
    // 检测HyperOS
    s.detectHyperOS()
    
    // 检测MIUI（如果HyperOS未检测到）
    if s.systemInfo.HyperOSInfo == nil || !s.systemInfo.HyperOSInfo.IsHyperOS {
        s.detectMIUI()
    }
}

// detectHyperOS 检测HyperOS
func (s *SystemAdapter) detectHyperOS() {
    hyperosInfo := &HyperOSInfo{}
    
    // 方法1: 检查HyperOS特定属性 
    if hyperosVersion, err := s.getSystemProperty("ro.hyperos.version"); err == nil && hyperosVersion != "" {
        hyperosInfo.IsHyperOS = true
        hyperosInfo.Version = hyperosVersion
    }
    
    // 方法2: 检查构建指纹中的HyperOS标识
    if fingerprint, exists := s.systemInfo.SystemProps["ro.system.build.fingerprint"]; exists {
        if strings.Contains(strings.ToLower(fingerprint), "hyperos") {
            hyperosInfo.IsHyperOS = true
            // 从指纹中提取版本信息
            if matches := regexp.MustCompile(`([\d.]+)/V\d+\.\d+\.\d+\.\d+`).FindStringSubmatch(fingerprint); len(matches) > 1 {
                hyperosInfo.Version = matches[1]
            }
        }
    }
    
    // 方法3: 检查MIUI版本作为基础（HyperOS基于MIUI）
    if miuiVersion, exists := s.systemInfo.SystemProps["ro.miui.ui.version.name"]; exists && hyperosInfo.IsHyperOS {
        hyperosInfo.BaseMIUIVersion = miuiVersion
    }
    
    // 方法4: 检查构建描述
    if buildDesc, exists := s.systemInfo.SystemProps["ro.build.description"]; exists {
        if strings.Contains(strings.ToLower(buildDesc), "hyperos") {
            hyperosInfo.IsHyperOS = true
            // 检测HyperMind AI功能 
            hyperosInfo.HyperMindEnabled = s.detectHyperMind()
        }
    }
    
    if hyperosInfo.IsHyperOS {
        s.systemInfo.HyperOSInfo = hyperosInfo
        // 设置版本信息
        if hyperosInfo.Version == "" {
            if incremental, exists := s.systemInfo.SystemProps["ro.system.build.version.incremental"]; exists {
                hyperosInfo.Version = incremental
            }
        }
        hyperosInfo.BuildNumber = s.systemInfo.SystemProps["ro.build.display.id"]
        
        // 判断版本（中国/国际）
        if strings.Contains(strings.ToLower(hyperosInfo.BuildNumber), "cn") {
            hyperosInfo.Edition = "China"
        } else {
            hyperosInfo.Edition = "Global"
        }
    }
}

// detectHyperMind 检测HyperMind AI功能 
func (s *SystemAdapter) detectHyperMind() bool {
    // 检查HyperMind相关属性或文件
    if _, err := s.getSystemProperty("ro.hypermind.enable"); err == nil {
        return true
    }
    
    // 检查AI服务包
    if output, err := exec.Command("pm", "list", "packages", "hypermind").Output(); err == nil {
        if strings.Contains(string(output), "hypermind") {
            return true
        }
    }
    
    return false
}

// detectMIUI 检测MIUI
func (s *SystemAdapter) detectMIUI() {
    miuiInfo := &MIUIInfo{}
    
    // 方法1: 检查MIUI版本属性
    if miuiVersion, exists := s.systemInfo.SystemProps["ro.miui.ui.version.name"]; exists && miuiVersion != "" {
        miuiInfo.IsMIUI = true
        miuiInfo.Version = miuiVersion
    }
    
    // 方法2: 检查构建指纹中的MIUI标识
    if fingerprint, exists := s.systemInfo.SystemProps["ro.system.build.fingerprint"]; exists {
        if strings.Contains(strings.ToLower(fingerprint), "miui") {
            miuiInfo.IsMIUI = true
        }
    }
    
    // 方法3: 检查MIUI版本代码
    if _, exists := s.systemInfo.SystemProps["ro.miui.ui.version.code"]; exists {
        miuiInfo.IsMIUI = true
    }
    
    if miuiInfo.IsMIUI {
        s.systemInfo.MIUIInfo = miuiInfo
        miuiInfo.BuildNumber = s.systemInfo.SystemProps["ro.build.display.id"]
        
        // 判断版本（中国/国际）
        if strings.Contains(strings.ToLower(miuiInfo.BuildNumber), "cn") {
            miuiInfo.Edition = "China"
        } else {
            miuiInfo.Edition = "Global"
        }
        
        // 检测光子引擎 
        miuiInfo.PhotonEngine = s.detectPhotonEngine()
    }
}

// detectPhotonEngine 检测MIUI光子引擎
func (s *SystemAdapter) detectPhotonEngine() bool {
    // 检查光子引擎相关属性
    if photonProp, err := s.getSystemProperty("ro.miui.photon.engine"); err == nil {
        return photonProp == "1"
    }
    
    // 检查性能配置
    if output, err := exec.Command("getprop", "persist.sys.photon.enable").Output(); err == nil {
        return strings.TrimSpace(string(output)) == "1"
    }
    
    return false
}

// detectHarmonyOS 检测鸿蒙OS
func (s *SystemAdapter) detectHarmonyOS() {
    harmonyInfo := &HarmonyOSInfo{}
    
    // 方法1: 检查HarmonyOS特定属性 
    if harmonyVersion, err := s.getSystemProperty("ro.harmony.version"); err == nil && harmonyVersion != "" {
        harmonyInfo.IsHarmonyOS = true
        harmonyInfo.Version = harmonyVersion
    }
    
    // 方法2: 检查构建版本属性
    if buildVersion, err := s.getSystemProperty("ro.build.harmony.version"); err == nil && buildVersion != "" {
        harmonyInfo.IsHarmonyOS = true
        harmonyInfo.Version = buildVersion
    }
    
    // 方法3: 检查构建描述中的Harmony标识
    if buildDesc, exists := s.systemInfo.SystemProps["ro.build.description"]; exists {
        if strings.Contains(strings.ToLower(buildDesc), "harmony") {
            harmonyInfo.IsHarmonyOS = true
        }
    }
    
    if harmonyInfo.IsHarmonyOS {
        s.systemInfo.HarmonyOSInfo = harmonyInfo
        harmonyInfo.BuildNumber = s.systemInfo.SystemProps["ro.build.display.id"]
        
        // 检测分布式架构 
        harmonyInfo.Distributed = s.detectDistributedArch()
        
        // 检测方舟引擎
        harmonyInfo.ArkEngine = s.detectArkEngine()
    }
}

// detectDistributedArch 检测鸿蒙分布式架构
func (s *SystemAdapter) detectDistributedArch() bool {
    // 检查分布式能力
    if distProp, err := s.getSystemProperty("hw.distributed.ability"); err == nil {
        return distProp == "true"
    }
    
    // 检查分布式软总线
    if _, err := exec.LookPath("distributed_client"); err == nil {
        return true
    }
    
    return false
}

// detectArkEngine 检测方舟引擎
func (s *SystemAdapter) detectArkEngine() bool {
    // 检查方舟引擎属性
    if arkProp, err := s.getSystemProperty("ro.ark.enable"); err == nil {
        return arkProp == "1"
    }
    
    return false
}

// detectColorOS 检测ColorOS
func (s *SystemAdapter) detectColorOS() {
    // 检查ColorOS标识 
    if buildDesc, exists := s.systemInfo.SystemProps["ro.build.description"]; exists {
        if strings.Contains(strings.ToLower(buildDesc), "coloros") {
            s.systemInfo.SystemType = SystemColorOS
        }
    }
    
    // 检查OPPO版本属性
    if oppoVersion, exists := s.systemInfo.SystemProps["ro.oppo.version"]; exists && oppoVersion != "" {
        s.systemInfo.SystemType = SystemColorOS
    }
}

// detectOriginOS 检测OriginOS
func (s *SystemAdapter) detectOriginOS() {
    // 检查OriginOS标识 
    if buildDesc, exists := s.systemInfo.SystemProps["ro.build.description"]; exists {
        if strings.Contains(strings.ToLower(buildDesc), "originos") {
            s.systemInfo.SystemType = SystemOriginOS
        }
    }
    
    // 检查vivo版本属性
    if vivoVersion, exists := s.systemInfo.SystemProps["ro.vivo.version"]; exists && vivoVersion != "" {
        s.systemInfo.SystemType = SystemOriginOS
    }
}

// detectOneUI 检测One UI
func (s *SystemAdapter) detectOneUI() {
    // 检查三星系统标识
    if buildDesc, exists := s.systemInfo.SystemProps["ro.build.description"]; exists {
        if strings.Contains(strings.ToLower(buildDesc), "oneui") {
            s.systemInfo.SystemType = SystemOneUI
        }
    }
}

// detectFlyme 检测Flyme
func (s *SystemAdapter) detectFlyme() {
    // 检查Flyme标识
    if buildDesc, exists := s.systemInfo.SystemProps["ro.build.description"]; exists {
        if strings.Contains(strings.ToLower(buildDesc), "flyme") {
            s.systemInfo.SystemType = SystemFlyme
        }
    }
}

// detectGenericSystem 检测通用系统
func (s *SystemAdapter) detectGenericSystem() {
    // 基于构建描述和指纹的通用检测
    buildDesc := strings.ToLower(s.systemInfo.SystemProps["ro.build.description"])
    fingerprint := strings.ToLower(s.systemInfo.SystemProps["ro.system.build.fingerprint"])
    
    // 检查各种系统标识
    systems := map[string]string{
        "lineageos": SystemAOSP,
        "arrowos":   SystemAOSP, 
        "pixel":     SystemAOSP,
        "evolution": SystemAOSP,
        "aosp":      SystemAOSP,
    }
    
    for identifier, systemType := range systems {
        if strings.Contains(buildDesc, identifier) || strings.Contains(fingerprint, identifier) {
            s.systemInfo.SystemType = systemType
            return
        }
    }
}

// determineSystemType 判断系统类型
func (s *SystemAdapter) determineSystemType() {
    // 如果配置中指定了系统类型，则使用配置值
    if s.config.SystemType != "" && s.config.SystemType != "auto" {
        s.systemInfo.SystemType = s.config.SystemType
        return
    }
    
    // 如果已经通过制造商检测确定了系统类型，直接返回
    if s.systemInfo.SystemType != "" {
        return
    }
    
    // 优先检测小米系统
    if s.systemInfo.HyperOSInfo != nil && s.systemInfo.HyperOSInfo.IsHyperOS {
        s.systemInfo.SystemType = SystemTypeHyperOS
        return
    }
    
    if s.systemInfo.MIUIInfo != nil && s.systemInfo.MIUIInfo.IsMIUI {
        s.systemInfo.SystemType = SystemTypeMIUI
        return
    }
    
    // 检测鸿蒙系统
    if s.systemInfo.HarmonyOSInfo != nil && s.systemInfo.HarmonyOSInfo.IsHarmonyOS {
        s.systemInfo.SystemType = SystemHarmonyOS
        return
    }
    
    // 检测是否为类原生系统
    if s.isAOSPSystem() {
        s.systemInfo.SystemType = SystemAOSP
        return
    }

    // 检测是否为其他定制系统
    if s.isCustomROM() {
        s.systemInfo.SystemType = "custom"
        return
    }

    // 默认为原生系统
    s.systemInfo.SystemType = SystemStock
}

// 系统适配方法
func (s *SystemAdapter) adaptHyperOS() {
    core.LogMessage(s.logger, 0, "应用HyperOS自适应策略", s.config.Config)
    
    // 使用独立的 cleanParams
    s.cleanParams["hyperos_system"] = true
    s.cleanParams["skip_hyperos_apps"] = true
    s.cleanParams["hyperos_ai_data"] = s.systemInfo.HyperOSInfo.HyperMindEnabled
    s.cleanParams["device_notifications"] = true
    
    // 性能优化参数
    s.cleanParams["conservative_memory"] = true
    s.cleanParams["optimize_animations"] = true
}

func (s *SystemAdapter) adaptMIUI() {
    core.LogMessage(s.logger, 0, "应用MIUI自适应策略", s.config.Config)
    
    s.cleanParams["miui_system"] = true
    s.cleanParams["skip_miui_apps"] = true
    s.cleanParams["photon_engine"] = s.systemInfo.MIUIInfo.PhotonEngine
    
    // 根据MIUI版本调整策略
    if s.systemInfo.MIUIInfo.Version >= "15" {
        s.cleanParams["enhanced_clean"] = true
        s.cleanParams["ai_office_data"] = true
    }
}

func (s *SystemAdapter) adaptHarmonyOS() {
    core.LogMessage(s.logger, 0, "应用HarmonyOS自适应策略", s.config.Config)
    
    s.cleanParams["harmonyos_system"] = true
    s.cleanParams["distributed_data"] = s.systemInfo.HarmonyOSInfo.Distributed
    s.cleanParams["ark_engine"] = s.systemInfo.HarmonyOSInfo.ArkEngine
    s.cleanParams["skip_huawei_apps"] = true
    
    if s.systemInfo.HarmonyOSInfo.Distributed {
        s.cleanParams["cross_device_data"] = true
    }
}

func (s *SystemAdapter) adaptColorOS() {
    core.LogMessage(s.logger, 0, "应用ColorOS自适应策略", s.config.Config)
    
    s.cleanParams["coloros_system"] = true
    s.cleanParams["tide_engine"] = true // 潮汐引擎
    s.cleanParams["aurora_engine"] = true // 极光引擎
    s.cleanParams["ai_photo_enhance"] = true // AI影像增强
    
    // 抗老化优化
    s.cleanParams["anti_aging_focus"] = true
}

func (s *SystemAdapter) adaptOriginOS() {
    core.LogMessage(s.logger, 0, "应用OriginOS自适应策略", s.config.Config)
    
    s.cleanParams["originos_system"] = true
    s.cleanParams["blue_river_engine"] = true // 蓝河流畅引擎
    s.cleanParams["atomic_design"] = true // 原子设计体系
    s.cleanParams["spring_animation"] = true // Spring弹性动效
    
    // 游戏场景优化
    s.cleanParams["game_optimization"] = true
}

func (s *SystemAdapter) adaptOneUI() {
    core.LogMessage(s.logger, 0, "应用One UI自适应策略", s.config.Config)
    
    s.cleanParams["oneui_system"] = true
    s.cleanParams["dex_mode"] = true // DeX模式
    s.cleanParams["s_pen_support"] = true
    s.cleanParams["enterprise_security"] = true // 企业级安全
}

func (s *SystemAdapter) adaptFlyme() {
    core.LogMessage(s.logger, 0, "应用Flyme自适应策略", s.config.Config)
    
    s.cleanParams["flyme_system"] = true
    s.cleanParams["ad_free"] = true // 无广告系统
    s.cleanParams["small_window"] = true // 小窗模式
    s.cleanParams["space_compression"] = true // 空间压缩
}

func (s *SystemAdapter) adaptAOSP() {
    core.LogMessage(s.logger, 0, "应用类原生系统自适应策略", s.config.Config)
    
    s.cleanParams["aggressive_clean"] = true
    s.cleanParams["deep_system_clean"] = true
    s.cleanParams["minimal_system"] = true
}

func (s *SystemAdapter) adaptStockROM() {
    core.LogMessage(s.logger, 0, "应用原生系统自适应策略", s.config.Config)
    
    s.cleanParams["standard_clean"] = true
    s.cleanParams["balanced_approach"] = true
}

// ========== 工具方法 ==========

func (s *SystemAdapter) getSystemProperty(prop string) (string, error) {
    cmd := exec.Command("getprop", prop)
    output, err := cmd.Output()
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(string(output)), nil
}

func (s *SystemAdapter) detectStorageInfo() {
    if output, err := exec.Command("df", "-h", "/data").Output(); err == nil {
        lines := strings.Split(string(output), "\n")
        if len(lines) > 1 {
            fields := strings.Fields(lines[1])
            if len(fields) >= 5 {
                s.systemInfo.StorageInfo = &StorageInfo{
                    TotalSize:    fields[1],
                    UsedSpace:    fields[2],
                    FreeSpace:    fields[3],
                    UsagePercent: fields[4],
                }
                return
            }
        }
    }
    s.systemInfo.StorageInfo = &StorageInfo{
        TotalSize:    "unknown",
        FreeSpace:    "unknown", 
        UsedSpace:    "unknown",
        UsagePercent: "unknown",
    }
}

func (s *SystemAdapter) detectProcessInfo() {
    if output, err := exec.Command("ps").Output(); err == nil {
        lines := strings.Split(string(output), "\n")
        s.systemInfo.ProcessCount = len(lines) - 1 // 减去标题行
    } else {
        s.systemInfo.ProcessCount = 0
    }
}

func (s *SystemAdapter) checkRootAccess() bool {
    // 检查su命令
    if _, err := exec.LookPath("su"); err == nil {
        return true
    }
    
    // 检查/system/bin/su
    if _, err := os.Stat("/system/bin/su"); err == nil {
        return true
    }
    
    // 检查/system/xbin/su  
    if _, err := os.Stat("/system/xbin/su"); err == nil {
        return true
    }
    
    return false
}

func (s *SystemAdapter) checkAdbDebug() bool {
    if debugProp, err := s.getSystemProperty("ro.debuggable"); err == nil {
        return debugProp == "1"
    }
    return false
}

func (s *SystemAdapter) getSELinuxStatus() string {
    if output, err := exec.Command("getenforce").Output(); err == nil {
        return strings.TrimSpace(string(output))
    }
    return "unknown"
}

func (s *SystemAdapter) detectSupportedABIs() {
    if abiList, exists := s.systemInfo.SystemProps["ro.product.cpu.abilist"]; exists {
        s.features.SupportedABIs = strings.Split(abiList, ",")
    } else {
        s.features.SupportedABIs = []string{s.systemInfo.CPUArch}
    }
}

func (s *SystemAdapter) getKernelVersion() string {
    if output, err := exec.Command("uname", "-r").Output(); err == nil {
        return strings.TrimSpace(string(output))
    }
    return "unknown"
}

func (s *SystemAdapter) detectAnimationLevel() {
    // 检测动画等级
    if s.systemInfo.SystemType == SystemOriginOS || s.systemInfo.SystemType == SystemColorOS {
        s.features.AnimationLevel = "high"
    } else if s.systemInfo.SystemType == SystemTypeHyperOS {
        s.features.AnimationLevel = "medium"
    } else {
        s.features.AnimationLevel = "low"
    }
}

func (s *SystemAdapter) detectMemoryManagement() {
    // 检测内存管理策略
    switch s.systemInfo.SystemType {
    case SystemOriginOS, SystemColorOS:
        s.features.MemoryManagement = "aggressive"
    case SystemHarmonyOS:
        s.features.MemoryManagement = "balanced" 
    default:
        s.features.MemoryManagement = "conservative"
    }
}

func (s *SystemAdapter) isAOSPSystem() bool {
    // 检查AOSP特征
    aospIndicators := []string{"aosp", "lineage", "arrow", "pixel", "evolution"}
    
    romLower := strings.ToLower(s.systemInfo.ROMVersion)
    for _, indicator := range aospIndicators {
        if strings.Contains(romLower, indicator) {
            return true
        }
    }
    
    // 检查特定系统属性
    aospProps := []string{"ro.aosp.device", "ro.lineage.device"}
    for _, prop := range aospProps {
        if value, err := s.getSystemProperty(prop); err == nil && value != "" {
            return true
        }
    }
    
    return false
}

func (s *SystemAdapter) isCustomROM() bool {
    // 常见定制ROM标识
    customROMs := []string{
        "miui", "emui", "coloros", "oxygenos", "oneui", "fun", "joy", "realme", "flyme",
        "zuk", "letv", "smartisan", "meizu", "gionee", "coolpad", "lenovo",
    }
    
    romLower := strings.ToLower(s.systemInfo.ROMVersion)
    manufacturerLower := strings.ToLower(s.systemInfo.Manufacturer)
    
    for _, rom := range customROMs {
        if strings.Contains(romLower, rom) || strings.Contains(manufacturerLower, rom) {
            return true
        }
    }
    
    return false
}

func (s *SystemAdapter) generateSystemProfile() error {
    profile := map[string]interface{}{
        "system_info":     s.systemInfo,
        "system_features": s.features,
        "clean_params":    s.cleanParams, // 包含清理参数
        "detected_at":     time.Now().Format(time.RFC3339),
        "ez_clean_version": "2.0.0",
    }
    
    data, err := json.MarshalIndent(profile, "", "  ")
    if err != nil {
        return fmt.Errorf("序列化系统配置失败: %v", err)
    }
    
    // 确保目录存在
    profileDir := "/data/local/tmp/ez-clean"
    if err := os.MkdirAll(profileDir, 0755); err != nil {
        // 尝试使用SD卡目录
        profileDir = "/sdcard/Android/data/ez-clean"
        if err := os.MkdirAll(profileDir, 0755); err != nil {
            return fmt.Errorf("创建目录失败: %v", err)
        }
    }
    
    profileFile := filepath.Join(profileDir, "system_profile.json")
    if err := os.WriteFile(profileFile, data, 0644); err != nil {
        return fmt.Errorf("写入系统配置失败: %v", err)
    }
    
    core.LogMessage(s.logger, 1, fmt.Sprintf("系统配置文件已生成: %s", profileFile), s.config.Config)
    return nil
}

// 新增工具方法

// IsXiaomiSystem 检查是否为小米系统
func (s *SystemAdapter) IsXiaomiSystem() bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    return s.systemInfo.SystemType == SystemTypeHyperOS || s.systemInfo.SystemType == SystemTypeMIUI
}

// GetAndroidSDKVersion 获取Android SDK版本
func (s *SystemAdapter) GetAndroidSDKVersion() int {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    if sdkStr, exists := s.systemInfo.SystemProps["ro.build.version.sdk"]; exists {
        if sdk, err := strconv.Atoi(sdkStr); err == nil {
            return sdk
        }
    }
    return 0
}

// IsRooted 检查设备是否已root
func (s *SystemAdapter) IsRooted() bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    return s.features.HasRootAccess
}

// GetSystemSummary 获取系统摘要信息
func (s *SystemAdapter) GetSystemSummary() map[string]string {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    summary := map[string]string{
        "system_type":     s.systemInfo.SystemType,
        "manufacturer":    s.systemInfo.Manufacturer,
        "model":           s.systemInfo.Model,
        "android_version": s.systemInfo.AndroidVersion,
        "rom_version":     s.systemInfo.ROMVersion,
        "cpu_arch":        s.systemInfo.CPUArch,
    }
    
    if s.systemInfo.StorageInfo != nil {
        summary["storage_usage"] = s.systemInfo.StorageInfo.UsagePercent
    }
    
    // 添加系统特定信息
    if s.systemInfo.HyperOSInfo != nil && s.systemInfo.HyperOSInfo.IsHyperOS {
        summary["hyperos_version"] = s.systemInfo.HyperOSInfo.Version
    }
    if s.systemInfo.MIUIInfo != nil && s.systemInfo.MIUIInfo.IsMIUI {
        summary["miui_version"] = s.systemInfo.MIUIInfo.Version
    }
    if s.systemInfo.HarmonyOSInfo != nil && s.systemInfo.HarmonyOSInfo.IsHarmonyOS {
        summary["harmonyos_version"] = s.systemInfo.HarmonyOSInfo.Version
    }
    
    return summary
}

// GetOptimizationSuggestions 获取优化建议
func (s *SystemAdapter) GetOptimizationSuggestions() []string {
    suggestions := []string{}
    
    switch s.systemInfo.SystemType {
    case SystemTypeHyperOS:
        suggestions = append(suggestions, 
            "启用HyperOS AI学习数据清理",
            "优化设备通知缓存",
            "清理跨设备协同临时数据")
    case SystemTypeMIUI:
        suggestions = append(suggestions,
            "优化光子引擎缓存",
            "清理MIUI系统主题残留",
            "处理AI办公套件数据")
    case SystemHarmonyOS:
        suggestions = append(suggestions,
            "清理分布式架构缓存",
            "优化方舟引擎运行数据",
            "处理跨设备剪贴板历史")
    case SystemOriginOS:
        suggestions = append(suggestions,
            "优化蓝河流畅引擎缓存",
            "清理原子组件数据",
            "处理Spring动效临时文件")
    case SystemColorOS:
        suggestions = append(suggestions,
            "清理潮汐引擎临时数据",
            "优化极光引擎缓存",
            "处理AI影像增强数据")
    }
    
    return suggestions
}