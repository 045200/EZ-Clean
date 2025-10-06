// Package ezclean 提供Android设备的智能清理功能
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ==================== 常量定义 ====================
const (
	LogLevelCritical = 0
	LogLevelBasic    = 1
	LogLevelDetailed = 2
	LogLevelDebug    = 3

	DefaultIntervalMin   = 1440
	DefaultLogBufferSize = 20
	DefaultLogPurgeSize  = "5M"
	
	MaxRecursionDepth = 20
	BatchDeleteSize   = 100
	MaxFileSize       = 500 * 1024 * 1024
	
	// 安全限制
	MaxConcurrentLimit    = 10
	MaxBatchSizeLimit     = 100
	MaxPathsPerClean      = 10000
	MaxPathLength         = 4096
	MaxOpenFiles          = 1000
	ShutdownTimeoutSec    = 10
	
	// 操作频率限制调整
	MaxOperationsPerMinute = 5000  // 大幅提高限制
	OperationResetInterval = 30 * time.Second  // 缩短重置间隔
)

// ==================== 清理类型定义 ====================
type CleanType int

const (
	CleanTypeNormal CleanType = iota
	CleanTypeMT
)

// ==================== 系统状态定义 ====================
type SystemStatus int

const (
	StatusOptimal SystemStatus = iota
	StatusModerate
	StatusConservative
	StatusCritical
)

// ==================== 健康状态定义 ====================
type HealthStatus int

const (
	HealthStatusHealthy HealthStatus = iota
	HealthStatusDegraded
	HealthStatusUnhealthy
)

// ==================== 系统类型定义 ====================
type SystemType int

const (
	SystemTypeAOSP SystemType = iota
	SystemTypeAOSPBased
	SystemTypeMIUI
	SystemTypeEMUI
	SystemTypeColorOS
	SystemTypeFuntouchOS
	SystemTypeOneUI
	SystemTypeOther
)

// ==================== 配置结构 ====================
type AppConfig struct {
	IntervalMin        int
	TimedClean         bool
	LogEnable          bool
	CalcSizeEn         bool
	MtClean            bool
	MtPackages         string
	MtAggressive       bool
	LogClean           bool
	LogPurgeSize       string
	LogLevel           int
	LogBufferSize      int
	LogCompress        bool
	MaxConcurrent      int
	BatchSize          int
	SafeMode           bool
	BackupEnabled      bool
	MaxBackupSize      string
	UseFastDelete      bool
	CleanEmptyDirs     bool
	ExcludeSystem      bool
	ResourceAware      bool
	BatteryThreshold   int
	MemoryThreshold    int
	CPULoadThreshold   int
	// 安全配置
	AllowedBasePaths   []string
	RequireConfigSign  bool
	MaxFileOperations  int
	AuditMode          bool
	// 性能配置
	HealthCheckInterval int
	MetricsEnabled      bool
	ConfigHotReload     bool
	// 系统自适应
	SystemAdaptive     bool
}

// ==================== 系统信息结构 ====================
type SystemInfo struct {
	AndroidVersion    int
	TotalMemory       int64
	AvailableMemory   int64
	CPUCores          int
	CPULoad           float64
	BatteryLevel      int
	IsCharging        bool
	RootMethod        string
	StorageAvailable  int64
	SystemStatus      SystemStatus
	SystemType        SystemType
	Manufacturer      string
	Model             string
	ROMVersion        string
	IsTablet          bool
	HasExternalSD     bool
}

// ==================== 健康状态结构 ====================
type HealthStatusReport struct {
	Status          HealthStatus
	Timestamp       time.Time
	Checks          map[string]bool
	Metrics         map[string]interface{}
	LastError       string
	Uptime          time.Duration
}

// ==================== 性能指标结构 ====================
type Metrics struct {
	sync.RWMutex
	FilesCleaned        int64
	BytesFreed          int64
	OperationsFailed    int64
	CleanupDuration     time.Duration
	LastCleanupTime     time.Time
	MemoryUsage         int64
	GoroutineCount      int
	OpenFileCount       int
	CPUUsage            float64
}

// ==================== 全局变量 ====================
var (
	configPath  string
	blackPath   string
	whitePath   string
	mtBlackPath string
	logPath     string
	backupDir   string
	auditPath   string
	healthPath  string

	globalConfig AppConfig
	systemInfo   SystemInfo
	logFile      *os.File
	logWriter    *bufio.Writer

	shutdownChan = make(chan struct{})
	pauseChan    = make(chan bool, 10)
	
	cleanupStats struct {
		sync.RWMutex
		totalFiles int
		totalBytes int64
		lastRun    time.Time
	}

	resourceMonitor struct {
		sync.RWMutex
		lastCheck    time.Time
		currentStatus SystemStatus
	}

	// 安全控制 - 改进的操作频率限制
	securityContext struct {
		sync.RWMutex
		fileOperationCount int32
		lastOperationTime  time.Time
		lastResetTime      time.Time
		suspiciousActivities []string
	}

	// 资源管理器
	resourceManager = &ResourceManager{
		openFiles: make(map[string]*os.File),
		maxFiles:  MaxOpenFiles,
	}

	// 配置管理器
	configManager = &SafeConfig{}

	// 健康监控
	healthMonitor = &HealthMonitor{
		startTime: time.Now(),
		status:    HealthStatusHealthy,
		checks:    make(map[string]bool),
		metrics:   make(map[string]interface{}),
	}

	// 性能指标
	globalMetrics = &Metrics{}
)

// ==================== 系统保护路径 ====================
var criticalSystemPaths = []string{
	"/system", "/vendor", "/proc", "/sys", "/dev", "/boot",
	"/data/adb", "/data/system", "/data/vendor", "/data/misc",
	"/data/app/", "/system/app/", "/product", "/odm", "/oem",
}

// ==================== 允许清理的基础路径 ====================
var allowedBasePaths = []string{
	"/data/media/0/Android/data",
	"/data/data",
	"/data/local/tmp",
	"/cache",
	"/data/media/0/Android/EZ-Clean",
	"/storage/emulated/0/Android/data",
}

// ==================== 资源管理器 ====================
type ResourceManager struct {
	mu        sync.RWMutex
	openFiles map[string]*os.File
	maxFiles  int
}

func (rm *ResourceManager) OpenFile(path string) (*os.File, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	if len(rm.openFiles) >= rm.maxFiles {
		return nil, fmt.Errorf("文件描述符耗尽，当前已打开 %d 个文件", len(rm.openFiles))
	}
	
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	
	rm.openFiles[path] = file
	return file, nil
}

func (rm *ResourceManager) CloseFile(path string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	if file, exists := rm.openFiles[path]; exists {
		delete(rm.openFiles, path)
		return file.Close()
	}
	return nil
}

func (rm *ResourceManager) CloseAll() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	var lastError error
	for path, file := range rm.openFiles {
		if err := file.Close(); err != nil {
			lastError = err
			logMsg(fmt.Sprintf("关闭文件失败 %s: %v", path, err), LogLevelDebug)
		}
		delete(rm.openFiles, path)
	}
	
	return lastError
}

func (rm *ResourceManager) GetOpenFileCount() int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return len(rm.openFiles)
}

// ==================== 安全配置管理器 ====================
type SafeConfig struct {
	mu     sync.RWMutex
	config AppConfig
}

func (sc *SafeConfig) Get() AppConfig {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.config
}

func (sc *SafeConfig) Update(newConfig AppConfig) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.config = newConfig
}

func (sc *SafeConfig) GetMaxConcurrent() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if sc.config.MaxConcurrent <= 0 {
		return 3
	}
	return min(sc.config.MaxConcurrent, MaxConcurrentLimit)
}

func (sc *SafeConfig) GetBatchSize() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if sc.config.BatchSize <= 0 {
		return 50
	}
	return min(sc.config.BatchSize, MaxBatchSizeLimit)
}

// ==================== 健康监控器 ====================
type HealthMonitor struct {
	sync.RWMutex
	startTime time.Time
	status    HealthStatus
	checks    map[string]bool
	metrics   map[string]interface{}
	lastError string
}

func (hm *HealthMonitor) UpdateCheck(name string, healthy bool) {
	hm.Lock()
	defer hm.Unlock()
	hm.checks[name] = healthy
	hm.updateOverallStatus()
}

func (hm *HealthMonitor) UpdateMetric(name string, value interface{}) {
	hm.Lock()
	defer hm.Unlock()
	hm.metrics[name] = value
}

func (hm *HealthMonitor) RecordError(err error) {
	hm.Lock()
	defer hm.Unlock()
	if err != nil {
		hm.lastError = err.Error()
		hm.status = HealthStatusUnhealthy
	}
}

func (hm *HealthMonitor) updateOverallStatus() {
	healthyCount := 0
	totalCount := len(hm.checks)
	
	for _, healthy := range hm.checks {
		if healthy {
			healthyCount++
		}
	}
	
	if totalCount == 0 {
		hm.status = HealthStatusHealthy
		return
	}
	
	if healthyCount == totalCount {
		hm.status = HealthStatusHealthy
	} else if float64(healthyCount)/float64(totalCount) > 0.7 {
		hm.status = HealthStatusDegraded
	} else {
		hm.status = HealthStatusUnhealthy
	}
}

func (hm *HealthMonitor) GetStatus() HealthStatusReport {
	hm.RLock()
	defer hm.RUnlock()
	
	checksCopy := make(map[string]bool)
	for k, v := range hm.checks {
		checksCopy[k] = v
	}
	
	metricsCopy := make(map[string]interface{})
	for k, v := range hm.metrics {
		metricsCopy[k] = v
	}
	
	return HealthStatusReport{
		Status:    hm.status,
		Timestamp: time.Now(),
		Checks:    checksCopy,
		Metrics:   metricsCopy,
		LastError: hm.lastError,
		Uptime:    time.Since(hm.startTime),
	}
}

// ==================== 初始化系统 ====================
func init() {
	if err := initPaths(); err != nil {
		fmt.Fprintf(os.Stderr, "路径初始化失败: %v\n", err)
		os.Exit(1)
	}

	if err := initLogSystem(); err != nil {
		fmt.Fprintf(os.Stderr, "日志系统初始化失败: %v\n", err)
		os.Exit(1)
	}
}

func initPaths() error {
	// 优先尝试 /data/media/0/Android/EZ-Clean/
	dataDir := "/data/media/0/Android/EZ-Clean/"
	
	// 如果主路径不可用，尝试备用路径
	if _, err := os.Stat(dataDir); err != nil {
		dataDir = "/storage/emulated/0/Android/EZ-Clean/"
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("创建数据目录失败 %s: %v", dataDir, err)
		}
	} else {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("创建数据目录失败 %s: %v", dataDir, err)
		}
	}

	configPath = filepath.Join(dataDir, "config.conf")
	blackPath = filepath.Join(dataDir, "blacklist.conf")
	whitePath = filepath.Join(dataDir, "whitelist.conf")
	mtBlackPath = filepath.Join(dataDir, "MT.conf")
	logPath = filepath.Join(dataDir, "clean.log")
	backupDir = filepath.Join(dataDir, "backup")
	healthPath = filepath.Join(dataDir, "health.status")

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("创建备份目录失败 %s: %v", backupDir, err)
	}

	logMsg(fmt.Sprintf("数据目录: %s", dataDir), LogLevelBasic)
	return nil
}

func initLogSystem() error {
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %v", err)
	}

	var err error
	logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %v", err)
	}

	if err := os.Chmod(logPath, 0644); err != nil {
		return fmt.Errorf("设置日志文件权限失败: %v", err)
	}

	logWriter = bufio.NewWriterSize(logFile, DefaultLogBufferSize*1024)
	
	healthMonitor.UpdateCheck("log_system", true)
	return nil
}

// ==================== 工具函数 ====================
func min(a, b int) int {
	if a < 0 || b < 0 {
		return 0
	}
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a < 0 || b < 0 {
		return 0
	}
	if a > b {
		return a
	}
	return b
}

func safeSliceLimit(slice []string, max int) []string {
	if len(slice) <= max {
		return slice
	}
	newSlice := make([]string, max)
	copy(newSlice, slice[:max])
	return newSlice
}

// 获取本地时间字符串（统一时间格式）
func getLocalTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// 格式化时间（统一时间格式）
func formatTime(t time.Time) string {
	if t.IsZero() {
		return "从未"
	}
	return t.Format("2006-01-02 15:04:05")
}

// 获取系统时间 - 优先获取Android系统时间，失败则使用本地北京时间
func getSystemTime() string {
	// 尝试多种方法获取Android系统时间
	timeFormats := []string{
		"+%Y-%m-%d %H:%M:%S",
		"+%F %T",
		"+%c",
	}
	
	commands := [][]string{
		{"date"},
		{"busybox", "date"},
		{"toybox", "date"},
	}
	
	for _, cmdArgs := range commands {
		for _, format := range timeFormats {
			args := make([]string, len(cmdArgs))
			copy(args, cmdArgs)
			if len(args) > 0 {
				// 如果是date命令，添加格式参数
				if args[0] == "date" || args[0] == "busybox" || args[0] == "toybox" {
					args = append(args, format)
				}
			}
			
			if len(args) == 0 {
				continue
			}
			
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			
			cmd := exec.CommandContext(ctx, args[0], args[1:]...)
			output, err := cmd.Output()
			if err == nil {
				timeStr := strings.TrimSpace(string(output))
				// 验证时间格式是否正确（包含数字和分隔符）
				if len(timeStr) >= 10 && containsDigits(timeStr) {
					return timeStr
				}
			}
		}
	}
	
	// 所有方法都失败，使用本地北京时间
	logMsg("无法获取Android系统时间，使用本地北京时间", LogLevelDebug)
	return getLocalTime()
}

// 检查字符串是否包含数字
func containsDigits(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// ==================== 配置管理 ====================
func loadConfig() error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logMsg("配置文件不存在，创建默认配置", LogLevelBasic)
		return saveDefaultConfig()
	}

	// 检查配置文件权限
	if !isSecureConfigFile(configPath) {
		return fmt.Errorf("配置文件权限不安全")
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	newConfig, err := parseConfigContent(string(content))
	if err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	if err := validateConfig(newConfig); err != nil {
		logMsg(fmt.Sprintf("配置验证失败，使用默认值: %v", err), LogLevelCritical)
		return saveDefaultConfig()
	}

	configManager.Update(newConfig)
	logMsg("配置文件加载成功", LogLevelDetailed)
	healthMonitor.UpdateCheck("config_system", true)
	return nil
}

func parseConfigContent(content string) (AppConfig, error) {
	config := AppConfig{}
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// 解析键值对
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		
		switch key {
		case "interval_min":
			if v, err := strconv.Atoi(value); err == nil {
				config.IntervalMin = v
			}
		case "timed_cleaning":
			config.TimedClean = strings.ToLower(value) == "true"
		case "log_enable":
			config.LogEnable = strings.ToLower(value) == "true"
		case "calc_size_enable":
			config.CalcSizeEn = strings.ToLower(value) == "true"
		case "mt_cleaning":
			config.MtClean = strings.ToLower(value) == "true"
		case "mt_packages":
			config.MtPackages = value
		case "mt_aggressive":
			config.MtAggressive = strings.ToLower(value) == "true"
		case "log_cleaning":
			config.LogClean = strings.ToLower(value) == "true"
		case "log_purge_size":
			config.LogPurgeSize = value
		case "log_level":
			if v, err := strconv.Atoi(value); err == nil {
				config.LogLevel = v
			}
		case "log_buffer_size":
			if v, err := strconv.Atoi(value); err == nil {
				config.LogBufferSize = v
			}
		case "log_compress":
			config.LogCompress = strings.ToLower(value) == "true"
		case "max_concurrent":
			if v, err := strconv.Atoi(value); err == nil {
				config.MaxConcurrent = v
			}
		case "batch_size":
			if v, err := strconv.Atoi(value); err == nil {
				config.BatchSize = v
			}
		case "safe_mode":
			config.SafeMode = strings.ToLower(value) == "true"
		case "backup_enabled":
			config.BackupEnabled = strings.ToLower(value) == "true"
		case "max_backup_size":
			config.MaxBackupSize = value
		case "use_fast_delete":
			config.UseFastDelete = strings.ToLower(value) == "true"
		case "clean_empty_dirs":
			config.CleanEmptyDirs = strings.ToLower(value) == "true"
		case "exclude_system":
			config.ExcludeSystem = strings.ToLower(value) == "true"
		case "resource_aware":
			config.ResourceAware = strings.ToLower(value) == "true"
		case "battery_threshold":
			if v, err := strconv.Atoi(value); err == nil {
				config.BatteryThreshold = v
			}
		case "memory_threshold":
			if v, err := strconv.Atoi(value); err == nil {
				config.MemoryThreshold = v
			}
		case "cpu_load_threshold":
			if v, err := strconv.Atoi(value); err == nil {
				config.CPULoadThreshold = v
			}
		case "allowed_base_paths":
			config.AllowedBasePaths = strings.Split(value, ",")
		case "require_config_sign":
			config.RequireConfigSign = strings.ToLower(value) == "true"
		case "max_file_operations":
			if v, err := strconv.Atoi(value); err == nil {
				config.MaxFileOperations = v
			}
		case "audit_mode":
			config.AuditMode = strings.ToLower(value) == "true"
		case "health_check_interval":
			if v, err := strconv.Atoi(value); err == nil {
				config.HealthCheckInterval = v
			}
		case "metrics_enabled":
			config.MetricsEnabled = strings.ToLower(value) == "true"
		case "config_hot_reload":
			config.ConfigHotReload = strings.ToLower(value) == "true"
		case "system_adaptive":
			config.SystemAdaptive = strings.ToLower(value) == "true"
		}
	}
	
	return config, nil
}

func saveDefaultConfig() error {
	newConfig := AppConfig{
		IntervalMin:        DefaultIntervalMin,
		TimedClean:         true,
		LogEnable:          true,
		CalcSizeEn:         false,
		MtClean:            true,
		MtPackages:         "bin.mt.plus,bin.mt.plus9,bin.mt.plus.debug",
		MtAggressive:       false,
		LogClean:           true,
		LogPurgeSize:       DefaultLogPurgeSize,
		LogLevel:           LogLevelDebug,
		LogBufferSize:      DefaultLogBufferSize,
		LogCompress:        false,
		MaxConcurrent:      3,
		BatchSize:          50,
		SafeMode:           true,
		BackupEnabled:      false,
		MaxBackupSize:      "100M",
		UseFastDelete:      true,
		CleanEmptyDirs:     true,
		ExcludeSystem:      true,
		ResourceAware:      true,
		BatteryThreshold:   20,
		MemoryThreshold:    512,
		CPULoadThreshold:   80,
		// 安全配置
		AllowedBasePaths:   allowedBasePaths,
		RequireConfigSign:  false,
		MaxFileOperations:  MaxOperationsPerMinute, // 使用新的限制
		AuditMode:          false,
		// 性能配置
		HealthCheckInterval: 60,
		MetricsEnabled:      true,
		ConfigHotReload:     true,
		// 系统自适应
		SystemAdaptive:      true,
	}

	configManager.Update(newConfig)
	
	configContent := generateConfigContent(newConfig)
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return fmt.Errorf("写入默认配置失败: %v", err)
	}

	logMsg("默认配置文件已创建", LogLevelBasic)
	return nil
}

func generateConfigContent(config AppConfig) string {
	var content strings.Builder
	
	content.WriteString("# EZ-Clean 配置文件\n")
	content.WriteString("# 注释以 # 开头\n\n")
	
	content.WriteString("# 基本配置\n")
	content.WriteString(fmt.Sprintf("interval_min = %d\n", config.IntervalMin))
	content.WriteString(fmt.Sprintf("timed_cleaning = %t\n", config.TimedClean))
	content.WriteString(fmt.Sprintf("log_enable = %t\n", config.LogEnable))
	content.WriteString(fmt.Sprintf("calc_size_enable = %t\n", config.CalcSizeEn))
	content.WriteString(fmt.Sprintf("log_level = %d\n", config.LogLevel))
	content.WriteString(fmt.Sprintf("log_buffer_size = %d\n", config.LogBufferSize))
	content.WriteString(fmt.Sprintf("log_compress = %t\n", config.LogCompress))
	
	content.WriteString("\n# MT清理配置\n")
	content.WriteString(fmt.Sprintf("mt_cleaning = %t\n", config.MtClean))
	content.WriteString(fmt.Sprintf("mt_packages = %s\n", config.MtPackages))
	content.WriteString(fmt.Sprintf("mt_aggressive = %t\n", config.MtAggressive))
	
	content.WriteString("\n# 清理配置\n")
	content.WriteString(fmt.Sprintf("log_cleaning = %t\n", config.LogClean))
	content.WriteString(fmt.Sprintf("log_purge_size = %s\n", config.LogPurgeSize))
	content.WriteString(fmt.Sprintf("max_concurrent = %d\n", config.MaxConcurrent))
	content.WriteString(fmt.Sprintf("batch_size = %d\n", config.BatchSize))
	content.WriteString(fmt.Sprintf("safe_mode = %t\n", config.SafeMode))
	content.WriteString(fmt.Sprintf("backup_enabled = %t\n", config.BackupEnabled))
	content.WriteString(fmt.Sprintf("max_backup_size = %s\n", config.MaxBackupSize))
	content.WriteString(fmt.Sprintf("use_fast_delete = %t\n", config.UseFastDelete))
	content.WriteString(fmt.Sprintf("clean_empty_dirs = %t\n", config.CleanEmptyDirs))
	content.WriteString(fmt.Sprintf("exclude_system = %t\n", config.ExcludeSystem))
	
	content.WriteString("\n# 资源感知配置\n")
	content.WriteString(fmt.Sprintf("resource_aware = %t\n", config.ResourceAware))
	content.WriteString(fmt.Sprintf("battery_threshold = %d\n", config.BatteryThreshold))
	content.WriteString(fmt.Sprintf("memory_threshold = %d\n", config.MemoryThreshold))
	content.WriteString(fmt.Sprintf("cpu_load_threshold = %d\n", config.CPULoadThreshold))
	
	content.WriteString("\n# 安全配置\n")
	content.WriteString(fmt.Sprintf("allowed_base_paths = %s\n", strings.Join(config.AllowedBasePaths, ",")))
	content.WriteString(fmt.Sprintf("require_config_sign = %t\n", config.RequireConfigSign))
	content.WriteString(fmt.Sprintf("max_file_operations = %d\n", config.MaxFileOperations))
	content.WriteString(fmt.Sprintf("audit_mode = %t\n", config.AuditMode))
	
	content.WriteString("\n# 性能配置\n")
	content.WriteString(fmt.Sprintf("health_check_interval = %d\n", config.HealthCheckInterval))
	content.WriteString(fmt.Sprintf("metrics_enabled = %t\n", config.MetricsEnabled))
	content.WriteString(fmt.Sprintf("config_hot_reload = %t\n", config.ConfigHotReload))
	
	content.WriteString("\n# 系统自适应\n")
	content.WriteString(fmt.Sprintf("system_adaptive = %t\n", config.SystemAdaptive))
	
	return content.String()
}

func isSecureConfigFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// 检查文件权限
	if info.Mode().Perm() & 0002 != 0 {
		return false // 不允许其他用户写入
	}

	return true
}

func validateConfig(config AppConfig) error {
	if config.IntervalMin < 1 {
		return fmt.Errorf("interval_min不能小于1")
	}
	if config.LogLevel < LogLevelCritical || config.LogLevel > LogLevelDebug {
		return fmt.Errorf("log_level必须在%d-%d之间", LogLevelCritical, LogLevelDebug)
	}
	if config.MaxConcurrent < 1 {
		return fmt.Errorf("max_concurrent不能小于1")
	}
	if config.BatchSize < 1 {
		return fmt.Errorf("batch_size不能小于1")
	}
	if config.LogBufferSize < 1 {
		return fmt.Errorf("log_buffer_size不能小于1")
	}
	if config.BatteryThreshold < 5 || config.BatteryThreshold > 95 {
		return fmt.Errorf("battery_threshold必须在5-95之间")
	}
	if config.MemoryThreshold < 100 {
		return fmt.Errorf("memory_threshold不能小于100MB")
	}
	if config.CPULoadThreshold < 10 || config.CPULoadThreshold > 95 {
		return fmt.Errorf("cpu_load_threshold必须在10-95之间")
	}
	if config.MaxFileOperations < 10 {
		return fmt.Errorf("max_file_operations不能小于10")
	}
	if config.HealthCheckInterval < 10 {
		return fmt.Errorf("health_check_interval不能小于10秒")
	}

	return nil
}

// ==================== 安全路径验证 ====================
func validateCleanPath(path string) (string, error) {
	// 检查路径长度
	if len(path) > MaxPathLength {
		return "", fmt.Errorf("路径过长")
	}

	// 解析绝对路径并清理
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("路径解析失败: %v", err)
	}

	// 检查路径遍历攻击
	if containsPathTraversal(absPath) {
		return "", fmt.Errorf("检测到路径遍历攻击")
	}

	// 验证是否在允许的基础路径内
	if !isPathAllowed(absPath) {
		return "", fmt.Errorf("路径不在允许的清理范围内: %s", absPath)
	}

	// 检查是否为关键系统路径
	if isCriticalSystemPath(absPath) {
		return "", fmt.Errorf("路径为受保护的系统路径")
	}

	return absPath, nil
}

func containsPathTraversal(path string) bool {
	traversalPatterns := []string{
		"../", "..\\", "/..", "\\..",
		"./", ".\\", "//", "\\\\",
	}
	
	for _, pattern := range traversalPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	
	// 检查绝对路径是否试图跳出允许范围
	components := strings.Split(path, string(filepath.Separator))
	depth := 0
	for _, comp := range components {
		if comp == ".." {
			depth--
			if depth < 0 {
				return true
			}
		} else if comp != "." && comp != "" {
			depth++
		}
	}
	
	return false
}

func isPathAllowed(path string) bool {
	// 使用配置中的允许路径，如果为空则使用默认值
	basePaths := configManager.Get().AllowedBasePaths
	if len(basePaths) == 0 {
		basePaths = allowedBasePaths
	}

	for _, basePath := range basePaths {
		cleanBase := filepath.Clean(basePath)
		if path == cleanBase || strings.HasPrefix(path+string(filepath.Separator), cleanBase+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func isCriticalSystemPath(path string) bool {
	if !configManager.Get().ExcludeSystem {
		return false
	}

	cleanedPath := filepath.Clean(path)
	
	for _, criticalPath := range criticalSystemPaths {
		cleanCritical := filepath.Clean(criticalPath)
		if cleanedPath == cleanCritical || 
		   strings.HasPrefix(cleanedPath+"/", cleanCritical+"/") {
			return true
		}
	}
	
	protectedPatterns := []string{
		"/data/app/", "/system/app/", "/system/priv-app/",
		"/vendor/app/", "/product/app/", "/data/dalvik-cache/",
		"/data/misc_ce/", "/data/misc_de/", "/data/system_ce/",
		"/data/system_de/", "/data/user_de/",
	}
	
	for _, pattern := range protectedPatterns {
		if strings.Contains(cleanedPath, pattern) {
			return true
		}
	}
	
	return false
}

// ==================== 操作结果结构 ====================
type OperationResult struct {
	Success bool
	Data    interface{}
	Error   error
}

func (r OperationResult) LogAndHandle(operation string, level int) {
	if r.Error != nil {
		logMsg(fmt.Sprintf("%s失败: %v", operation, r.Error), level)
		healthMonitor.RecordError(r.Error)
	} else if r.Success {
		logMsg(fmt.Sprintf("%s成功", operation), level)
		healthMonitor.UpdateCheck(operation, true)
	}
}

// ==================== 增强的环境检测 ====================
func safeDetectEnvironment() OperationResult {
	var result OperationResult
	
	if version, err := getAndroidVersion(); err != nil {
		result.Error = fmt.Errorf("Android版本检测失败: %w", err)
		healthMonitor.UpdateCheck("android_version", false)
		return result
	} else {
		systemInfo.AndroidVersion = version
		healthMonitor.UpdateCheck("android_version", true)
	}

	// 检测设备信息
	if err := detectDeviceInfo(); err != nil {
		logMsg(fmt.Sprintf("设备信息检测失败: %v", err), LogLevelDebug)
	}

	// 检测系统类型
	detectSystemType()

	if rootMethod := detectRootMethod(); rootMethod != "none" {
		systemInfo.RootMethod = rootMethod
		healthMonitor.UpdateCheck("root_access", true)
	} else {
		result.Error = fmt.Errorf("未检测到Root环境")
		healthMonitor.UpdateCheck("root_access", false)
		return result
	}

	if err := detectSystemResources(); err != nil {
		result.Error = fmt.Errorf("系统资源检测失败: %w", err)
		healthMonitor.UpdateCheck("system_resources", false)
	} else {
		healthMonitor.UpdateCheck("system_resources", true)
	}

	systemInfo.SystemStatus = calculateSystemStatus()
	result.Success = true
	
	// 记录系统信息
	logMsg(fmt.Sprintf("系统检测完成: Android %d, %s, %s, 类型: %v", 
		systemInfo.AndroidVersion, systemInfo.Manufacturer, 
		systemInfo.Model, systemInfo.SystemType), LogLevelBasic)
		
	return result
}

func getAndroidVersion() (int, error) {
	if output, err := exec.Command("getprop", "ro.build.version.sdk").Output(); err == nil {
		if version, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
			return version, nil
		}
	}
	return 0, fmt.Errorf("无法检测Android版本")
}

// ==================== 安全的Root检测 ====================
func detectRootMethod() string {
	if checkKernelSU() {
		return "kernelsu"
	}
	if checkMagisk() {
		return "magisk"
	}
	return "none"
}

func checkKernelSU() bool {
	ksuPaths := []string{
		"/data/adb/ksu",
		"/system/bin/ksu",
		"/system/xbin/ksu",
		"/data/adb/modules/ksu",
	}
	
	for _, path := range ksuPaths {
		if fileExists(path) {
			return true
		}
	}
	
	return checkProcessRunning("ksud")
}

func checkMagisk() bool {
	magiskPaths := []string{
		"/data/adb/magisk",
		"/system/bin/magisk",
		"/system/xbin/magisk",
		"/sbin/magisk",
	}
	
	for _, path := range magiskPaths {
		if fileExists(path) {
			return true
		}
	}
	
	return checkProcessRunning("magiskd") || checkSuBinary("/system/bin/su")
}

// 文件存在性检查
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// 安全的SU二进制检查
func checkSuBinary(path string) bool {
	// 验证路径安全性
	if !isKnownSuPath(path) {
		return false
	}

	// 验证文件存在性
	if !fileExists(path) {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 使用固定参数执行，避免命令注入
	cmd := exec.CommandContext(ctx, path, "-v", "--version")
	output, err := cmd.Output()
	
	if err != nil {
		return false
	}
	
	// 验证输出内容
	return strings.Contains(string(output), "SU") || 
	       strings.Contains(string(output), "Magisk") ||
	       strings.Contains(string(output), "KernelSU")
}

func isKnownSuPath(path string) bool {
	knownPaths := []string{
		"/system/bin/su",
		"/system/xbin/su", 
		"/sbin/su",
		"/vendor/bin/su",
		"/system/bin/ksu",
		"/system/xbin/ksu",
	}
	
	for _, knownPath := range knownPaths {
		if path == knownPath {
			return true
		}
	}
	return false
}

func checkProcessRunning(process string) bool {
	commands := [][]string{
		{"pgrep", "-f", process},
		{"pidof", process},
	}
	
	for _, args := range commands {
		if len(args) == 0 {
			continue
		}
		cmd := exec.Command(args[0], args[1:]...)
		output, err := cmd.Output()
		if err == nil && len(output) > 0 {
			return true
		}
	}
	return false
}

// ==================== 设备信息检测 ====================
func detectDeviceInfo() error {
	// 制造商
	if output, err := exec.Command("getprop", "ro.product.manufacturer").Output(); err == nil {
		systemInfo.Manufacturer = strings.TrimSpace(string(output))
	}
	
	// 型号
	if output, err := exec.Command("getprop", "ro.product.model").Output(); err == nil {
		systemInfo.Model = strings.TrimSpace(string(output))
	}
	
	// ROM版本
	if output, err := exec.Command("getprop", "ro.build.version.incremental").Output(); err == nil {
		systemInfo.ROMVersion = strings.TrimSpace(string(output))
	}
	
	// 检测是否为平板
	if output, err := exec.Command("getprop", "ro.build.characteristics").Output(); err == nil {
		characteristics := strings.ToLower(strings.TrimSpace(string(output)))
		systemInfo.IsTablet = strings.Contains(characteristics, "tablet")
	}
	
	// 检测外部SD卡
	systemInfo.HasExternalSD = checkExternalSDCard()
	
	return nil
}

func checkExternalSDCard() bool {
	possiblePaths := []string{
		"/storage/sdcard1",
		"/storage/extSdCard",
		"/storage/external_sd",
		"/storage/emulated/1",
		"/mnt/external_sd",
		"/mnt/sdcard/external_sd",
		"/mnt/sdcard-ext",
	}
	
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// ==================== 系统类型检测 ====================
func detectSystemType() {
	// 检测MIUI
	if checkMIUI() {
		systemInfo.SystemType = SystemTypeMIUI
		return
	}
	
	// 检测EMUI
	if checkEMUI() {
		systemInfo.SystemType = SystemTypeEMUI
		return
	}
	
	// 检测ColorOS
	if checkColorOS() {
		systemInfo.SystemType = SystemTypeColorOS
		return
	}
	
	// 检测FuntouchOS
	if checkFuntouchOS() {
		systemInfo.SystemType = SystemTypeFuntouchOS
		return
	}
	
	// 检测OneUI
	if checkOneUI() {
		systemInfo.SystemType = SystemTypeOneUI
		return
	}
	
	// 检测AOSP
	if checkAOSP() {
		systemInfo.SystemType = SystemTypeAOSP
		return
	}
	
	// 类原生
	if checkAOSPBased() {
		systemInfo.SystemType = SystemTypeAOSPBased
		return
	}
	
	systemInfo.SystemType = SystemTypeOther
}

func checkMIUI() bool {
	miuiIndicators := []string{
		"ro.miui.ui.version.name",
		"ro.miui.ui.version.code",
		"ro.miui.internal.storage",
	}
	
	for _, prop := range miuiIndicators {
		if output, err := exec.Command("getprop", prop).Output(); err == nil {
			if strings.TrimSpace(string(output)) != "" {
				return true
			}
		}
	}
	
	// 检查MIUI特定目录
	miuiDirs := []string{
		"/system/app/MiuiVideo",
		"/system/app/MiuiGallery",
		"/system/priv-app/MiuiHome",
	}
	
	for _, dir := range miuiDirs {
		if fileExists(dir) {
			return true
		}
	}
	
	return false
}

func checkEMUI() bool {
	emuiIndicators := []string{
		"ro.build.version.emui",
		"ro.build.hw_emui_api_level",
	}
	
	for _, prop := range emuiIndicators {
		if output, err := exec.Command("getprop", prop).Output(); err == nil {
			if strings.TrimSpace(string(output)) != "" {
				return true
			}
		}
	}
	
	// 检查华为特定目录
	emuiDirs := []string{
		"/system/app/HwCamera",
		"/system/app/HwSystemManager",
		"/system/priv-app/HwSystemManager",
	}
	
	for _, dir := range emuiDirs {
		if fileExists(dir) {
			return true
		}
	}
	
	return false
}

func checkColorOS() bool {
	colorOSIndicators := []string{
		"ro.oppo.version",
		"ro.oppo.operator",
		"ro.build.version.opporom",
	}
	
	for _, prop := range colorOSIndicators {
		if output, err := exec.Command("getprop", prop).Output(); err == nil {
			if strings.TrimSpace(string(output)) != "" {
				return true
			}
		}
	}
	
	// 检查OPPO特定目录
	colorOSDirs := []string{
		"/system/app/ColorOSGallery",
		"/system/app/OppoCamera",
		"/system/priv-app/OppoLauncher",
	}
	
	for _, dir := range colorOSDirs {
		if fileExists(dir) {
			return true
		}
	}
	
	return false
}

func checkFuntouchOS() bool {
	funtouchOSIndicators := []string{
		"ro.vivo.os.version",
		"ro.vivo.os.name",
	}
	
	for _, prop := range funtouchOSIndicators {
		if output, err := exec.Command("getprop", prop).Output(); err == nil {
			if strings.TrimSpace(string(output)) != "" {
				return true
			}
		}
	}
	
	// 检查vivo特定目录
	funtouchOSDirs := []string{
		"/system/app/vivoGallery",
		"/system/app/vivoCamera",
		"/system/priv-app/vivoLauncher",
	}
	
	for _, dir := range funtouchOSDirs {
		if fileExists(dir) {
			return true
		}
	}
	
	return false
}

func checkOneUI() bool {
	oneUIIndicators := []string{
		"ro.build.PDA",
		"ro.build.version.samsung",
	}
	
	// 三星设备通常有特定的型号前缀
	if strings.HasPrefix(strings.ToLower(systemInfo.Manufacturer), "samsung") {
		return true
	}
	
	for _, prop := range oneUIIndicators {
		if output, err := exec.Command("getprop", prop).Output(); err == nil {
			if strings.TrimSpace(string(output)) != "" {
				return true
			}
		}
	}
	
	// 检查三星特定目录
	oneUIDirs := []string{
		"/system/app/SamsungCamera",
		"/system/app/SamsungGallery",
		"/system/priv-app/SamsungLauncher",
	}
	
	for _, dir := range oneUIDirs {
		if fileExists(dir) {
			return true
		}
	}
	
	return false
}

func checkAOSP() bool {
	// AOSP通常没有厂商特定的属性
	aospIndicators := []string{
		"ro.build.type", // 通常是userdebug或eng
	}
	
	hasAOSPProps := true
	for _, prop := range aospIndicators {
		if output, err := exec.Command("getprop", prop).Output(); err != nil {
			hasAOSPProps = false
			break
		} else if strings.TrimSpace(string(output)) == "" {
			hasAOSPProps = false
			break
		}
	}
	
	return hasAOSPProps && systemInfo.Manufacturer == "" && systemInfo.ROMVersion == ""
}

func checkAOSPBased() bool {
	// 类原生系统（如LineageOS, PixelExperience等）
	customROMIndicators := []string{
		"ro.lineage.version",
		"ro.pixelexperience.version",
		"ro.carbon.version",
		"ro.aosp.version",
	}
	
	for _, prop := range customROMIndicators {
		if output, err := exec.Command("getprop", prop).Output(); err == nil {
			if strings.TrimSpace(string(output)) != "" {
				return true
			}
		}
	}
	
	// 检查原生系统特征
	if systemInfo.Manufacturer == "Google" || 
	   strings.Contains(strings.ToLower(systemInfo.Model), "pixel") {
		return true
	}
	
	return false
}

// ==================== 系统资源检测 ====================
func detectSystemResources() error {
	if err := detectMemoryInfo(); err != nil {
		return fmt.Errorf("内存检测失败: %v", err)
	}
	if err := detectCPUInfo(); err != nil {
		return fmt.Errorf("CPU检测失败: %v", err)
	}
	if err := detectBatteryInfo(); err != nil {
		return fmt.Errorf("电池检测失败: %v", err)
	}
	if err := detectStorageInfo(); err != nil {
		return fmt.Errorf("存储检测失败: %v", err)
	}
	return nil
}

func detectMemoryInfo() error {
	content, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if kb, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
					systemInfo.TotalMemory = kb * 1024
				}
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if kb, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
					systemInfo.AvailableMemory = kb * 1024
				}
			}
		}
	}
	return nil
}

func detectCPUInfo() error {
	systemInfo.CPUCores = runtime.NumCPU()
	if load, err := getCPULoad(); err == nil {
		systemInfo.CPULoad = load
	}
	return nil
}

func getCPULoad() (float64, error) {
	content, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(content))
	if len(fields) > 0 {
		if load, err := strconv.ParseFloat(fields[0], 64); err == nil {
			return (load / float64(systemInfo.CPUCores)) * 100, nil
		}
	}
	return 0, fmt.Errorf("无法解析CPU负载")
}

func detectBatteryInfo() error {
	if content, err := os.ReadFile("/sys/class/power_supply/battery/capacity"); err == nil {
		if level, err := strconv.Atoi(strings.TrimSpace(string(content))); err == nil {
			systemInfo.BatteryLevel = level
		}
	}

	if content, err := os.ReadFile("/sys/class/power_supply/battery/status"); err == nil {
		status := strings.TrimSpace(string(content))
		systemInfo.IsCharging = strings.Contains(status, "Charging") || 
		                       strings.Contains(status, "Full")
	}
	return nil
}

func detectStorageInfo() error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/data", &stat); err != nil {
		return err
	}
	systemInfo.StorageAvailable = (int64(stat.Bavail) * int64(stat.Bsize)) / 1024 / 1024
	return nil
}

// ==================== 资源感知和动态调整 ====================
func calculateSystemStatus() SystemStatus {
	if systemInfo.TotalMemory == 0 {
		return StatusOptimal
	}
	
	memoryUsage := float64(systemInfo.TotalMemory-systemInfo.AvailableMemory) / float64(systemInfo.TotalMemory) * 100

	batteryLow := systemInfo.BatteryLevel < configManager.Get().BatteryThreshold
	notCharging := !systemInfo.IsCharging

	if memoryUsage > 90 || systemInfo.CPULoad > 90 || (batteryLow && notCharging) {
		return StatusCritical
	} else if memoryUsage > 75 || systemInfo.CPULoad > 75 {
		return StatusConservative
	} else if memoryUsage > 50 || systemInfo.CPULoad > 50 {
		return StatusModerate
	} else {
		return StatusOptimal
	}
}

func getAdjustedCleanParams() (maxConcurrent int, batchSize int) {
	resourceMonitor.RLock()
	status := resourceMonitor.currentStatus
	resourceMonitor.RUnlock()

	switch status {
	case StatusOptimal:
		return configManager.GetMaxConcurrent(), configManager.GetBatchSize()
	case StatusModerate:
		return max(1, configManager.GetMaxConcurrent()/2), max(10, configManager.GetBatchSize()/2)
	case StatusConservative:
		return 1, max(5, configManager.GetBatchSize()/4)
	case StatusCritical:
		return 0, 0
	default:
		return configManager.GetMaxConcurrent(), configManager.GetBatchSize()
	}
}

func shouldPauseCleaning() bool {
	if !configManager.Get().ResourceAware {
		return false
	}

	resourceMonitor.RLock()
	defer resourceMonitor.RUnlock()
	
	return resourceMonitor.currentStatus == StatusCritical
}

func startResourceMonitor() {
	logMsg("启动资源监控器", LogLevelDetailed)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := detectSystemResources(); err == nil {
				newStatus := calculateSystemStatus()
				
				resourceMonitor.Lock()
				oldStatus := resourceMonitor.currentStatus
				resourceMonitor.currentStatus = newStatus
				resourceMonitor.lastCheck = time.Now()
				resourceMonitor.Unlock()

				if oldStatus != newStatus {
					statusNames := []string{"Optimal", "Moderate", "Conservative", "Critical"}
					if int(oldStatus) < len(statusNames) && int(newStatus) < len(statusNames) {
						logMsg(fmt.Sprintf("系统状态变更: %s -> %s", 
							statusNames[oldStatus], statusNames[newStatus]), LogLevelBasic)
					}
					
					if newStatus == StatusCritical && oldStatus != StatusCritical {
						select {
						case pauseChan <- true:
						default:
						}
					} else if newStatus != StatusCritical && oldStatus == StatusCritical {
						select {
						case pauseChan <- false:
						default:
						}
					}
				}
			}
		case <-shutdownChan:
			logMsg("资源监控器停止", LogLevelDetailed)
			return
		}
	}
}

// ==================== 系统特定的清理策略 ====================
func getSystemSpecificCleanParams() (maxConcurrent int, batchSize int, useFastDelete bool) {
	baseConcurrent := configManager.GetMaxConcurrent()
	baseBatchSize := configManager.GetBatchSize()
	
	switch systemInfo.SystemType {
	case SystemTypeMIUI:
		// MIUI 对文件操作较敏感，使用保守策略
		return max(1, baseConcurrent/2), max(10, baseBatchSize/2), false
	case SystemTypeEMUI:
		// EMUI 性能较好，可以使用中等策略
		return baseConcurrent, baseBatchSize, true
	case SystemTypeColorOS, SystemTypeFuntouchOS:
		// ColorOS和FuntouchOS对并发较敏感
		return max(1, baseConcurrent/3), max(5, baseBatchSize/3), false
	case SystemTypeOneUI:
		// OneUI 性能优秀，可以使用积极策略
		return min(baseConcurrent+1, MaxConcurrentLimit), baseBatchSize, true
	case SystemTypeAOSP, SystemTypeAOSPBased:
		// 原生系统性能最佳
		return baseConcurrent, baseBatchSize, true
	default:
		// 其他系统使用保守策略
		return max(1, baseConcurrent/2), max(10, baseBatchSize/2), false
	}
}

// ==================== 改进的操作频率限制 ====================
func checkOperationRateLimit() bool {
	securityContext.Lock()
	defer securityContext.Unlock()

	now := time.Now()
	
	// 如果超过重置间隔，重置计数器
	if now.Sub(securityContext.lastResetTime) > OperationResetInterval {
		securityContext.fileOperationCount = 0
		securityContext.lastResetTime = now
		logMsg("操作频率计数器已重置", LogLevelDebug)
	}

	// 获取系统状态相关的操作限制
	maxOps := getOperationLimitBySystemStatus()
	if maxOps == 0 {
		return false // 系统状态严重，不允许操作
	}

	// 检查操作限制
	if securityContext.fileOperationCount >= int32(maxOps) {
		logMsg(fmt.Sprintf("操作频率超限: %d/%d (每%d秒)", 
			securityContext.fileOperationCount, maxOps, int(OperationResetInterval.Seconds())), LogLevelDebug)
		return false
	}

	return true
}

func getOperationLimitBySystemStatus() int {
	resourceMonitor.RLock()
	status := resourceMonitor.currentStatus
	resourceMonitor.RUnlock()

	switch status {
	case StatusOptimal:
		return MaxOperationsPerMinute
	case StatusModerate:
		return MaxOperationsPerMinute / 2
	case StatusConservative:
		return MaxOperationsPerMinute / 4
	case StatusCritical:
		return 0
	default:
		return MaxOperationsPerMinute / 2
	}
}

func recordOperation() {
	securityContext.Lock()
	defer securityContext.Unlock()
	securityContext.fileOperationCount++
	securityContext.lastOperationTime = time.Now()
}

// ==================== 安全的文件操作 ====================
func cleanPath(path string) (int64, bool) {
	// 验证路径安全性
	validatedPath, err := validateCleanPath(path)
	if err != nil {
		logMsg(fmt.Sprintf("路径验证失败 %s: %v", path, err), LogLevelDebug)
		return 0, false
	}

	// 检查文件操作频率限制 - 只在安全模式下启用
	if configManager.Get().SafeMode {
		if !checkOperationRateLimit() {
			logMsg("操作频率超限，暂停清理", LogLevelBasic)
			return 0, false
		}
	}

	fileInfo, err := os.Stat(validatedPath)
	if err != nil {
		if os.IsNotExist(err) {
			logMsg(fmt.Sprintf("路径不存在: %s", validatedPath), LogLevelDebug)
		} else if os.IsPermission(err) {
			logMsg(fmt.Sprintf("权限不足: %s", validatedPath), LogLevelDebug)
		} else {
			logMsg(fmt.Sprintf("访问路径失败 %s: %v", validatedPath, err), LogLevelDebug)
		}
		return 0, false
	}

	if fileInfo.IsDir() {
		return cleanDirectory(validatedPath)
	} else {
		return cleanFile(validatedPath)
	}
}

func cleanFile(path string) (int64, bool) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return 0, false
	}

	if fileInfo.Size() > MaxFileSize {
		return 0, false
	}

	// 记录操作
	recordOperation()

	// 安全删除文件
	if err := secureDeleteFile(path); err != nil {
		atomic.AddInt64(&globalMetrics.OperationsFailed, 1)
		return 0, false
	}

	atomic.AddInt64(&globalMetrics.FilesCleaned, 1)
	atomic.AddInt64(&globalMetrics.BytesFreed, fileInfo.Size())
	return fileInfo.Size(), true
}

// 安全的文件删除
func secureDeleteFile(path string) error {
	// 在Android环境下，直接删除文件
	if err := os.Remove(path); err != nil {
		return err
	}
	return nil
}

func cleanDirectory(path string) (int64, bool) {
	if !isPathWritable(path) {
		logMsg(fmt.Sprintf("目录不可写: %s", path), LogLevelDebug)
		return 0, false
	}

	if configManager.Get().UseFastDelete {
		if freed, success := fastDeleteDirectory(path); success {
			return freed, true
		}
	}
	
	return cleanDirectorySafe(path)
}

func cleanDirectorySafe(path string) (int64, bool) {
	var totalFreed int64
	cleanedAny := false
	
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0, false
	}

	for _, entry := range entries {
		fullPath := filepath.Join(path, entry.Name())
		
		// 验证子路径安全性
		if _, err := validateCleanPath(fullPath); err != nil {
			logMsg(fmt.Sprintf("子路径验证失败: %s", err), LogLevelDebug)
			continue
		}

		if entry.IsDir() {
			freed, cleaned := cleanDirectory(fullPath)
			if cleaned {
				totalFreed += freed
				cleanedAny = true
			}
		} else {
			freed, cleaned := cleanFile(fullPath)
			if cleaned {
				totalFreed += freed
				cleanedAny = true
			}
		}
	}

	if configManager.Get().CleanEmptyDirs && isDirectoryEmpty(path) {
		if err := os.Remove(path); err == nil {
			cleanedAny = true
		}
	}
	return totalFreed, cleanedAny
}

func fastDeleteDirectory(path string) (int64, bool) {
	size, err := getDirectorySize(path)
	if err != nil {
		return 0, false
	}
	
	// 记录操作
	recordOperation()

	if err := os.RemoveAll(path); err != nil {
		atomic.AddInt64(&globalMetrics.OperationsFailed, 1)
		return 0, false
	}
	
	atomic.AddInt64(&globalMetrics.FilesCleaned, 1)
	atomic.AddInt64(&globalMetrics.BytesFreed, size)
	return size, true
}

func getDirectorySize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})
	return size, err
}

func isDirectoryEmpty(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) == 0
}

func isPathWritable(path string) bool {
	if isMountReadOnly(path) {
		return false
	}
	
	dir := filepath.Dir(path)
	testFile := filepath.Join(dir, ".write_test_tmp")
	
	if err := os.WriteFile(testFile, []byte("test"), 0644); err == nil {
		os.Remove(testFile)
		return true
	}
	
	return false
}

func isMountReadOnly(path string) bool {
	cmd := exec.Command("mount")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, path) && strings.Contains(line, "ro") {
			return true
		}
	}
	
	return false
}

// ==================== 改进的并发清理控制 ====================
func performConcurrentCleanup(targetList, whitelist []string) int {
	if shouldPauseCleaning() {
		logMsg("系统资源紧张，暂停清理操作", LogLevelBasic)
		return 0
	}

	// 在清理开始前重置操作计数器
	securityContext.Lock()
	securityContext.fileOperationCount = 0
	securityContext.lastResetTime = time.Now()
	securityContext.Unlock()

	maxConcurrent, batchSize := getAdjustedCleanParams()
	if maxConcurrent == 0 {
		logMsg("系统资源严重不足，跳过本次清理", LogLevelBasic)
		return 0
	}

	// 应用安全限制
	maxConcurrent = min(maxConcurrent, MaxConcurrentLimit)
	batchSize = min(batchSize, MaxBatchSizeLimit)
	
	// 限制处理的总路径数
	targetList = safeSliceLimit(targetList, MaxPathsPerClean)
	if len(targetList) > MaxPathsPerClean {
		logMsg(fmt.Sprintf("路径数量超过限制，仅处理前 %d 条", MaxPathsPerClean), LogLevelBasic)
	}

	logMsg(fmt.Sprintf("资源感知清理: 并发数=%d, 批次大小=%d", maxConcurrent, batchSize), LogLevelDetailed)

	startTime := time.Now()
	defer func() {
		globalMetrics.Lock()
		globalMetrics.CleanupDuration = time.Since(startTime)
		globalMetrics.LastCleanupTime = time.Now()
		globalMetrics.Unlock()
	}()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrent)
	
	results := make(chan int, len(targetList))
	errors := make(chan error, len(targetList))
	
	processedCount := 0
	
	for i := 0; i < len(targetList) && processedCount < MaxPathsPerClean; i += batchSize {
		end := i + batchSize
		if end > len(targetList) {
			end = len(targetList)
		}
		
		batch := targetList[i:end]
		
		for _, path := range batch {
			if processedCount >= MaxPathsPerClean {
				break
			}

			// 安全检查
			if isCriticalSystemPath(path) {
				logMsg(fmt.Sprintf("跳过关键系统路径: %s", path), LogLevelDebug)
				continue
			}

			if whitelist != nil && isInWhitelist(path, whitelist) {
				logMsg(fmt.Sprintf("白名单过滤: %s", path), LogLevelDebug)
				continue
			}

			wg.Add(1)
			processedCount++
			
			go func(p string) {
				defer wg.Done()
				
				if shouldPauseCleaning() {
					logMsg("清理过程中检测到资源紧张，中止当前操作", LogLevelBasic)
					return
				}
				
				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				case <-time.After(30 * time.Second):
					errors <- fmt.Errorf("获取信号量超时: %s", p)
					return
				}
				
				freed, cleaned, err := safeCleanPath(p)
				if err != nil {
					errors <- err
					results <- 0
					return
				}
				
				if cleaned {
					results <- 1
					cleanupStats.Lock()
					cleanupStats.totalFiles++
					cleanupStats.totalBytes += freed
					cleanupStats.Unlock()
					
					logMsg(fmt.Sprintf("清理成功: %s (%.2fMB)", p, float64(freed)/1024/1024), LogLevelDetailed)
				} else {
					results <- 0
				}
			}(path)
		}

		// 添加延迟以避免资源峰值
		time.Sleep(100 * time.Millisecond)
	}

	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	totalCleaned := 0
	errorCount := 0
	
	for result := range results {
		totalCleaned += result
	}
	
	for err := range errors {
		errorCount++
		logMsg(fmt.Sprintf("清理错误: %v", err), LogLevelDebug)
	}
	
	if errorCount > 0 {
		logMsg(fmt.Sprintf("清理过程中发生 %d 个错误", errorCount), LogLevelBasic)
	}

	return totalCleaned
}

func safeCleanPath(path string) (freed int64, cleaned bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in cleanPath: %v", r)
			cleaned = false
			freed = 0
		}
	}()
	
	freed, cleaned = cleanPath(path)
	return freed, cleaned, nil
}

// ==================== 改进的健康检查和指标收集 ====================
func startHealthMonitor() {
	interval := configManager.Get().HealthCheckInterval
	if interval == 0 {
		interval = 60
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	// 立即执行一次健康检查和指标收集
	performHealthCheck()
	collectMetrics(true) // 强制收集所有指标
	saveHealthStatus()

	logMsg(fmt.Sprintf("健康监控器已启动，检查间隔: %d秒", interval), LogLevelBasic)

	for {
		select {
		case <-ticker.C:
			performHealthCheck()
			collectMetrics(false)
			saveHealthStatus()
		case <-shutdownChan:
			logMsg("健康监控器停止", LogLevelDetailed)
			return
		}
	}
}

func performHealthCheck() {
	// 检查关键系统状态
	healthMonitor.UpdateCheck("file_operations", checkOperationRateLimit())
	healthMonitor.UpdateCheck("memory_usage", checkMemoryUsage())
	healthMonitor.UpdateCheck("goroutine_count", checkGoroutineCount())
	healthMonitor.UpdateCheck("open_files", checkOpenFiles())
	
	// 更新系统资源状态
	if err := detectSystemResources(); err == nil {
		healthMonitor.UpdateCheck("system_resources", true)
	} else {
		healthMonitor.UpdateCheck("system_resources", false)
		healthMonitor.RecordError(err)
	}
}

func checkMemoryUsage() bool {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	globalMetrics.Lock()
	globalMetrics.MemoryUsage = int64(m.Alloc)
	globalMetrics.Unlock()
	
	// 如果内存使用超过1GB，认为不健康
	return m.Alloc < 1024*1024*1024
}

func checkGoroutineCount() bool {
	count := runtime.NumGoroutine()
	
	globalMetrics.Lock()
	globalMetrics.GoroutineCount = count
	globalMetrics.Unlock()
	
	// 如果goroutine数量超过1000，认为不健康
	return count < 1000
}

func checkOpenFiles() bool {
	count := resourceManager.GetOpenFileCount()
	
	globalMetrics.Lock()
	globalMetrics.OpenFileCount = count
	globalMetrics.Unlock()
	
	// 如果打开文件数接近限制，认为不健康
	return count < MaxOpenFiles*8/10
}

func collectMetrics(force bool) {
	if !configManager.Get().MetricsEnabled && !force {
		return
	}

	logMsg("开始收集性能指标", LogLevelDebug)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	// 更新系统资源信息
	if err := detectSystemResources(); err == nil {
		globalMetrics.Lock()
		globalMetrics.CPUUsage = systemInfo.CPULoad
		globalMetrics.Unlock()
	} else {
		logMsg(fmt.Sprintf("系统资源检测失败: %v", err), LogLevelDebug)
	}
	
	// 收集基本运行时指标
	healthMonitor.UpdateMetric("memory_alloc_mb", float64(m.Alloc)/1024/1024)
	healthMonitor.UpdateMetric("memory_sys_mb", float64(m.Sys)/1024/1024)
	healthMonitor.UpdateMetric("goroutines", runtime.NumGoroutine())
	healthMonitor.UpdateMetric("open_files", resourceManager.GetOpenFileCount())
	healthMonitor.UpdateMetric("cpu_cores", systemInfo.CPUCores)
	
	// 收集系统资源指标
	healthMonitor.UpdateMetric("cpu_usage_percent", systemInfo.CPULoad)
	healthMonitor.UpdateMetric("battery_level_percent", systemInfo.BatteryLevel)
	healthMonitor.UpdateMetric("battery_charging", systemInfo.IsCharging)
	healthMonitor.UpdateMetric("available_memory_mb", float64(systemInfo.AvailableMemory)/1024/1024)
	healthMonitor.UpdateMetric("total_memory_mb", float64(systemInfo.TotalMemory)/1024/1024)
	healthMonitor.UpdateMetric("storage_available_mb", systemInfo.StorageAvailable)
	healthMonitor.UpdateMetric("android_version", systemInfo.AndroidVersion)
	
	// 收集清理操作指标
	globalMetrics.RLock()
	healthMonitor.UpdateMetric("files_cleaned_total", globalMetrics.FilesCleaned)
	healthMonitor.UpdateMetric("bytes_freed_mb", float64(globalMetrics.BytesFreed)/1024/1024)
	healthMonitor.UpdateMetric("operations_failed_total", globalMetrics.OperationsFailed)
	healthMonitor.UpdateMetric("last_cleanup_duration_sec", globalMetrics.CleanupDuration.Seconds())
	if !globalMetrics.LastCleanupTime.IsZero() {
		healthMonitor.UpdateMetric("last_cleanup_time", formatTime(globalMetrics.LastCleanupTime))
	}
	healthMonitor.UpdateMetric("current_memory_usage_mb", float64(globalMetrics.MemoryUsage)/1024/1024)
	healthMonitor.UpdateMetric("current_goroutines", globalMetrics.GoroutineCount)
	healthMonitor.UpdateMetric("current_open_files", globalMetrics.OpenFileCount)
	healthMonitor.UpdateMetric("current_cpu_usage_percent", globalMetrics.CPUUsage)
	globalMetrics.RUnlock()
	
	// 收集操作频率信息
	securityContext.RLock()
	healthMonitor.UpdateMetric("file_operations_count", securityContext.fileOperationCount)
	healthMonitor.UpdateMetric("last_operation_time", formatTime(securityContext.lastOperationTime))
	healthMonitor.UpdateMetric("operation_reset_time", formatTime(securityContext.lastResetTime))
	securityContext.RUnlock()
	
	// 收集清理统计信息
	cleanupStats.RLock()
	healthMonitor.UpdateMetric("total_files_cleaned", cleanupStats.totalFiles)
	healthMonitor.UpdateMetric("total_bytes_freed_mb", float64(cleanupStats.totalBytes)/1024/1024)
	if !cleanupStats.lastRun.IsZero() {
		healthMonitor.UpdateMetric("last_cleanup_run", formatTime(cleanupStats.lastRun))
	}
	cleanupStats.RUnlock()
	
	// 收集系统状态信息
	resourceMonitor.RLock()
	healthMonitor.UpdateMetric("system_status", int(resourceMonitor.currentStatus))
	healthMonitor.UpdateMetric("last_resource_check", formatTime(resourceMonitor.lastCheck))
	resourceMonitor.RUnlock()
	
	logMsg(fmt.Sprintf("性能指标收集完成，共收集 %d 个指标", len(healthMonitor.metrics)), LogLevelDebug)
}

func saveHealthStatus() {
	status := healthMonitor.GetStatus()
	content := generateHealthContent(status)
	
	if err := os.WriteFile(healthPath, []byte(content), 0644); err != nil {
		logMsg(fmt.Sprintf("保存健康状态失败: %v", err), LogLevelDebug)
	} else {
		logMsg("健康状态报告已保存", LogLevelDebug)
	}
}

func generateHealthContent(status HealthStatusReport) string {
	var content strings.Builder
	
	// 使用统一的系统时间格式
	reportTime := getSystemTime()
	
	content.WriteString("# EZ-Clean 健康状态报告\n")
	content.WriteString(fmt.Sprintf("生成时间 = %s\n", reportTime))
	content.WriteString(fmt.Sprintf("status = %d\n", status.Status))
	content.WriteString(fmt.Sprintf("uptime = %s\n", status.Uptime.String()))
	
	if status.LastError != "" {
		content.WriteString(fmt.Sprintf("last_error = %s\n", status.LastError))
	}
	
	content.WriteString("\n# 健康检查状态\n")
	for check, healthy := range status.Checks {
		statusStr := "健康"
		if !healthy {
			statusStr = "异常"
		}
		content.WriteString(fmt.Sprintf("check.%s = %s\n", check, statusStr))
	}
	
	content.WriteString("\n# 性能指标\n")
	if len(status.Metrics) == 0 {
		content.WriteString("# 无性能指标数据\n")
	} else {
		for metric, value := range status.Metrics {
			switch v := value.(type) {
			case string:
				content.WriteString(fmt.Sprintf("metric.%s = %s\n", metric, v))
			case int, int32, int64:
				content.WriteString(fmt.Sprintf("metric.%s = %d\n", metric, v))
			case float32, float64:
				content.WriteString(fmt.Sprintf("metric.%s = %.2f\n", metric, v))
			case bool:
				content.WriteString(fmt.Sprintf("metric.%s = %t\n", metric, v))
			default:
				content.WriteString(fmt.Sprintf("metric.%s = %v\n", metric, v))
			}
		}
	}
	
	// 添加系统信息摘要
	content.WriteString("\n# 系统信息摘要\n")
	content.WriteString(fmt.Sprintf("system.manufacturer = %s\n", systemInfo.Manufacturer))
	content.WriteString(fmt.Sprintf("system.model = %s\n", systemInfo.Model))
	content.WriteString(fmt.Sprintf("system.android_version = %d\n", systemInfo.AndroidVersion))
	content.WriteString(fmt.Sprintf("system.root_method = %s\n", systemInfo.RootMethod))
	content.WriteString(fmt.Sprintf("system.type = %d\n", systemInfo.SystemType))
	content.WriteString(fmt.Sprintf("system.is_tablet = %t\n", systemInfo.IsTablet))
	content.WriteString(fmt.Sprintf("system.has_external_sd = %t\n", systemInfo.HasExternalSD))
	
	return content.String()
}

// ==================== 配置热重载 ====================
func startConfigHotReload() {
	if !configManager.Get().ConfigHotReload {
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	lastModTime := time.Now()
	
	for {
		select {
		case <-ticker.C:
			info, err := os.Stat(configPath)
			if err != nil {
				continue
			}
			
			if info.ModTime().After(lastModTime) {
				logMsg("检测到配置文件变化，重新加载配置", LogLevelBasic)
				if err := loadConfig(); err != nil {
					logMsg(fmt.Sprintf("配置热重载失败: %v", err), LogLevelCritical)
				} else {
					logMsg("配置热重载成功", LogLevelBasic)
				}
				lastModTime = info.ModTime()
			}
		case <-shutdownChan:
			return
		}
	}
}

// ==================== 服务管理 ====================
func startBasicServices() {
	logMsg("启动基础监控服务", LogLevelDetailed)
	go startSimpleCleanService()

	if configManager.Get().MtClean {
		go startMtService()
	}
	logMsg("基础服务启动完成", LogLevelDetailed)
}

func startSimpleCleanService() {
	logMsg("定时清理服务启动（常规清理）", LogLevelDetailed)
	config := configManager.Get()
	interval := time.Duration(config.IntervalMin) * time.Minute
	if interval <= 0 {
		interval = time.Duration(DefaultIntervalMin) * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			performCleaning(CleanTypeNormal)
		case <-shutdownChan:
			logMsg("定时清理服务停止", LogLevelDetailed)
			return
		}
	}
}

func startMtService() {
	logMsg("MT监控服务启动", LogLevelDetailed)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if isMtRunning() {
				performCleaning(CleanTypeMT)
			}
		case <-shutdownChan:
			logMsg("MT监控服务停止", LogLevelDetailed)
			return
		}
	}
}

// ==================== MT管理器检测 ====================
func isMtRunning() bool {
	processes := []string{"bin.mt.plus", "mtmanager", "mt管理器", "com.mt", "bin.mt.plus9"}
	
	for _, proc := range processes {
		if checkProcessRunning(proc) {
			logMsg(fmt.Sprintf("检测到MT管理器进程: %s", proc), LogLevelDetailed)
			return true
		}
	}
	
	packages := strings.Split(configManager.Get().MtPackages, ",")
	for _, pkg := range packages {
		pkg = strings.TrimSpace(pkg)
		if pkg != "" && isPackageInstalled(pkg) {
			logMsg(fmt.Sprintf("检测到MT管理器包: %s", pkg), LogLevelDetailed)
			return true
		}
	}
	
	logMsg("未检测到MT管理器进程", LogLevelDebug)
	return false
}

func isPackageInstalled(pkg string) bool {
	commands := [][]string{
		{"pm", "list", "packages", pkg},
		{"cmd", "package", "list", "packages", pkg},
	}
	
	for _, args := range commands {
		if len(args) == 0 {
			continue
		}
		cmd := exec.Command(args[0], args[1:]...)
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), pkg) {
			return true
		}
	}
	return false
}

// ==================== 清理执行函数 ====================
func performInitialCleaning() {
	logMsg("执行初始清理（常规模式）", LogLevelBasic)
	performCleaning(CleanTypeNormal)
}

func performCleaning(cleanType CleanType) {
	logMsg("开始执行清理任务", LogLevelBasic)

	var totalStats struct {
		pathsProcessed int
		filesDeleted   int
		bytesFreed     int64
		startTime      time.Time
	}
	totalStats.startTime = time.Now()

	switch cleanType {
	case CleanTypeNormal:
		totalStats.pathsProcessed = performNormalCleaning()
	case CleanTypeMT:
		totalStats.pathsProcessed = performMTCleaning()
	}

	duration := time.Since(totalStats.startTime)
	cleanupStats.RLock()
	totalStats.filesDeleted = cleanupStats.totalFiles
	totalStats.bytesFreed = cleanupStats.totalBytes
	cleanupStats.RUnlock()

	// 更新最后运行时间
	cleanupStats.Lock()
	cleanupStats.lastRun = time.Now()
	cleanupStats.Unlock()

	typeName := "常规"
	if cleanType == CleanTypeMT {
		typeName = "MT触发"
	}
	
	logMsg(fmt.Sprintf("%s清理完成 [路径:%d 文件:%d 大小:%.2fMB 耗时:%v]", 
		typeName, totalStats.pathsProcessed, totalStats.filesDeleted, 
		float64(totalStats.bytesFreed)/1024/1024, duration.Round(time.Millisecond)), LogLevelBasic)
	
	// 清理完成后立即收集一次指标
	collectMetrics(true)
}

func performNormalCleaning() int {
	logMsg("执行常规清理（黑名单+白名单过滤）", LogLevelBasic)
	blacklist, whitelist, err := loadBlackWhiteLists()
	if err != nil {
		logMsg(fmt.Sprintf("加载黑白名单失败: %v", err), LogLevelCritical)
		return 0
	}
	return performConcurrentCleanup(blacklist, whitelist)
}

func performMTCleaning() int {
	logMsg("执行MT触发清理（仅MT名单，不过滤白名单）", LogLevelBasic)
	mtPaths, err := loadMTList()
	if err != nil {
		logMsg(fmt.Sprintf("加载MT名单失败: %v", err), LogLevelCritical)
		return 0
	}
	return performConcurrentCleanup(mtPaths, nil)
}

func loadBlackWhiteLists() (blacklist, whitelist []string, err error) {
	blacklist, err = loadAndExpandListFile(blackPath, "黑名单")
	if err != nil {
		return nil, nil, err
	}
	whitelist, err = loadAndExpandListFile(whitePath, "白名单")
	if err != nil {
		return nil, nil, err
	}
	return blacklist, whitelist, nil
}

func loadMTList() ([]string, error) {
	return loadAndExpandListFile(mtBlackPath, "MT清理名单")
}

func loadAndExpandListFile(filePath, name string) ([]string, error) {
	rawPaths, err := loadListFile(filePath, name)
	if err != nil {
		return nil, err
	}

	var expandedPaths []string
	for _, path := range rawPaths {
		expanded := expandWildcardPath(path)
		expandedPaths = append(expandedPaths, expanded...)
	}
	
	logMsg(fmt.Sprintf("%s扩展后共有 %d 条路径", name, len(expandedPaths)), LogLevelDetailed)
	return expandedPaths, nil
}

func loadListFile(filePath, name string) ([]string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在，创建空文件
			if err := os.WriteFile(filePath, []byte("# "+name+"文件\n"), 0644); err != nil {
				return nil, fmt.Errorf("创建%s文件失败: %v", name, err)
			}
			return []string{}, nil
		}
		return nil, fmt.Errorf("读取%s文件失败: %v", name, err)
	}

	lines := strings.Split(string(content), "\n")
	var paths []string
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, "/") {
			continue
		}
		paths = append(paths, trimmed)
	}
	
	logMsg(fmt.Sprintf("从 %s 加载了 %d 条路径", name, len(paths)), LogLevelDetailed)
	return paths, nil
}

func expandWildcardPath(pattern string) []string {
	var result []string
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		matches, err := filepath.Glob(pattern)
		if err == nil && len(matches) > 0 {
			result = append(result, matches...)
		} else {
			result = append(result, pattern)
		}
	} else {
		result = append(result, pattern)
	}
	return result
}

func isInWhitelist(path string, whitelist []string) bool {
	for _, whitePath := range whitelist {
		if path == whitePath {
			return true
		}
		if strings.HasSuffix(whitePath, "/") && strings.HasPrefix(path, whitePath) {
			return true
		}
		if strings.Contains(whitePath, "*") {
			if matched, _ := filepath.Match(whitePath, path); matched {
				return true
			}
		}
	}
	return false
}

// ==================== 系统检查 ====================
func performSystemCheck() bool {
	if getAvailableDisk() < 50 * 1024 * 1024 {
		logMsg("磁盘空间不足", LogLevelCritical)
		return false
	}
	return true
}

func getAvailableDisk() int64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/data", &stat); err != nil {
		return 1024 * 1024 * 1024
	}
	return int64(stat.Bavail) * int64(stat.Bsize)
}

// ==================== 工具函数 ====================
func ensureEssentialDirs() error {
	dirs := []string{
		"/data/media/0/Android/EZ-Clean",
		"/storage/emulated/0/Android/EZ-Clean",
		backupDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录 %s 失败: %v", dir, err)
		}
	}

	return nil
}

func logMsg(msg string, level int) {
	config := configManager.Get()
	logEnabled := true
	currentLevel := LogLevelDebug
	
	if config.LogLevel >= 0 {
		logEnabled = config.LogEnable
		currentLevel = config.LogLevel
	}

	if !logEnabled || level > currentLevel {
		return
	}

	timestamp := getSystemTime() // 使用统一的系统时间
	
	levelNames := []string{"CRITICAL", "BASIC", "DETAILED", "DEBUG"}
	levelName := "UNKNOWN"
	if level >= 0 && level < len(levelNames) {
		levelName = levelNames[level]
	}
	
	fullMsg := fmt.Sprintf("[%s] [%s] %s\n", timestamp, levelName, msg)

	if logWriter != nil {
		logWriter.WriteString(fullMsg)
		logWriter.Flush()
	} else if logFile != nil {
		// 如果logWriter为nil，直接写入logFile
		logFile.WriteString(fullMsg)
		logFile.Sync()
	} else {
		// 如果连logFile都为nil，输出到标准错误
		fmt.Fprintf(os.Stderr, "%s", fullMsg)
	}
	
	if config.LogCompress {
		go compressOldLogs()
	}
}

func compressOldLogs() {
	logDir := filepath.Dir(logPath)
	files, err := filepath.Glob(filepath.Join(logDir, "clean.log.*"))
	if err != nil {
		logMsg(fmt.Sprintf("查找旧日志文件失败: %v", err), LogLevelDebug)
		return
	}
	
	for _, file := range files {
		if strings.HasSuffix(file, ".gz") {
			continue
		}
		
		if err := compressFile(file); err == nil {
			if err := os.Remove(file); err != nil {
				logMsg(fmt.Sprintf("删除原日志文件失败 %s: %v", file, err), LogLevelDebug)
			}
		} else {
			logMsg(fmt.Sprintf("压缩日志文件失败 %s: %v", file, err), LogLevelDebug)
		}
	}
}

func compressFile(src string) error {
	dest := src + ".gz"
	
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	gzWriter := gzip.NewWriter(destFile)
	defer gzWriter.Close()

	_, err = io.Copy(gzWriter, srcFile)
	return err
}

// ==================== 主循环和控制函数 ====================
func runMainLoop() {
	logMsg("进入主循环，等待信号...", LogLevelBasic)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	statusTicker := time.NewTicker(5 * time.Minute)
	resourceTicker := time.NewTicker(1 * time.Minute)
	defer statusTicker.Stop()
	defer resourceTicker.Stop()

	paused := false

	for {
		select {
		case <-sigChan:
			logMsg("收到终止信号", LogLevelBasic)
			gracefulShutdown()
			return
		case pause := <-pauseChan:
			if pause && !paused {
				logMsg("系统资源紧张，进入暂停模式", LogLevelBasic)
				paused = true
			} else if !pause && paused {
				logMsg("系统资源恢复，退出暂停模式", LogLevelBasic)
				paused = false
			}
		case <-statusTicker.C:
			if !paused {
				logMsg("程序运行中...", LogLevelDebug)
			} else {
				logMsg("程序暂停中...", LogLevelDebug)
			}
		case <-resourceTicker.C:
			if configManager.Get().ResourceAware {
				if err := detectSystemResources(); err == nil {
					newStatus := calculateSystemStatus()
					resourceMonitor.Lock()
					resourceMonitor.currentStatus = newStatus
					resourceMonitor.Unlock()
				}
			}
		case <-shutdownChan:
			return
		}
	}
}

func waitWithTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	
	select {
	case <-c:
		return true
	case <-time.After(timeout):
		return false
	}
}

func gracefulShutdown() {
	logMsg("开始优雅关闭", LogLevelBasic)
	
	// 第一步：停止接受新任务
	close(shutdownChan)
	
	// 第二步：等待进行中的操作完成
	var wg sync.WaitGroup
	wg.Add(3)
	
	go func() {
		defer wg.Done()
		// 等待资源监控器停止
		time.Sleep(2 * time.Second)
	}()
	
	// 第三步：按顺序关闭资源
	go func() {
		defer wg.Done()
		if logWriter != nil {
			logWriter.Flush()
		}
		if logFile != nil {
			logFile.Sync()
			logFile.Close()
		}
	}()
	
	go func() {
		defer wg.Done()
		resourceManager.CloseAll()
	}()
	
	// 第四步：等待所有关闭操作完成
	if waitWithTimeout(&wg, time.Duration(ShutdownTimeoutSec)*time.Second) {
		logMsg("资源清理完成", LogLevelBasic)
	} else {
		logMsg("资源清理超时，强制退出", LogLevelCritical)
	}
	
	// 保存最终健康状态
	saveHealthStatus()
	
	os.Exit(0)
}

func handlePanicAndCleanup() {
	if r := recover(); r != nil {
		logMsg(fmt.Sprintf("程序异常: %v", r), LogLevelCritical)
	}
	gracefulShutdown()
}

func emergencyShutdown(reason string) {
	logMsg("紧急关闭: "+reason, LogLevelCritical)
	os.Exit(1)
}

func exitWithError(msg string) {
	logMsg("程序错误退出: "+msg, LogLevelCritical)
	gracefulShutdown()
}

// ==================== 系统自适应配置调整 ====================
func adjustConfigForSystem() {
	currentConfig := configManager.Get()
	
	maxConcurrent, batchSize, useFastDelete := getSystemSpecificCleanParams()
	
	newConfig := currentConfig
	newConfig.MaxConcurrent = maxConcurrent
	newConfig.BatchSize = batchSize
	newConfig.UseFastDelete = useFastDelete
	
	configManager.Update(newConfig)
	
	logMsg(fmt.Sprintf("系统自适应配置: 并发数=%d, 批次大小=%d, 快速删除=%v", 
		maxConcurrent, batchSize, useFastDelete), LogLevelBasic)
}

// ==================== 主程序入口 ====================
func main() {
	defer handlePanicAndCleanup()

	logMsg("=== EZ-Clean 清理系统启动 ===", LogLevelBasic)
	logMsg(fmt.Sprintf("版本: 4.3 | 时间: %s", getSystemTime()), LogLevelBasic)
	logMsg("安全模式: 已启用", LogLevelBasic)

	if err := ensureEssentialDirs(); err != nil {
		emergencyShutdown("目录创建失败: " + err.Error())
	}

	logMsg("开始环境检测", LogLevelBasic)
	result := safeDetectEnvironment()
	result.LogAndHandle("环境检测", LogLevelBasic)
	if result.Error != nil {
		exitWithError("环境检测失败: " + result.Error.Error())
	}
	logMsg("✓ 环境检测完成", LogLevelBasic)

	logMsg("开始Root权限验证", LogLevelBasic)
	if systemInfo.RootMethod == "none" {
		exitWithError("Root权限验证失败，程序终止")
	}
	logMsg("✓ 已获得Root权限", LogLevelBasic)

	logMsg("开始加载配置", LogLevelDetailed)
	if err := loadConfig(); err != nil {
		logMsg(fmt.Sprintf("配置加载失败: %v", err), LogLevelCritical)
		exitWithError("配置加载失败")
	} else {
		logMsg("✓ 配置加载完成", LogLevelBasic)
	}

	// 根据系统类型调整配置
	if configManager.Get().SystemAdaptive {
		adjustConfigForSystem()
	}

	logMsg("开始系统检查", LogLevelDetailed)
	if !performSystemCheck() {
		logMsg("系统检查发现问题但继续运行", LogLevelCritical)
	} else {
		logMsg("✓ 系统检查通过", LogLevelBasic)
	}

	// 启动监控服务
	if configManager.Get().ResourceAware {
		go startResourceMonitor()
		logMsg("资源感知模式已启用", LogLevelBasic)
	} else {
		logMsg("资源感知模式已禁用", LogLevelBasic)
	}

	// 启动健康监控
	go startHealthMonitor()
	logMsg("健康监控已启动", LogLevelBasic)

	// 启动配置热重载
	if configManager.Get().ConfigHotReload {
		go startConfigHotReload()
		logMsg("配置热重载已启用", LogLevelBasic)
	}

	logMsg("启动基础服务", LogLevelBasic)
	startBasicServices()

	logMsg("执行初始清理", LogLevelBasic)
	performInitialCleaning()

	logMsg("进入主循环", LogLevelBasic)
	runMainLoop()
}