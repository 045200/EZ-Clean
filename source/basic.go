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
	
	// 日志轮转配置
	LogRotationDays          = 3
	LogRotationCheckInterval = 1 * time.Hour
	MaxLogFileSize           = 10 * 1024 * 1024
)

// ==================== 类型定义 ====================
type CleanType int
type SystemStatus int

const (
	CleanTypeNormal CleanType = iota
	CleanTypeMT
)

const (
	StatusOptimal SystemStatus = iota
	StatusModerate
	StatusConservative
	StatusCritical
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
	LogRotationEnabled bool
	LogRetentionDays   int
	MaxLogSize         string
}

// ==================== 系统信息结构 ====================
type SystemInfo struct {
	AndroidVersion   int
	TotalMemory      int64
	AvailableMemory  int64
	CPUCores         int
	CPULoad          float64
	BatteryLevel     int
	IsCharging       bool
	RootMethod       string
	StorageAvailable int64
	SystemStatus     SystemStatus
}

// ==================== 全局变量 ====================
var (
	configPath  string
	blackPath   string
	whitePath   string
	mtBlackPath string
	logPath     string
	backupDir   string

	globalConfig AppConfig
	systemInfo   SystemInfo
	logFile      *os.File
	logWriter    *bufio.Writer
	logMutex     sync.Mutex

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

	lastRotationDate string
	rotationMutex    sync.Mutex
)

// ==================== 系统保护路径 ====================
var criticalSystemPaths = []string{
	"/system", "/vendor", "/proc", "/sys", "/dev", "/boot",
	"/data/adb", "/data/system", "/data/vendor", "/data/misc",
	"/data/app/", "/system/app/", "/product", "/odm", "/oem",
}

// ==================== 初始化函数 ====================
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
	baseDir := "/storage/emulated/0/Android/EZ-Clean/"
	
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return fmt.Errorf("创建主配置目录失败 %s: %v", baseDir, err)
	}

	configPath = filepath.Join(baseDir, "config.conf")
	blackPath = filepath.Join(baseDir, "blacklist.conf")
	whitePath = filepath.Join(baseDir, "whitelist.conf")
	mtBlackPath = filepath.Join(baseDir, "MT.conf")
	logPath = filepath.Join(baseDir, "Clean.log")
	backupDir = filepath.Join(baseDir, "backup")

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("创建备份目录失败 %s: %v", backupDir, err)
	}

	logMsg("主配置目录初始化完成", LogLevelBasic)
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

	testMsg := fmt.Sprintf("[%s] === 日志系统启动 ===\n", getSystemTime())
	if _, err := logFile.WriteString(testMsg); err != nil {
		return fmt.Errorf("日志文件写入测试失败: %v", err)
	}

	if err := logWriter.Flush(); err != nil {
		return fmt.Errorf("日志刷新失败: %v", err)
	}
	
	if err := logFile.Sync(); err != nil {
		return fmt.Errorf("日志同步失败: %v", err)
	}

	return nil
}

// ==================== 环境检测函数 ====================
func detectEnvironment() error {
	if version, err := getAndroidVersion(); err == nil {
		systemInfo.AndroidVersion = version
		logMsg(fmt.Sprintf("Android版本: %d", version), LogLevelBasic)
	} else {
		logMsg(fmt.Sprintf("Android版本检测失败: %v", err), LogLevelCritical)
		systemInfo.AndroidVersion = 0
	}

	if rootMethod := detectRootMethod(); rootMethod != "none" {
		systemInfo.RootMethod = rootMethod
		logMsg(fmt.Sprintf("Root环境: %s", rootMethod), LogLevelBasic)
	} else {
		return fmt.Errorf("未检测到Root环境")
	}

	if err := detectSystemResources(); err != nil {
		logMsg(fmt.Sprintf("系统资源检测失败: %v", err), LogLevelCritical)
	} else {
		logMsg(fmt.Sprintf("系统资源: %dMB内存, %d核心CPU, %d%%电量", 
			systemInfo.TotalMemory/1024/1024, systemInfo.CPUCores, systemInfo.BatteryLevel), LogLevelBasic)
	}

	systemInfo.SystemStatus = calculateSystemStatus()
	return nil
}

func getAndroidVersion() (int, error) {
	if output, err := exec.Command("getprop", "ro.build.version.sdk").Output(); err == nil {
		if version, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
			return version, nil
		}
	}
	return 0, fmt.Errorf("无法检测Android版本")
}

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
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func checkMagisk() bool {
	magiskPaths := []string{
		"/data/adb/magisk",
		"/system/bin/magisk",
		"/system/xbin/magisk",
		"/sbin/magisk",
	}
	
	for _, path := range magiskPaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	
	return checkSuBinary("/system/bin/su")
}

func checkSuBinary(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "-c", "id")
	output, err := cmd.Output()
	return err == nil && strings.Contains(string(output), "uid=0")
}

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
		systemInfo.IsCharging = strings.Contains(status, "Charging") || strings.Contains(status, "Full")
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
	memoryUsage := float64(systemInfo.TotalMemory-systemInfo.AvailableMemory) / float64(systemInfo.TotalMemory) * 100
	batteryLow := systemInfo.BatteryLevel < globalConfig.BatteryThreshold
	notCharging := !systemInfo.IsCharging

	if memoryUsage > 90 || systemInfo.CPULoad > 90 || (batteryLow && notCharging) {
		return StatusCritical
	} else if memoryUsage > 75 || systemInfo.CPULoad > 75 {
		return StatusConservative
	} else if memoryUsage > 50 || systemInfo.CPULoad > 50 {
		return StatusModerate
	}
	return StatusOptimal
}

func getAdjustedCleanParams() (maxConcurrent int, batchSize int) {
	resourceMonitor.RLock()
	status := resourceMonitor.currentStatus
	resourceMonitor.RUnlock()

	switch status {
	case StatusOptimal:
		return globalConfig.MaxConcurrent, globalConfig.BatchSize
	case StatusModerate:
		return maxInt(1, globalConfig.MaxConcurrent/2), maxInt(10, globalConfig.BatchSize/2)
	case StatusConservative:
		return 1, maxInt(5, globalConfig.BatchSize/4)
	case StatusCritical:
		return 0, 0
	default:
		return globalConfig.MaxConcurrent, globalConfig.BatchSize
	}
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
					logMsg(fmt.Sprintf("系统状态变更: %s -> %s", statusNames[oldStatus], statusNames[newStatus]), LogLevelBasic)
					
					if newStatus == StatusCritical && oldStatus != StatusCritical {
						pauseChan <- true
					} else if newStatus != StatusCritical && oldStatus == StatusCritical {
						pauseChan <- false
					}
				}
			}
		case <-shutdownChan:
			logMsg("资源监控器停止", LogLevelDetailed)
			return
		}
	}
}

func shouldPauseCleaning() bool {
	if !globalConfig.ResourceAware {
		return false
	}
	resourceMonitor.RLock()
	defer resourceMonitor.RUnlock()
	return resourceMonitor.currentStatus == StatusCritical
}

// ==================== 配置文件管理 ====================
func loadConfig() error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logMsg("配置文件不存在，创建默认配置", LogLevelBasic)
		return saveDefaultConfig()
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

	globalConfig = newConfig
	logMsg("配置文件加载成功", LogLevelDetailed)
	return nil
}

func parseConfigContent(content string) (AppConfig, error) {
	config := AppConfig{}
	lines := strings.Split(content, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
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
		case "log_rotation_enabled":
			config.LogRotationEnabled = strings.ToLower(value) == "true"
		case "log_retention_days":
			if v, err := strconv.Atoi(value); err == nil {
				config.LogRetentionDays = v
			}
		case "max_log_size":
			config.MaxLogSize = value
		}
	}
	return config, nil
}

func saveDefaultConfig() error {
	globalConfig = AppConfig{
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
		LogRotationEnabled: true,
		LogRetentionDays:   LogRotationDays,
		MaxLogSize:         "10M",
	}

	configContent := generateConfigContent(globalConfig)
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
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
	
	content.WriteString("\n# 日志轮转配置\n")
	content.WriteString(fmt.Sprintf("log_rotation_enabled = %t\n", config.LogRotationEnabled))
	content.WriteString(fmt.Sprintf("log_retention_days = %d\n", config.LogRetentionDays))
	content.WriteString(fmt.Sprintf("max_log_size = %s\n", config.MaxLogSize))
	
	return content.String()
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
	if config.LogRetentionDays < 1 {
		return fmt.Errorf("log_retention_days不能小于1")
	}
	return nil
}

// ==================== Root权限检查 ====================
func checkRootPermission() bool {
	if systemInfo.RootMethod != "none" {
		return true
	}

	suPaths := []string{
		"/system/bin/su", "/system/xbin/su", "/sbin/su", 
		"/vendor/bin/su", "su",
	}

	for _, path := range suPaths {
		if checkSuBinary(path) {
			logMsg("Root权限验证成功: "+path, LogLevelBasic)
			return true
		}
	}

	if checkRootCharacteristics() {
		logMsg("通过系统特征验证Root权限", LogLevelBasic)
		return true
	}

	logMsg("Root权限验证失败", LogLevelCritical)
	return false
}

func checkRootCharacteristics() bool {
	rootIndicators := []string{
		"/system/bin/su", "/system/xbin/su", "/sbin/su",
		"/data/local/bin/su", "/data/local/xbin/su", "/data/local/su",
		"/system/sd/xbin/su", "/system/bin/failsafe/su", "/su/bin/su",
	}
	
	for _, indicator := range rootIndicators {
		if _, err := os.Stat(indicator); err == nil {
			return true
		}
	}
	return false
}

// ==================== 进程检测 ====================
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

// ==================== 系统路径保护 ====================
func isCriticalSystemPath(path string) bool {
	if !globalConfig.ExcludeSystem {
		return false
	}

	cleanedPath := filepath.Clean(path)
	
	for _, criticalPath := range criticalSystemPaths {
		cleanCritical := filepath.Clean(criticalPath)
		if cleanedPath == cleanCritical || strings.HasPrefix(cleanedPath+"/", cleanCritical+"/") {
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

// ==================== 文件操作 ====================
func cleanPath(path string) (int64, bool) {
	if isCriticalSystemPath(path) {
		logMsg(fmt.Sprintf("拒绝清理关键系统路径: %s", path), LogLevelCritical)
		return 0, false
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			logMsg(fmt.Sprintf("路径不存在: %s", path), LogLevelDebug)
		} else if os.IsPermission(err) {
			logMsg(fmt.Sprintf("权限不足: %s", path), LogLevelDebug)
		} else {
			logMsg(fmt.Sprintf("访问路径失败 %s: %v", path, err), LogLevelDebug)
		}
		return 0, false
	}

	if fileInfo.IsDir() {
		return cleanDirectory(path)
	}
	return cleanFile(path)
}

func cleanDirectory(path string) (int64, bool) {
	if !isPathWritable(path) {
		logMsg(fmt.Sprintf("目录不可写: %s", path), LogLevelDebug)
		return 0, false
	}

	if globalConfig.UseFastDelete {
		if freed, success := fastDeleteDirectory(path); success {
			return freed, true
		}
	}
	return cleanDirectorySafe(path)
}

func cleanFile(path string) (int64, bool) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	if fileInfo.Size() > MaxFileSize {
		return 0, false
	}
	if err := os.Remove(path); err != nil {
		return 0, false
	}
	return fileInfo.Size(), true
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

	if globalConfig.CleanEmptyDirs && isDirectoryEmpty(path) {
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
	if err := os.RemoveAll(path); err != nil {
		return 0, false
	}
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

// ==================== 并发清理控制 ====================
func performConcurrentCleanup(targetList, whitelist []string) int {
	if shouldPauseCleaning() {
		logMsg("系统资源紧张，暂停清理操作", LogLevelBasic)
		return 0
	}

	maxConcurrent, batchSize := getAdjustedCleanParams()
	if maxConcurrent == 0 {
		logMsg("系统资源严重不足，跳过本次清理", LogLevelBasic)
		return 0
	}

	logMsg(fmt.Sprintf("资源感知清理: 并发数=%d, 批次大小=%d", maxConcurrent, batchSize), LogLevelDetailed)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrent)
	results := make(chan int, len(targetList))
	errors := make(chan error, len(targetList))
	
	for i := 0; i < len(targetList); i += batchSize {
		end := i + batchSize
		if end > len(targetList) {
			end = len(targetList)
		}
		
		batch := targetList[i:end]
		
		for _, path := range batch {
			if isCriticalSystemPath(path) {
				logMsg(fmt.Sprintf("跳过关键系统路径: %s", path), LogLevelDebug)
				continue
			}

			if whitelist != nil && isInWhitelist(path, whitelist) {
				logMsg(fmt.Sprintf("白名单过滤: %s", path), LogLevelDebug)
				continue
			}

			wg.Add(1)
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

// ==================== MT管理器检测 ====================
func isMtRunning() bool {
	processes := []string{"bin.mt.plus", "mtmanager", "mt管理器", "com.mt", "bin.mt.plus9"}
	
	for _, proc := range processes {
		if checkProcessRunning(proc) {
			logMsg(fmt.Sprintf("检测到MT管理器进程: %s", proc), LogLevelDetailed)
			return true
		}
	}
	
	packages := strings.Split(globalConfig.MtPackages, ",")
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

// ==================== 名单文件处理 ====================
func loadBlackWhiteLists() (blacklist, whitelist []string, err error) {
	blacklist, err = loadListFile(blackPath, "黑名单")
	if err != nil {
		return nil, nil, err
	}
	whitelist, err = loadListFile(whitePath, "白名单")
	if err != nil {
		return nil, nil, err
	}
	return blacklist, whitelist, nil
}

func loadMTList() ([]string, error) {
	return loadListFile(mtBlackPath, "MT清理名单")
}

func loadListFile(filePath, name string) ([]string, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("%s文件不存在: %s", name, filePath)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取%s文件失败: %v", name, err)
	}

	lines := strings.Split(string(content), "\n")
	var paths []string
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		paths = append(paths, trimmed)
	}
	
	logMsg(fmt.Sprintf("从 %s 加载了 %d 条路径", name, len(paths)), LogLevelDetailed)
	return paths, nil
}

func isInWhitelist(path string, whitelist []string) bool {
	for _, whitePath := range whitelist {
		if path == whitePath {
			return true
		}
		if strings.HasSuffix(whitePath, "/") && strings.HasPrefix(path, whitePath) {
			return true
		}
		if strings.Contains(whitePath, "*") || strings.Contains(whitePath, "?") {
			if matched, _ := filepath.Match(whitePath, path); matched {
				return true
			}
		}
	}
	return false
}

// ==================== 日志系统 ====================
func logMsg(msg string, level int) {
	logMutex.Lock()
	defer logMutex.Unlock()
	
	logEnabled := true
	currentLevel := LogLevelDebug
	
	if globalConfig.LogLevel >= 0 {
		logEnabled = globalConfig.LogEnable
		currentLevel = globalConfig.LogLevel
	}

	if !logEnabled || level > currentLevel {
		return
	}

	timestamp := getSystemTime()
	
	levelNames := []string{"CRITICAL", "BASIC", "DETAILED", "DEBUG"}
	levelName := "UNKNOWN"
	if level >= 0 && level < len(levelNames) {
		levelName = levelNames[level]
	}
	
	fullMsg := fmt.Sprintf("[%s] [%s] %s\n", timestamp, levelName, msg)

	if logFile != nil {
		if _, err := logFile.WriteString(fullMsg); err != nil {
			fmt.Fprintf(os.Stderr, "写入日志失败: %v\n", err)
			return
		}

		if err := logFile.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "同步日志失败: %v\n", err)
			return
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s", fullMsg)
	}
	
	if globalConfig.LogRotationEnabled {
		checkLogRotation()
	}
}

// ==================== 日志轮转功能 ====================
func startLogRotationMonitor() {
	if !globalConfig.LogRotationEnabled {
		logMsg("日志轮转功能已禁用", LogLevelBasic)
		return
	}

	rotationMutex.Lock()
	lastRotationDate = time.Now().Format("20060102")
	rotationMutex.Unlock()

	logMsg("启动日志轮转监控器", LogLevelDetailed)
	ticker := time.NewTicker(LogRotationCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			performDailyRotation()
		case <-shutdownChan:
			logMsg("日志轮转监控器停止", LogLevelDetailed)
			return
		}
	}
}

func checkLogRotation() {
	info, err := os.Stat(logPath)
	if err != nil {
		return
	}

	maxSize, err := parseSizeString(globalConfig.MaxLogSize)
	if err != nil {
		maxSize = MaxLogFileSize
	}

	if info.Size() > maxSize {
		logMsg(fmt.Sprintf("日志文件大小 %.2fMB 超过限制 %.2fMB，执行轮转", 
			float64(info.Size())/1024/1024, float64(maxSize)/1024/1024), LogLevelBasic)
		performSizeBasedRotation()
	}
}

func performDailyRotation() {
	currentDate := time.Now().Format("20060102")
	
	rotationMutex.Lock()
	defer rotationMutex.Unlock()
	
	if lastRotationDate == currentDate {
		return
	}

	logMsg("检测到日期变更，执行每日日志轮转", LogLevelBasic)
	
	if logFile != nil {
		logWriter.Flush()
		logFile.Sync()
		logFile.Close()
		logFile = nil
		logWriter = nil
	}

	backupLogPath := logPath + "." + lastRotationDate

	if info, err := os.Stat(logPath); err == nil && info.Size() > 0 {
		if err := os.Rename(logPath, backupLogPath); err != nil {
			logMsg(fmt.Sprintf("重命名日志文件失败: %v", err), LogLevelCritical)
		} else {
			logMsg(fmt.Sprintf("日志已轮转至: %s", backupLogPath), LogLevelBasic)
			go compressLogFile(backupLogPath)
		}
	}

	lastRotationDate = currentDate

	if err := initLogSystem(); err != nil {
		logMsg(fmt.Sprintf("重新初始化日志系统失败: %v", err), LogLevelCritical)
	} else {
		logMsg("日志系统重新初始化成功", LogLevelBasic)
	}

	cleanupOldLogs()
}

func performSizeBasedRotation() {
	logMutex.Lock()
	defer logMutex.Unlock()

	logMsg("开始执行基于大小的日志轮转", LogLevelDetailed)

	if logFile != nil {
		logWriter.Flush()
		logFile.Sync()
		logFile.Close()
		logFile = nil
		logWriter = nil
	}

	timestamp := time.Now().Format("20060102_150405")
	backupLogPath := logPath + "." + timestamp

	if err := os.Rename(logPath, backupLogPath); err != nil {
		logMsg(fmt.Sprintf("重命名日志文件失败: %v", err), LogLevelCritical)
		if initLogErr := initLogSystem(); initLogErr != nil {
			logMsg(fmt.Sprintf("重新初始化日志系统失败: %v", initLogErr), LogLevelCritical)
		}
		return
	}

	logMsg(fmt.Sprintf("日志已轮转至: %s", backupLogPath), LogLevelBasic)
	go compressLogFile(backupLogPath)

	if err := initLogSystem(); err != nil {
		logMsg(fmt.Sprintf("重新初始化日志系统失败: %v", err), LogLevelCritical)
	} else {
		logMsg("日志系统重新初始化成功", LogLevelBasic)
	}

	cleanupOldLogs()
}

func compressLogFile(filePath string) {
	if strings.HasSuffix(filePath, ".gz") {
		return
	}
	
	if err := compressFile(filePath); err == nil {
		if err := os.Remove(filePath); err != nil {
			logMsg(fmt.Sprintf("删除原日志文件失败 %s: %v", filePath, err), LogLevelDebug)
		} else {
			logMsg(fmt.Sprintf("压缩日志文件: %s.gz", filepath.Base(filePath)), LogLevelDetailed)
		}
	} else {
		logMsg(fmt.Sprintf("压缩日志文件失败 %s: %v", filePath, err), LogLevelDebug)
	}
}

func cleanupOldLogs() {
	retentionDays := globalConfig.LogRetentionDays
	if retentionDays <= 0 {
		retentionDays = LogRotationDays
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	logDir := filepath.Dir(logPath)

	files, err := os.ReadDir(logDir)
	if err != nil {
		logMsg(fmt.Sprintf("读取日志目录失败: %v", err), LogLevelDebug)
		return
	}

	deletedCount := 0
	for _, file := range files {
		filename := file.Name()
		if strings.HasPrefix(filename, "Clean.log.") {
			filePath := filepath.Join(logDir, filename)
			info, err := file.Info()
			if err != nil {
				continue
			}

			if info.ModTime().Before(cutoffTime) {
				if err := os.Remove(filePath); err == nil {
					deletedCount++
					logMsg(fmt.Sprintf("删除旧日志文件: %s", filename), LogLevelDetailed)
				} else {
					logMsg(fmt.Sprintf("删除旧日志文件失败 %s: %v", filename, err), LogLevelDebug)
				}
			}
		}
	}

	if deletedCount > 0 {
		logMsg(fmt.Sprintf("日志清理完成，删除了 %d 个旧日志文件", deletedCount), LogLevelBasic)
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

// ==================== 服务管理 ====================
func startBasicServices() {
	logMsg("启动基础监控服务", LogLevelDetailed)
	go startSimpleCleanService()

	if globalConfig.MtClean {
		go startMtService()
	}
	
	if globalConfig.LogRotationEnabled {
		go startLogRotationMonitor()
	}
	
	logMsg("基础服务启动完成", LogLevelDetailed)
}

func startSimpleCleanService() {
	logMsg("定时清理服务启动（常规清理）", LogLevelDetailed)
	interval := time.Duration(globalConfig.IntervalMin) * time.Minute
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

	typeName := "常规"
	if cleanType == CleanTypeMT {
		typeName = "MT触发"
	}
	
	logMsg(fmt.Sprintf("%s清理完成 [路径:%d 文件:%d 大小:%.2fMB 耗时:%v]", 
		typeName, totalStats.pathsProcessed, totalStats.filesDeleted, 
		float64(totalStats.bytesFreed)/1024/1024, duration.Round(time.Millisecond)), LogLevelBasic)
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

// ==================== 工具函数 ====================
func getSystemTime() string {
	if output, err := exec.Command("date", "+%Y-%m-%d %H:%M:%S").Output(); err == nil {
		return strings.TrimSpace(string(output))
	}
	return time.Now().Format("2006-01-02 15:04:05")
}

func ensureEssentialDirs() error {
	dirs := []string{
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

func parseSizeString(sizeStr string) (int64, error) {
	if len(sizeStr) == 0 {
		return 0, fmt.Errorf("空字符串")
	}

	multiplier := int64(1)
	upperStr := strings.ToUpper(sizeStr)

	if strings.HasSuffix(upperStr, "K") {
		multiplier = 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	} else if strings.HasSuffix(upperStr, "M") {
		multiplier = 1024 * 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	} else if strings.HasSuffix(upperStr, "G") {
		multiplier = 1024 * 1024 * 1024
		sizeStr = sizeStr[:len(sizeStr)-1]
	}

	value, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return 0, err
	}

	return value * multiplier, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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

func checkRequiredListFiles() error {
	requiredFiles := []struct {
		path string
		name string
	}{
		{blackPath, "黑名单"},
		{whitePath, "白名单"}, 
		{mtBlackPath, "MT清理名单"},
	}

	for _, file := range requiredFiles {
		if _, err := os.Stat(file.path); os.IsNotExist(err) {
			return fmt.Errorf("%s文件不存在: %s", file.name, file.path)
		}
		
		if info, err := os.Stat(file.path); err == nil {
			if info.Size() == 0 {
				logMsg(fmt.Sprintf("警告: %s文件为空", file.name), LogLevelCritical)
			}
		}
	}
	return nil
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
			if globalConfig.ResourceAware {
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

func handlePanicAndCleanup() {
	if r := recover(); r != nil {
		logMsg(fmt.Sprintf("程序异常: %v", r), LogLevelCritical)
		emergencyLogFlush()
	}
	gracefulShutdown()
}

func gracefulShutdown() {
	logMsg("开始优雅关闭", LogLevelBasic)
	close(shutdownChan)
	time.Sleep(1 * time.Second)
	
	if logWriter != nil {
		logWriter.Flush()
	}
	if logFile != nil {
		logFile.Sync()
		logFile.Close()
	}
	
	logMsg("程序正常退出", LogLevelBasic)
	os.Exit(0)
}

func emergencyShutdown(reason string) {
	logMsg("紧急关闭: "+reason, LogLevelCritical)
	emergencyLogFlush()
	os.Exit(1)
}

func emergencyLogFlush() {
	if logFile != nil {
		logFile.Sync()
	}
}

func exitWithError(msg string) {
	logMsg("程序错误退出: "+msg, LogLevelCritical)
	gracefulShutdown()
}

// ==================== 主程序入口 ====================
func main() {
	defer handlePanicAndCleanup()

	logMsg("=== EZ-Clean 清理系统启动 ===", LogLevelBasic)
	logMsg(fmt.Sprintf("版本: 4.0 | 时间: %s", getSystemTime()), LogLevelBasic)
	logMsg(fmt.Sprintf("主配置目录: /storage/emulated/0/Android/EZ-Clean"), LogLevelBasic)

	if err := ensureEssentialDirs(); err != nil {
		emergencyShutdown("目录创建失败: " + err.Error())
	}

	logMsg("开始环境检测", LogLevelBasic)
	if err := detectEnvironment(); err != nil {
		exitWithError("环境检测失败: " + err.Error())
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

	logMsg("检查名单文件", LogLevelDetailed)
	if err := checkRequiredListFiles(); err != nil {
		exitWithError("名单文件检查失败: " + err.Error())
	}
	logMsg("✓ 名单文件检查完成", LogLevelBasic)

	logMsg("开始系统检查", LogLevelDetailed)
	if !performSystemCheck() {
		logMsg("系统检查发现问题但继续运行", LogLevelCritical)
	} else {
		logMsg("✓ 系统检查通过", LogLevelBasic)
	}

	if globalConfig.ResourceAware {
		go startResourceMonitor()
		logMsg("资源感知模式已启用", LogLevelBasic)
	} else {
		logMsg("资源感知模式已禁用", LogLevelBasic)
	}

	logMsg("启动基础服务", LogLevelBasic)
	startBasicServices()

	logMsg("执行初始清理", LogLevelBasic)
	performInitialCleaning()

	logMsg("进入主循环", LogLevelBasic)
	runMainLoop()
}