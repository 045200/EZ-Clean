// Package ezclean 提供Android设备的智能清理功能
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
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

// ==================== 配置结构 ====================
type AppConfig struct {
	IntervalMin        int    `json:"interval_min"`
	TimedClean         bool   `json:"timed_cleaning"`
	LogEnable          bool   `json:"log_enable"`
	CalcSizeEn         bool   `json:"calc_size_enable"`
	MtClean            bool   `json:"mt_cleaning"`
	MtPackages         string `json:"mt_packages"`
	MtAggressive       bool   `json:"mt_aggressive"`
	LogClean           bool   `json:"log_cleaning"`
	LogPurgeSize       string `json:"log_purge_size"`
	LogLevel           int    `json:"log_level"`
	LogBufferSize      int    `json:"log_buffer_size"`
	LogCompress        bool   `json:"log_compress"`
	MaxConcurrent      int    `json:"max_concurrent"`
	BatchSize          int    `json:"batch_size"`
	SafeMode           bool   `json:"safe_mode"`
	BackupEnabled      bool   `json:"backup_enabled"`
	MaxBackupSize      string `json:"max_backup_size"`
	UseFastDelete      bool   `json:"use_fast_delete"`
	CleanEmptyDirs     bool   `json:"clean_empty_dirs"`
	ExcludeSystem      bool   `json:"exclude_system"`
	ResourceAware      bool   `json:"resource_aware"`
	BatteryThreshold   int    `json:"battery_threshold"`
	MemoryThreshold    int    `json:"memory_threshold"`
	CPULoadThreshold   int    `json:"cpu_load_threshold"`
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
)

// ==================== 系统保护路径 ====================
var criticalSystemPaths = []string{
	"/system", "/vendor", "/proc", "/sys", "/dev", "/boot",
	"/data/adb", "/data/system", "/data/vendor", "/data/misc",
	"/data/app/", "/system/app/", "/product", "/odm", "/oem",
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
	// 设置数据目录为 /data/media/0/Android/EZ-Clean
	dataDir := "/storage/emulated/0/Android/EZ-Clean/"
	
	// 确保数据目录存在
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("创建数据目录失败 %s: %v", dataDir, err)
	}

	// 设置各文件路径（基于数据目录）
	configPath = filepath.Join(dataDir, "config.json")
	blackPath = filepath.Join(dataDir, "blacklist.conf")
	whitePath = filepath.Join(dataDir, "whitelist.conf")
	mtBlackPath = filepath.Join(dataDir, "MT.conf")
	logPath = filepath.Join(dataDir, "Clean.log")
	backupDir = filepath.Join(dataDir, "backup")

	// 确保备份目录存在
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("创建备份目录失败 %s: %v", backupDir, err)
	}

	logMsg(fmt.Sprintf("数据目录: %s", dataDir), LogLevelBasic)
	logMsg("所有配置和日志文件将存储在数据目录中", LogLevelBasic)

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

// ==================== 增强的环境检测 ====================
func detectEnvironment() error {
	// 检测Android版本
	if version, err := getAndroidVersion(); err == nil {
		systemInfo.AndroidVersion = version
		logMsg(fmt.Sprintf("Android版本: %d", version), LogLevelBasic)
	} else {
		logMsg(fmt.Sprintf("Android版本检测失败: %v", err), LogLevelCritical)
		systemInfo.AndroidVersion = 0
	}

	// 检测Root环境
	if rootMethod := detectRootMethod(); rootMethod != "none" {
		systemInfo.RootMethod = rootMethod
		logMsg(fmt.Sprintf("Root环境: %s", rootMethod), LogLevelBasic)
	} else {
		return fmt.Errorf("未检测到Root环境")
	}

	// 检测系统资源
	if err := detectSystemResources(); err != nil {
		logMsg(fmt.Sprintf("系统资源检测失败: %v", err), LogLevelCritical)
	} else {
		logMsg(fmt.Sprintf("系统资源: %dMB内存, %d核心CPU, %d%%电量", 
			systemInfo.TotalMemory/1024/1024, systemInfo.CPUCores, systemInfo.BatteryLevel), LogLevelBasic)
	}

	// 更新系统状态
	systemInfo.SystemStatus = calculateSystemStatus()

	return nil
}

func getAndroidVersion() (int, error) {
	// 方法1: 通过build.prop
	if output, err := exec.Command("getprop", "ro.build.version.sdk").Output(); err == nil {
		if version, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
			return version, nil
		}
	}
	
	return 0, fmt.Errorf("无法检测Android版本")
}

func detectRootMethod() string {
	// 检测KernelSU
	if checkKernelSU() {
		return "kernelsu"
	}

	// 检测Magisk
	if checkMagisk() {
		return "magisk"
	}

	return "none"
}

func checkKernelSU() bool {
	// 检查KernelSU特定文件
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
	// 检查Magisk特定文件
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
	
	// 检查Magisk守护进程
	if checkProcessRunning("magiskd") {
		return true
	}

	// 检查MagiskSU
	if checkSuBinary("magisk") {
		return true
	}
	
	return false
}

func detectSystemResources() error {
	// 检测内存信息
	if err := detectMemoryInfo(); err != nil {
		return fmt.Errorf("内存检测失败: %v", err)
	}

	// 检测CPU信息
	if err := detectCPUInfo(); err != nil {
		return fmt.Errorf("CPU检测失败: %v", err)
	}

	// 检测电池信息
	if err := detectBatteryInfo(); err != nil {
		return fmt.Errorf("电池检测失败: %v", err)
	}

	// 检测存储信息
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
	memoryUsage := float64(systemInfo.TotalMemory-systemInfo.AvailableMemory) / float64(systemInfo.TotalMemory) * 100

	batteryLow := systemInfo.BatteryLevel < globalConfig.BatteryThreshold
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
		return globalConfig.MaxConcurrent, globalConfig.BatchSize
	case StatusModerate:
		return max(1, globalConfig.MaxConcurrent/2), max(10, globalConfig.BatchSize/2)
	case StatusConservative:
		return 1, max(5, globalConfig.BatchSize/4)
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
					logMsg(fmt.Sprintf("系统状态变更: %s -> %s", 
						statusNames[oldStatus], statusNames[newStatus]), LogLevelBasic)
					
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

// ==================== JSON配置实现 ====================
func loadConfig() error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logMsg("配置文件不存在，创建默认配置", LogLevelBasic)
		return saveDefaultConfig()
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	if err := json.Unmarshal(content, &globalConfig); err != nil {
		return fmt.Errorf("解析JSON配置失败: %v", err)
	}

	if err := validateConfig(); err != nil {
		logMsg(fmt.Sprintf("配置验证失败，使用默认值: %v", err), LogLevelCritical)
		return saveDefaultConfig()
	}

	logMsg("配置文件加载成功", LogLevelDetailed)
	return nil
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
	}

	data, err := json.MarshalIndent(globalConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化默认配置失败: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("写入默认配置失败: %v", err)
	}

	logMsg("默认配置文件已创建", LogLevelBasic)
	return nil
}

func validateConfig() error {
	if globalConfig.IntervalMin < 1 {
		return fmt.Errorf("interval_min不能小于1")
	}
	if globalConfig.LogLevel < LogLevelCritical || globalConfig.LogLevel > LogLevelDebug {
		return fmt.Errorf("log_level必须在%d-%d之间", LogLevelCritical, LogLevelDebug)
	}
	if globalConfig.MaxConcurrent < 1 {
		return fmt.Errorf("max_concurrent不能小于1")
	}
	if globalConfig.BatchSize < 1 {
		return fmt.Errorf("batch_size不能小于1")
	}
	if globalConfig.LogBufferSize < 1 {
		return fmt.Errorf("log_buffer_size不能小于1")
	}
	if globalConfig.BatteryThreshold < 5 || globalConfig.BatteryThreshold > 95 {
		return fmt.Errorf("battery_threshold必须在5-95之间")
	}
	if globalConfig.MemoryThreshold < 100 {
		return fmt.Errorf("memory_threshold不能小于100MB")
	}
	if globalConfig.CPULoadThreshold < 10 || globalConfig.CPULoadThreshold > 95 {
		return fmt.Errorf("cpu_load_threshold必须在10-95之间")
	}

	return nil
}

// ==================== Root权限检查函数 ====================
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

func checkSuBinary(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "-c", "id")
	output, err := cmd.Output()
	
	if err != nil {
		return false
	}
	
	return strings.Contains(string(output), "uid=0")
}

func checkRootCharacteristics() bool {
	rootIndicators := []string{
		"/system/bin/su",
		"/system/xbin/su",
		"/sbin/su",
		"/data/local/bin/su",
		"/data/local/xbin/su",
		"/data/local/su",
		"/system/sd/xbin/su",
		"/system/bin/failsafe/su",
		"/data/local/su",
		"/su/bin/su",
	}
	
	for _, indicator := range rootIndicators {
		if _, err := os.Stat(indicator); err == nil {
			return true
		}
	}
	
	return false
}

// ==================== 进程检测函数 ====================
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

// ==================== 文件操作函数 ====================
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
	} else {
		return cleanFile(path)
	}
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

// ==================== 路径安全检查 ====================
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

// ==================== 工具函数 ====================
func ensureEssentialDirs() error {
	// 只确保数据目录和备份目录存在
	dirs := []string{
		"/data/media/0/Android/EZ-Clean", // 数据目录
		backupDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录 %s 失败: %v", dir, err)
		}
	}

	// 创建必要的配置文件（如果不存在）
	requiredFiles := []string{blackPath, whitePath, mtBlackPath}
	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			var defaultContent string
			switch filepath.Base(file) {
			case "blacklist.conf":
				defaultContent = `#黑名单配置
# 应用缓存
/data/data/*/cache/*
/data/data/*/code_cache/*
/data/media/0/Android/data/*/cache/*
/data/media/0/Android/data/*/code_cache/*`
			case "whitelist.conf":
				defaultContent = `#白名单配置
/data/media/0/Download/
/data/media/0/DCIM/
/data/media/0/Pictures/
/data/media/0/Documents/`
			case "MT.conf":
				defaultContent = `#MT管理器触发清理名单
/data/media/0/.*
/data/media/0/QQBrowser/
/data/media/0/com.*`
			}
			
			if err := os.WriteFile(file, []byte(defaultContent), 0644); err != nil {
				return fmt.Errorf("创建必要文件 %s 失败: %v", file, err)
			}
			logMsg(fmt.Sprintf("创建名单文件: %s", file), LogLevelDebug)
		}
	}

	return nil
}

func getSystemTime() string {
	if output, err := exec.Command("date", "+%Y-%m-%d %H:%M:%S").Output(); err == nil {
		return strings.TrimSpace(string(output))
	}
	return time.Now().Format("2006-01-02 15:04:05")
}

func logMsg(msg string, level int) {
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

	if _, err := logFile.WriteString(fullMsg); err != nil {
		return
	}

	if err := logFile.Sync(); err != nil {
		return
	}
	
	if globalConfig.LogCompress {
		go compressOldLogs()
	}
}

func compressOldLogs() {
	logDir := filepath.Dir(logPath)
	files, err := filepath.Glob(filepath.Join(logDir, "Clean.log.*"))
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

// ==================== 服务管理 ====================
func startBasicServices() {
	logMsg("启动基础监控服务", LogLevelDetailed)
	go startSimpleCleanService()

	if globalConfig.MtClean {
		go startMtService()
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
	if _, err := os.Stat(whitePath); err != nil {
		logMsg("白名单文件缺失", LogLevelCritical)
		return false
	}
	if _, err := os.Stat(blackPath); err != nil {
		logMsg("黑名单文件缺失", LogLevelCritical)
		return false
	}
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
	logMsg(fmt.Sprintf("数据目录: /data/media/0/Android/EZ-Clean"), LogLevelBasic)

	// 确保必要的目录和文件存在
	if err := ensureEssentialDirs(); err != nil {
		emergencyShutdown("目录创建失败: " + err.Error())
	}

	// 环境检测
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

	logMsg("开始系统检查", LogLevelDetailed)
	if !performSystemCheck() {
		logMsg("系统检查发现问题但继续运行", LogLevelCritical)
	} else {
		logMsg("✓ 系统检查通过", LogLevelBasic)
	}

	// 启动资源监控
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

// 工具函数
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}