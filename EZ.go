package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 配置结构
type Config struct {
	ScheduleType  string
	ScheduleTime  string
	CleanEnabled  bool
	GCEnabled     bool
	LogMaxSize    string
	LogMaxAge     int
	LogLevel      int
	ConfigDir     string
	BlacklistFile string
	WhitelistFile string
	StatusFile    string
	LogFile       string
}

// 清理统计
type CleanStats struct {
	FilesCleaned int
	BytesFreed   int64
	StartTime    time.Time
	EndTime      time.Time
}

// 全局变量
var (
	config       *Config
	logger       *log.Logger
	logFile      *os.File
	systemTZ     *time.Location // 新增：系统时区
)

// 获取Android系统时区（只使用方法1和方法2）
func getSystemTimezone() *time.Location {
	// 方法1: 读取系统属性
	cmd := exec.Command("getprop", "persist.sys.timezone")
	output, err := cmd.Output()
	if err == nil {
		timezone := strings.TrimSpace(string(output))
		if timezone != "" {
			loc, err := time.LoadLocation(timezone)
			if err == nil {
				return loc
			}
		}
	}
	
	// 方法2: 读取TZ环境变量
	if tz := os.Getenv("TZ"); tz != "" {
		loc, err := time.LoadLocation(tz)
		if err == nil {
			return loc
		}
	}
	
	return time.Local
}

// 获取当前时间（使用系统时区）
func now() time.Time {
	if systemTZ != nil {
		return time.Now().In(systemTZ)
	}
	return time.Now()
}

// 格式化时间间隔为易读格式（精确到两位秒数）
func formatDuration(d time.Duration) string {
	totalSeconds := int(d.Seconds())
	
	days := totalSeconds / (24 * 3600)
	hours := (totalSeconds % (24 * 3600)) / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60
	
	var parts []string
	
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d天", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d小时", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%d分钟", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d秒", seconds))
	}
	
	return strings.Join(parts, "")
}

// 初始化日志
func initLogger() error {
	// 创建日志目录
	if err := os.MkdirAll(filepath.Dir(config.LogFile), 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %v", err)
	}

	// 打开日志文件
	file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %v", err)
	}

	logFile = file
	logger = log.New(file, "", 0)
	
	// 直接记录日志，使用系统时区
	timestamp := now().Format("2006-01-02 15:04:05 MST")
	message := fmt.Sprintf("%s [INFO] 日志系统初始化完成", timestamp)
	logger.Println(message)
	if config.LogLevel == 2 {
		fmt.Println(message)
	}
	
	return nil
}

// 日志函数
func logInfo(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	timestamp := now().Format("2006-01-02 15:04:05 MST")
	fullMessage := fmt.Sprintf("%s [INFO] %s", timestamp, message)
	
	if logger != nil {
		logger.Println(fullMessage)
	}
	
	// 开发环境输出到控制台
	if config.LogLevel == 2 {
		fmt.Println(fullMessage)
	}
}

func logWarn(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	timestamp := now().Format("2006-01-02 15:04:05 MST")
	fullMessage := fmt.Sprintf("%s [WARN] %s", timestamp, message)
	
	if logger != nil {
		logger.Println(fullMessage)
	}
	fmt.Println(fullMessage)
}

func logError(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	timestamp := now().Format("2006-01-02 15:04:05 MST")
	fullMessage := fmt.Sprintf("%s [ERROR] %s", timestamp, message)
	
	if logger != nil {
		logger.Println(fullMessage)
	}
	fmt.Println(fullMessage)
}

// 加载配置
func loadConfig(configPath string) (*Config, error) {
	configDir := filepath.Dir(configPath)
	cfg := &Config{
		ConfigDir:     configDir,
		BlacklistFile: filepath.Join(configDir, "blacklist.conf"),
		WhitelistFile: filepath.Join(configDir, "whitelist.conf"),
		StatusFile:    filepath.Join(configDir, "Clean.status"),
		LogFile:       filepath.Join(configDir, "Clean.log"),
		CleanEnabled:  true,
		GCEnabled:     true,
		LogLevel:      1,
	}

	file, err := os.Open(configPath)
	if err != nil {
		return cfg, nil // 使用默认配置
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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
		case "schedule_type":
			cfg.ScheduleType = value
		case "schedule_time":
			cfg.ScheduleTime = value
		case "clean_enabled":
			cfg.CleanEnabled = strings.ToLower(value) == "true"
		case "gc_enabled":
			cfg.GCEnabled = strings.ToLower(value) == "true"
		case "log_max_size":
			cfg.LogMaxSize = value
		case "log_max_age":
			if age, err := strconv.Atoi(value); err == nil {
				cfg.LogMaxAge = age
			}
		case "log_level":
			if level, err := strconv.Atoi(value); err == nil {
				cfg.LogLevel = level
			}
		}
	}

	return cfg, nil
}

// 检查环境条件 - 只用于GC操作
func checkEnvironment() bool {
	// 检查电池电量
	batteryLevel := getBatteryLevel()
	if batteryLevel <= 20 {
		logWarn("电量不足: %d%%，暂停GC操作", batteryLevel)
		return false
	}

	// 检查CPU使用率
	cpuUsage := getCPUUsage()
	if cpuUsage > 80.0 {
		logWarn("CPU使用率过高: %.2f%%，暂停GC操作", cpuUsage)
		return false
	}

	return true
}

// 获取电池电量
func getBatteryLevel() int {
	// 尝试多个可能的电池容量文件路径
	possiblePaths := []string{
		"/sys/class/power_supply/battery/capacity",
		"/sys/class/power_supply/BAT0/capacity",
		"/sys/class/power_supply/BAT1/capacity",
	}

	for _, batteryFile := range possiblePaths {
		content, err := os.ReadFile(batteryFile)
		if err != nil {
			continue // 尝试下一个路径
		}

		level, err := strconv.Atoi(strings.TrimSpace(string(content)))
		if err == nil && level >= 0 && level <= 100 {
			return level
		}
	}

	logWarn("无法读取电池电量，使用默认值100%")
	return 100 // 默认返回100%
}

// 获取CPU使用率
func getCPUUsage() float64 {
	// 读取/proc/stat获取CPU信息
	file, err := os.Open("/proc/stat")
	if err != nil {
		logWarn("无法读取CPU信息: %v", err)
		return 0.0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) >= 8 {
				// 解析CPU时间
				var times []int64
				for i := 1; i < 8; i++ {
					val, err := strconv.ParseInt(fields[i], 10, 64)
					if err != nil {
						return 0.0
					}
					times = append(times, val)
				}

				// 计算总时间和空闲时间
				total := times[0] + times[1] + times[2] + times[3] + times[4] + times[5] + times[6]
				idle := times[3]

				// 简单返回非空闲时间的比例（简化实现）
				if total > 0 {
					return float64(total-idle) / float64(total) * 100
				}
			}
		}
	}

	return 0.0
}

// 读取黑名单
func readBlacklist() ([]string, error) {
	var blacklist []string

	file, err := os.Open(config.BlacklistFile)
	if err != nil {
		// 如果文件不存在，创建默认黑名单文件
		if os.IsNotExist(err) {
			defaultBlacklist := []string{
				"/storage/emulated/0/Download/*.tmp",
				"/storage/emulated/0/Android/data/*/cache/*",
				"/storage/emulated/0/.thumbnails/*",
			}
			content := strings.Join(defaultBlacklist, "\n")
			if err := os.WriteFile(config.BlacklistFile, []byte(content), 0644); err != nil {
				return nil, fmt.Errorf("创建默认黑名单文件失败: %v", err)
			}
			return defaultBlacklist, nil
		}
		return nil, fmt.Errorf("打开黑名单文件失败: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		blacklist = append(blacklist, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取黑名单文件失败: %v", err)
	}

	logInfo("加载黑名单规则: %d 条", len(blacklist))
	return blacklist, nil
}

// 读取白名单
func readWhitelist() ([]string, error) {
	var whitelist []string

	file, err := os.Open(config.WhitelistFile)
	if err != nil {
		// 如果文件不存在，创建默认白名单文件
		if os.IsNotExist(err) {
			defaultWhitelist := []string{
				"/storage/emulated/0/DCIM/*",
				"/storage/emulated/0/Pictures/*",
				"/storage/emulated/0/Documents/*",
			}
			content := strings.Join(defaultWhitelist, "\n")
			if err := os.WriteFile(config.WhitelistFile, []byte(content), 0644); err != nil {
				return nil, fmt.Errorf("创建默认白名单文件失败: %v", err)
			}
			return defaultWhitelist, nil
		}
		return nil, fmt.Errorf("打开白名单文件失败: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		whitelist = append(whitelist, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取白名单文件失败: %v", err)
	}

	logInfo("加载白名单规则: %d 条", len(whitelist))
	return whitelist, nil
}

// 检查是否在白名单中
func isWhitelisted(path string, whitelist []string) bool {
	for _, whitePattern := range whitelist {
		// 直接前缀匹配
		patternBase := strings.TrimSuffix(whitePattern, "*")
		if strings.HasPrefix(path, patternBase) {
			return true
		}
		
		// 简单的通配符匹配
		if matched, _ := filepath.Match(whitePattern, path); matched {
			return true
		}
		
		// 目录匹配
		if strings.HasSuffix(whitePattern, "/") && strings.HasPrefix(path, whitePattern) {
			return true
		}
	}
	return false
}

// 安全检查 - 放宽限制，允许删除黑名单中的用户数据
func isSafeToDelete(path string) bool {
	// 检查系统关键路径 - 这些绝对不能删除
	protectedPaths := []string{
		"/system", "/vendor", "/product", 
		"/data/system", "/data/user",
		"/proc", "/sys", "/dev", "/acct", "/mnt",
	}

	for _, protected := range protectedPaths {
		if strings.HasPrefix(path, protected) {
			logWarn("拒绝删除系统关键路径: %s", path)
			return false
		}
	}

	// 移除危险文件扩展名检查，黑名单内的所有路径均可删除
	logInfo("允许删除黑名单路径: %s", path)
	return true
}

// 安全删除文件
func safeRemove(path string, stats *CleanStats) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	if !isSafeToDelete(path) {
		return fmt.Errorf("安全检查失败: %s", path)
	}

	if info.IsDir() {
		return removeDir(path, stats)
	} else {
		return removeFile(path, stats)
	}
}

// 删除文件
func removeFile(path string, stats *CleanStats) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		return err
	}

	stats.FilesCleaned++
	stats.BytesFreed += info.Size()
	logInfo("删除文件: %s (%.2f MB)", path, float64(info.Size())/1024/1024)

	return nil
}

// 删除目录
func removeDir(path string, stats *CleanStats) error {
	// 先删除目录内容
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		fullPath := filepath.Join(path, entry.Name())
		if err := safeRemove(fullPath, stats); err != nil {
			logWarn("删除子项失败 %s: %v", fullPath, err)
		}
	}
	
	// 然后删除空目录
	if err := os.Remove(path); err != nil {
		return err
	}
	
	logInfo("删除目录: %s", path)
	return nil
}

// 执行清理
func runClean() (*CleanStats, error) {
	stats := &CleanStats{
		StartTime: now(),
	}

	logInfo("开始清理过程...")

	// 读取名单
	blacklist, err := readBlacklist()
	if err != nil {
		return nil, err
	}

	whitelist, err := readWhitelist()
	if err != nil {
		return nil, err
	}

	// 清理每个模式
	for _, pattern := range blacklist {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			logWarn("模式匹配失败 %s: %v", pattern, err)
			continue
		}

		for _, path := range matches {
			if isWhitelisted(path, whitelist) {
				logInfo("跳过白名单文件: %s", path)
				continue
			}

			if err := safeRemove(path, stats); err != nil {
				logWarn("删除文件失败 %s: %v", path, err)
			}
		}
	}

	stats.EndTime = now()
	saveStats(stats)

	return stats, nil
}

// 保存统计信息
func saveStats(stats *CleanStats) {
	content := fmt.Sprintf(
		"最后清理时间: %s\n清理文件数: %d\n释放空间: %.2f MB\n耗时: %v\n",
		stats.EndTime.Format("2006-01-02 15:04:05"),
		stats.FilesCleaned,
		float64(stats.BytesFreed)/1024/1024,
		stats.EndTime.Sub(stats.StartTime),
	)

	if err := os.WriteFile(config.StatusFile, []byte(content), 0644); err != nil {
		logWarn("保存统计信息失败: %v", err)
	}
}

// 执行GC
func runGC() error {
	if !checkEnvironment() {
		return fmt.Errorf("环境条件不满足")
	}

	// 查找数据设备
	dataDevice := getDataDevice()
	if dataDevice == "" {
		logWarn("无法找到数据设备，跳过GC")
		return nil
	}

	// 查找sysfs路径
	sysfsPath := findSysfsPath(dataDevice)
	if sysfsPath == "" {
		logWarn("未找到sysfs路径，跳过GC")
		return nil
	}

	// 配置GC参数
	writeSysfs(filepath.Join(sysfsPath, "gc_min_sleep_time"), "100")
	writeSysfs(filepath.Join(sysfsPath, "gc_max_sleep_time"), "600")

	// 获取初始脏段
	initialDirty := readSysfsInt(filepath.Join(sysfsPath, "dirty_segments"))
	if initialDirty < 256 {
		logInfo("脏段数量低于阈值: %d", initialDirty)
		writeSysfs(filepath.Join(sysfsPath, "gc_urgent"), "0")
		return nil
	}

	logInfo("开始GC，初始脏段: %d", initialDirty)
	writeSysfs(filepath.Join(sysfsPath, "gc_urgent"), "1")

	// 监控GC进度
	timeout := time.After(10 * time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !checkEnvironment() {
				writeSysfs(filepath.Join(sysfsPath, "gc_urgent"), "0")
				logWarn("环境条件变化，暂停GC")
				
				// 等待环境改善
				if !waitForBetterEnvironment() {
					return fmt.Errorf("环境条件持续不佳")
				}
				
				writeSysfs(filepath.Join(sysfsPath, "gc_urgent"), "1")
				continue
			}

			currentDirty := readSysfsInt(filepath.Join(sysfsPath, "dirty_segments"))
			if currentDirty < 200 {
				writeSysfs(filepath.Join(sysfsPath, "gc_urgent"), "0")
				logInfo("GC完成，回收脏段: %d", initialDirty-currentDirty)
				return nil
			}

		case <-timeout:
			writeSysfs(filepath.Join(sysfsPath, "gc_urgent"), "0")
			logWarn("GC超时，已停止")
			return nil
		}
	}
}

// 等待环境改善
func waitForBetterEnvironment() bool {
	timeout := time.After(5 * time.Minute)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if checkEnvironment() {
				logInfo("环境条件已改善")
				return true
			}
		case <-timeout:
			logWarn("等待环境改善超时")
			return false
		}
	}
}

// 获取数据设备
func getDataDevice() string {
	// 尝试常见设备名称
	possibleDevices := []string{"sda", "sdb", "mmcblk0", "mmcblk1"}
	
	for _, device := range possibleDevices {
		f2fsPath := filepath.Join("/sys/fs/f2fs", device)
		mifsPath := filepath.Join("/sys/fs/mifs", device)
		
		if _, err := os.Stat(f2fsPath); err == nil {
			return device
		}
		if _, err := os.Stat(mifsPath); err == nil {
			return device
		}
	}
	
	// 尝试通过mount信息查找
	content, err := os.ReadFile("/proc/mounts")
	if err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.Contains(line, "/data ") {
				fields := strings.Fields(line)
				if len(fields) >= 1 {
					device := filepath.Base(fields[0])
					logInfo("通过mount信息找到数据设备: %s", device)
					return device
				}
			}
		}
	}
	
	logWarn("无法找到数据设备")
	return ""
}

// 查找sysfs路径
func findSysfsPath(device string) string {
	paths := []string{
		filepath.Join("/sys/fs/f2fs", device),
		filepath.Join("/sys/fs/mifs", device),
	}
	
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	
	return ""
}

// 读取sysfs整数
func readSysfsInt(path string) int {
	content, err := os.ReadFile(path)
	if err != nil {
		logWarn("读取sysfs文件失败 %s: %v", path, err)
		return 0
	}
	
	value, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		logWarn("解析sysfs值失败 %s: %v", path, err)
		return 0
	}
	
	return value
}

// 写入sysfs
func writeSysfs(path, value string) {
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		logWarn("写入sysfs文件失败 %s: %v", path, err)
	}
}

// 执行磁盘整理
func runTrim() {
	logInfo("开始磁盘整理...")
	
	// 检查fstrim是否可用
	if _, err := exec.LookPath("fstrim"); err != nil {
		logInfo("fstrim命令不可用，跳过磁盘整理")
		return
	}
	
	cmd := exec.Command("fstrim", "-v", "/data")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logWarn("磁盘整理失败: %v", err)
		return
	}
	
	// 解析输出
	outputStr := string(output)
	if strings.Contains(outputStr, "bytes") {
		logInfo("磁盘整理完成: %s", strings.TrimSpace(outputStr))
	} else {
		logInfo("磁盘整理完成")
	}
}

// 启动调度器
func startScheduler() {
	logInfo("启动调度器，模式: %s, 时区: %s", config.ScheduleType, systemTZ)
	
	for {
		var sleepDuration time.Duration
		
		switch config.ScheduleType {
		case "daily":
			sleepDuration = calculateDailySleep(systemTZ)
		case "interval":
			sleepDuration = calculateIntervalSleep()
		default:
			sleepDuration = 6 * time.Hour // 默认6小时
		}
		
		// 使用格式化函数显示友好的时间间隔
		logInfo("下次执行: %s后", formatDuration(sleepDuration))
		time.Sleep(sleepDuration)
		
		// 执行清理任务
		executeCleanTask()
	}
}

// 计算每日调度睡眠时间（使用时区）
func calculateDailySleep(timezone *time.Location) time.Duration {
	now := now().In(timezone)
	
	// 解析计划时间 (格式: "HH:MM")
	targetTime, err := time.Parse("15:04", config.ScheduleTime)
	if err != nil {
		logWarn("解析计划时间失败，使用默认时间")
		targetTime, _ = time.Parse("15:04", "03:00")
	}
	
	// 构建下一次执行时间（使用时区）
	nextRun := time.Date(now.Year(), now.Month(), now.Day(), 
		targetTime.Hour(), targetTime.Minute(), 0, 0, timezone)
	
	if now.After(nextRun) {
		nextRun = nextRun.Add(24 * time.Hour)
	}
	
	logInfo("当前时间: %s, 下次执行: %s", now.Format("2006-01-02 15:04:05 MST"), 
		nextRun.Format("2006-01-02 15:04:05 MST"))
	
	return nextRun.Sub(now)
}

// 计算间隔调度睡眠时间
func calculateIntervalSleep() time.Duration {
	interval, err := strconv.Atoi(config.ScheduleTime)
	if err != nil || interval <= 0 {
		interval = 360 // 默认6小时
	}
	
	return time.Duration(interval) * time.Minute
}

// 执行清理任务
func executeCleanTask() {
	logInfo("开始执行定时任务")
	
	// 执行清理 - 不受电量限制
	if config.CleanEnabled {
		stats, err := runClean()
		if err != nil {
			logError("清理任务失败: %v", err)
		} else {
			logInfo("清理完成: 释放 %d 文件, 总大小 %.2f MB", 
				stats.FilesCleaned, float64(stats.BytesFreed)/1024/1024)
		}
	} else {
		logInfo("清理功能已禁用")
	}
	
	// 执行GC和磁盘整理 - 受环境条件限制
	if config.GCEnabled {
		if err := runGC(); err != nil {
			logWarn("GC任务失败: %v", err)
		} else {
			logInfo("GC任务完成")
		}
		
		runTrim()
	} else {
		logInfo("GC功能已禁用")
	}
	
	logInfo("定时任务执行完成")
}

// 主函数
func main() {
	var (
		configPath = flag.String("config", "/storage/emulated/0/Android/EZ-Clean/config.conf", "配置文件路径")
		runOnce    = flag.Bool("once", false, "立即运行一次清理")
		daemon     = flag.Bool("daemon", true, "以守护进程方式运行")
	)
	flag.Parse()
	
	// 尽早获取系统时区
	systemTZ = getSystemTimezone()
	log.Printf("检测到系统时区: %s", systemTZ)
	
	// 加载配置
	var err error
	config, err = loadConfig(*configPath)
	if err != nil {
		fmt.Printf("加载配置失败: %v\n", err)
		os.Exit(1)
	}
	
	// 初始化日志
	if err := initLogger(); err != nil {
		fmt.Printf("初始化日志失败: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()
	
	logInfo("EZ-Clean 启动 - 系统时区: %s", systemTZ)
	
	// 立即运行一次
	if *runOnce {
		logInfo("开始立即清理...")
		executeCleanTask()
		logInfo("立即清理完成")
		return
	}
	
	// 守护进程模式
	if *daemon {
		logInfo("以守护进程模式运行")
		startScheduler()
		return
	}
	
	// 默认运行一次然后退出
	logInfo("开始单次清理...")
	executeCleanTask()
	logInfo("清理完成")
}