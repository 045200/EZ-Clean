package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IGLOU-EU/go-wildcard"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Config 主配置结构体
type Config struct {
	CleanInterval   int      `json:"clean_interval"`
	LogLevel        int      `json:"log_level"`
	LogMaxSize      int      `json:"log_max_size"`
	LogMaxAge       int      `json:"log_max_age"`
	LoopCleanEnable bool     `json:"loop_clean_enable"`
	AppCleanEnable  bool     `json:"app_clean_enable"`
	AppPackages     []string `json:"app_packages"`
}

// CleanResult 清理结果统计
type CleanResult struct {
	DirsRemoved  int64
	FilesRemoved int64
	SpaceFreed   int64
}

// 全局变量
var (
	config         Config
	logger         *log.Logger
	lumberjackLogger *lumberjack.Logger
	cleanMutex     sync.Mutex
	appCleanMutex  sync.Mutex
)

const (
	configDir      = "/storage/emulated/0/Android/EZ-Clean/"
	blacklistFile  = configDir + "blacklist.conf"
	whitelistFile  = configDir + "whitelist.conf"
	configFile     = configDir + "config.conf"
	appConfigFile  = configDir + "App.conf"
	logFile        = configDir + "Clean.log"
)

// parseConfig 解析主配置文件
func parseConfig() error {
	file, err := os.Open(configFile)
	if err != nil {
		return fmt.Errorf("打开配置文件失败: %v", err)
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
		case "clean_interval":
			config.CleanInterval, _ = strconv.Atoi(value)
		case "log_level":
			config.LogLevel, _ = strconv.Atoi(value)
		case "log_max_size":
			config.LogMaxSize, _ = strconv.Atoi(value)
		case "log_max_age":
			config.LogMaxAge, _ = strconv.Atoi(value)
		case "loop_clean_enable":
			config.LoopCleanEnable = strings.ToLower(value) == "true"
		case "app_clean_enable":
			config.AppCleanEnable = strings.ToLower(value) == "true"
		case "app_packages":
			if value != "" {
				config.AppPackages = strings.Split(value, ",")
				for i, pkg := range config.AppPackages {
					config.AppPackages[i] = strings.TrimSpace(pkg)
				}
			}
		}
	}
	
	// 设置默认值
	if config.CleanInterval == 0 {
		config.CleanInterval = 60
	}
	if config.LogLevel < 0 || config.LogLevel > 3 {
		config.LogLevel = 1
	}
	if config.LogMaxSize == 0 {
		config.LogMaxSize = 10
	}
	if config.LogMaxAge == 0 {
		config.LogMaxAge = 7
	}
	
	return scanner.Err()
}

// readListFile 读取名单文件
func readListFile(filename string) ([]string, error) {
	var lines []string
	
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "#") && line != "" {
			lines = append(lines, line)
		}
	}
	
	return lines, scanner.Err()
}

// 自定义Writer实现本地时间戳
type localTimeWriter struct {
	logger *lumberjack.Logger
}

func (w *localTimeWriter) Write(p []byte) (n int, err error) {
	localTime := time.Now().Format("2006/01/02 15:04:05")
	logEntry := fmt.Sprintf("%s %s", localTime, string(p))
	return w.logger.Write([]byte(logEntry))
}

// setupLogger 初始化日志系统
func setupLogger() error {
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %v", err)
	}
	
	lumberjackLogger = &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    config.LogMaxSize,
		MaxBackups: 3,
		MaxAge:     config.LogMaxAge,
		Compress:   true,
	}
	
	customWriter := &localTimeWriter{logger: lumberjackLogger}
	logger = log.New(customWriter, "", 0)
	return nil
}

// logMessage 根据日志等级记录日志
func logMessage(level int, message string) {
	if shouldLog(level) {
		levelStr := "DEBUG"
		switch level {
		case 1:
			levelStr = "INFO"
		case 2:
			levelStr = "WARN"
		case 3:
			levelStr = "ERROR"
		}
		logger.Printf("[%s] %s\n", levelStr, message)
	}
}

// shouldLog 判断是否应该记录该等级的日志
func shouldLog(level int) bool {
	return level >= config.LogLevel
}

// ========== 改进的清理逻辑 ==========

// removePath 彻底删除路径（文件或文件夹）
func removePath(path string) (int64, int64, int64, error) {
	var filesRemoved, dirsRemoved int64
	var spaceFreed int64

	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, 0, err
	}

	if info.IsDir() {
		// 递归删除文件夹及其所有内容
		err = filepath.Walk(path, func(filePath string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			
			if !fileInfo.IsDir() {
				// 删除文件
				if err := os.Remove(filePath); err == nil {
					filesRemoved++
					spaceFreed += fileInfo.Size()
					logMessage(0, fmt.Sprintf("删除文件: %s, 大小: %d bytes", filePath, fileInfo.Size()))
				}
			}
			return nil
		})
		
		if err != nil {
			return filesRemoved, dirsRemoved, spaceFreed, err
		}
		
		// 删除所有空文件夹（从最深层开始）
		err = removeEmptyDirs(path, &dirsRemoved)
		if err != nil {
			return filesRemoved, dirsRemoved, spaceFreed, err
		}
		
	} else {
		// 删除文件
		if err := os.Remove(path); err == nil {
			filesRemoved = 1
			spaceFreed = info.Size()
			logMessage(0, fmt.Sprintf("删除文件: %s, 大小: %d bytes", path, info.Size()))
		} else {
			return 0, 0, 0, err
		}
	}
	
	return filesRemoved, dirsRemoved, spaceFreed, nil
}

// removeEmptyDirs 递归删除空文件夹
func removeEmptyDirs(dirPath string, dirsRemoved *int64) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}
	
	// 先递归处理子目录
	for _, entry := range entries {
		if entry.IsDir() {
			subDirPath := filepath.Join(dirPath, entry.Name())
			if err := removeEmptyDirs(subDirPath, dirsRemoved); err != nil {
				return err
			}
		}
	}
	
	// 检查当前目录是否为空
	entries, err = os.ReadDir(dirPath)
	if err != nil {
		return err
	}
	
	if len(entries) == 0 {
		// 删除空目录
		if err := os.Remove(dirPath); err == nil {
			*dirsRemoved++
			logMessage(0, fmt.Sprintf("删除空目录: %s", dirPath))
		} else {
			return err
		}
	}
	
	return nil
}

// ========== 循环清理逻辑 ==========

// performLoopCleanup 执行循环清理
func performLoopCleanup() {
	if !cleanMutex.TryLock() {
		logMessage(0, "循环清理: 已有清理任务在进行中，跳过")
		return
	}
	defer cleanMutex.Unlock()
	
	logMessage(1, "开始循环清理任务")
	
	blacklist, err := readListFile(blacklistFile)
	if err != nil {
		logMessage(3, fmt.Sprintf("循环清理: 读取黑名单失败: %v", err))
		return
	}
	
	whitelist, err := readListFile(whitelistFile)
	if err != nil {
		logMessage(3, fmt.Sprintf("循环清理: 读取白名单失败: %v", err))
		return
	}
	
	var totalResult CleanResult
	
	for _, path := range blacklist {
		result := cleanPathWithWhitelist(path, whitelist)
		totalResult.DirsRemoved += result.DirsRemoved
		totalResult.FilesRemoved += result.FilesRemoved
		totalResult.SpaceFreed += result.SpaceFreed
	}
	
	// 记录清理结果
	logMessage(1, fmt.Sprintf(
		"循环清理完成: 删除文件夹%d个, 删除文件%d个, 释放空间%.2f MB",
		totalResult.DirsRemoved,
		totalResult.FilesRemoved,
		float64(totalResult.SpaceFreed)/(1024*1024),
	))
}

// cleanPathWithWhitelist 清理单个路径（应用白名单过滤）
func cleanPathWithWhitelist(path string, whitelist []string) CleanResult {
	var result CleanResult
	
	if isWhitelisted(path, whitelist) {
		logMessage(0, fmt.Sprintf("循环清理: 跳过白名单路径: %s", path))
		return result
	}
	
	if strings.Contains(path, "*") {
		// 通配符路径清理
		result = cleanWildcardPathWithWhitelist(path, whitelist)
	} else {
		// 具体路径清理
		files, dirs, space, err := removePath(path)
		if err != nil {
			logMessage(0, fmt.Sprintf("循环清理: 路径不存在或无法删除: %s, 错误: %v", path, err))
			return result
		}
		result.FilesRemoved = files
		result.DirsRemoved = dirs
		result.SpaceFreed = space
	}
	
	return result
}

// cleanWildcardPathWithWhitelist 使用通配符匹配清理路径（带白名单）
func cleanWildcardPathWithWhitelist(pattern string, whitelist []string) CleanResult {
	var result CleanResult
	
	baseDir := getBaseDir(pattern)
	
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		if wildcard.Match(pattern, path) {
			if isWhitelisted(path, whitelist) {
				logMessage(0, fmt.Sprintf("循环清理: 跳过白名单路径: %s", path))
				return nil
			}
			
			files, dirs, space, err := removePath(path)
			if err == nil {
				result.FilesRemoved += files
				result.DirsRemoved += dirs
				result.SpaceFreed += space
			}
		}
		return nil
	})
	
	if err != nil {
		logMessage(3, fmt.Sprintf("遍历目录失败: %s, 错误: %v", baseDir, err))
	}
	
	return result
}

// ========== App触发清理逻辑 ==========

// performAppCleanup 执行App触发清理
func performAppCleanup() {
	if !appCleanMutex.TryLock() {
		logMessage(0, "App触发清理: 已有清理任务在进行中，跳过")
		return
	}
	defer appCleanMutex.Unlock()
	
	logMessage(1, "开始App触发清理任务")
	
	appCleanList, err := readListFile(appConfigFile)
	if err != nil {
		logMessage(3, fmt.Sprintf("App触发清理: 读取清理名单失败: %v", err))
		return
	}
	
	var totalResult CleanResult
	
	for _, path := range appCleanList {
		result := cleanPath(path)
		totalResult.DirsRemoved += result.DirsRemoved
		totalResult.FilesRemoved += result.FilesRemoved
		totalResult.SpaceFreed += result.SpaceFreed
	}
	
	// 记录清理结果
	logMessage(1, fmt.Sprintf(
		"App触发清理完成: 删除文件夹%d个, 删除文件%d个, 释放空间%.2f MB",
		totalResult.DirsRemoved,
		totalResult.FilesRemoved,
		float64(totalResult.SpaceFreed)/(1024*1024),
	))
}

// cleanPath 清理单个路径（无白名单过滤）
func cleanPath(path string) CleanResult {
	var result CleanResult
	
	if strings.Contains(path, "*") {
		// 通配符路径清理
		result = cleanWildcardPath(path)
	} else {
		// 具体路径清理
		files, dirs, space, err := removePath(path)
		if err != nil {
			logMessage(0, fmt.Sprintf("App触发清理: 路径不存在或无法删除: %s, 错误: %v", path, err))
			return result
		}
		result.FilesRemoved = files
		result.DirsRemoved = dirs
		result.SpaceFreed = space
	}
	
	return result
}

// cleanWildcardPath 使用通配符匹配清理路径（无白名单）
func cleanWildcardPath(pattern string) CleanResult {
	var result CleanResult
	
	baseDir := getBaseDir(pattern)
	
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		if wildcard.Match(pattern, path) {
			files, dirs, space, err := removePath(path)
			if err == nil {
				result.FilesRemoved += files
				result.DirsRemoved += dirs
				result.SpaceFreed += space
			}
		}
		return nil
	})
	
	if err != nil {
		logMessage(3, fmt.Sprintf("遍历目录失败: %s, 错误: %v", baseDir, err))
	}
	
	return result
}

// ========== 通用函数 ==========

// isWhitelisted 检查路径是否在白名单中
func isWhitelisted(path string, whitelist []string) bool {
	for _, pattern := range whitelist {
		if wildcard.Match(pattern, path) {
			return true
		}
	}
	return false
}

// getBaseDir 从通配符路径中提取基目录
func getBaseDir(pattern string) string {
	wildcardIndex := strings.IndexAny(pattern, "*?[")
	if wildcardIndex == -1 {
		return filepath.Dir(pattern)
	}
	
	base := pattern[:wildcardIndex]
	return filepath.Dir(base)
}

// ========== 定时任务管理 ==========

// startLoopCleaner 启动循环清理定时任务
func startLoopCleaner(ctx context.Context) {
	if !config.LoopCleanEnable {
		logMessage(1, "循环清理已禁用")
		return
	}
	
	interval := time.Duration(config.CleanInterval) * time.Minute
	logMessage(1, fmt.Sprintf("循环清理间隔: %v", interval))
	
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	// 立即执行一次清理
	go performLoopCleanup()
	
	for {
		select {
		case <-ticker.C:
			go performLoopCleanup()
		case <-ctx.Done():
			logMessage(1, "循环清理器已停止")
			return
		}
	}
}

// startAppTrigger 启动App触发监控
func startAppTrigger(ctx context.Context) {
	if !config.AppCleanEnable {
		logMessage(1, "App触发清理已禁用")
		return
	}
	
	if len(config.AppPackages) == 0 {
		logMessage(2, "App触发清理: 未配置App包名")
		return
	}
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if isTargetAppRunning() {
				logMessage(1, "检测到目标App运行，触发清理")
				go performAppCleanup()
			}
		case <-ctx.Done():
			logMessage(1, "App触发监控已停止")
			return
		}
	}
}

// isTargetAppRunning 检查目标App是否在运行
func isTargetAppRunning() bool {
	for _, app := range config.AppPackages {
		if checkProcessRunning(app) {
			logMessage(0, fmt.Sprintf("检测到App运行: %s", app))
			return true
		}
	}
	return false
}

// checkProcessRunning 检查进程是否运行
func checkProcessRunning(processName string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		if _, err := strconv.Atoi(entry.Name()); err == nil {
			cmdlineFile := fmt.Sprintf("/proc/%s/cmdline", entry.Name())
			data, err := os.ReadFile(cmdlineFile)
			if err != nil {
				continue
			}
			
			cmdline := strings.Trim(string(data), "\x00")
			if strings.Contains(cmdline, processName) {
				return true
			}
		}
	}
	
	return false
}

// ========== 主程序 ==========

func main() {
	// 解析配置文件
	if err := parseConfig(); err != nil {
		if os.IsNotExist(err) {
			log.Printf("配置文件不存在，使用默认配置")
			config = Config{
				CleanInterval:   60,
				LogLevel:        1,
				LogMaxSize:      10,
				LogMaxAge:       7,
				LoopCleanEnable: true,
				AppCleanEnable:  true,
			}
			os.MkdirAll(configDir, 0755)
		} else {
			log.Fatalf("解析配置失败: %v", err)
		}
	}
	
	// 初始化日志系统
	if err := setupLogger(); err != nil {
		log.Fatalf("初始化日志系统失败: %v", err)
	}
	
	// 精简的INFO日志输出
	logMessage(1, "EZ-Clean 程序启动")
	logMessage(1, fmt.Sprintf("循环清理: %t (%d分钟)", config.LoopCleanEnable, config.CleanInterval))
	logMessage(1, fmt.Sprintf("App触发: %t (%d个App)", config.AppCleanEnable, len(config.AppPackages)))
	
	// 创建上下文用于优雅停止
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// 启动清理协程
	go startLoopCleaner(ctx)
	go startAppTrigger(ctx)
	
	// 保持主程序运行
	logMessage(1, "程序运行中...")
	select {}
}