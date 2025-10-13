package core

import (
    "bufio"
    "fmt"
    "os"
    "strconv"
    "strings"
    
    "ez-clean/pkg/constants"
)

// ParseConfig 解析主配置文件
func ParseConfig() (*Config, error) {
    config := &Config{}
    
    file, err := os.Open(constants.ConfigFile)
    if err != nil {
        return nil, fmt.Errorf("打开配置文件失败: %v", err)
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
    
    return config, scanner.Err()
}

// ReadListFile 读取名单文件
func ReadListFile(filename string) ([]string, error) {
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