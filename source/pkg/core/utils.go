package core

import (
    "fmt"
    "log"
    "os"
    "path/filepath"
    "strconv"
    "strings"
)

// removePath 彻底删除路径（文件或文件夹）
func removePath(path string, logger *log.Logger, config *Config) (int64, int64, int64, error) {
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
                    LogMessage(logger, 0, fmt.Sprintf("删除文件: %s, 大小: %d bytes", filePath, fileInfo.Size()), config)
                }
            }
            return nil
        })
        
        if err != nil {
            return filesRemoved, dirsRemoved, spaceFreed, err
        }
        
        // 删除所有空文件夹（从最深层开始）
        err = removeEmptyDirs(path, &dirsRemoved, logger, config)
        if err != nil {
            return filesRemoved, dirsRemoved, spaceFreed, err
        }
        
    } else {
        // 删除文件
        if err := os.Remove(path); err == nil {
            filesRemoved = 1
            spaceFreed = info.Size()
            LogMessage(logger, 0, fmt.Sprintf("删除文件: %s, 大小: %d bytes", path, info.Size()), config)
        } else {
            return 0, 0, 0, err
        }
    }
    
    return filesRemoved, dirsRemoved, spaceFreed, nil
}

// removeEmptyDirs 递归删除空文件夹
func removeEmptyDirs(dirPath string, dirsRemoved *int64, logger *log.Logger, config *Config) error {
    entries, err := os.ReadDir(dirPath)
    if err != nil {
        return err
    }
    
    // 先递归处理子目录
    for _, entry := range entries {
        if entry.IsDir() {
            subDirPath := filepath.Join(dirPath, entry.Name())
            if err := removeEmptyDirs(subDirPath, dirsRemoved, logger, config); err != nil {
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
            LogMessage(logger, 0, fmt.Sprintf("删除空目录: %s", dirPath), config)
        } else {
            return err
        }
    }
    
    return nil
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