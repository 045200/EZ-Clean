package core

import (
	"os/exec"
	"time"
	"fmt"
)

// setAndroidLocalTimeZone 通过Android系统命令获取默认时区并设置
func setAndroidLocalTimeZone() error {
	// Android系统通过getprop命令获取持久化的默认时区（persist.sys.timezone为系统时区属性）
	cmd := exec.Command("getprop", "persist.sys.timezone")
	output, err := cmd.Output()
	if err != nil {
		// 命令执行失败时，降级使用系统默认时区（兼容异常场景）
		time.Local = time.Local
		return fmt.Errorf("执行getprop命令失败: %v", err)
	}

	// 去除输出中的换行符，得到标准时区ID（如Asia/Shanghai）
	timezoneID := string(output[:len(output)-1])
	loc, err := time.LoadLocation(timezoneID)
	if err != nil {
		// 时区ID无效时，降级使用系统默认时区
		time.Local = time.Local
		return fmt.Errorf("加载时区%s失败: %v", timezoneID, err)
	}

	// 设置程序全局时区
	time.Local = loc
	return nil
}