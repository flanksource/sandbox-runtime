package srt

import (
	"os"
	"regexp"
	"runtime"
	"strings"
)

type Platform string

const (
	PlatformMacOS   Platform = "macos"
	PlatformLinux   Platform = "linux"
	PlatformWindows Platform = "windows"
	PlatformUnknown Platform = "unknown"
)

var wslVersionPattern = regexp.MustCompile(`(?i)WSL(\d+)`)

func GetPlatform() Platform {
	switch runtime.GOOS {
	case "darwin":
		return PlatformMacOS
	case "linux":
		return PlatformLinux
	case "windows":
		return PlatformWindows
	default:
		return PlatformUnknown
	}
}

func parseWSLVersion(procVersion string) string {
	if procVersion == "" {
		return ""
	}

	if matches := wslVersionPattern.FindStringSubmatch(procVersion); len(matches) > 1 {
		return matches[1]
	}

	if strings.Contains(strings.ToLower(procVersion), "microsoft") {
		return "1"
	}

	return ""
}

func GetWSLVersion() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}
	return parseWSLVersion(string(data))
}
