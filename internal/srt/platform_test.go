package srt

import (
	"runtime"
	"testing"
)

func TestGetPlatform(t *testing.T) {
	p := GetPlatform()
	switch runtime.GOOS {
	case "darwin":
		if p != PlatformMacOS {
			t.Fatalf("expected %q, got %q", PlatformMacOS, p)
		}
	case "linux":
		if p != PlatformLinux {
			t.Fatalf("expected %q, got %q", PlatformLinux, p)
		}
	case "windows":
		if p != PlatformWindows {
			t.Fatalf("expected %q, got %q", PlatformWindows, p)
		}
	default:
		if p != PlatformUnknown {
			t.Fatalf("expected %q, got %q", PlatformUnknown, p)
		}
	}
}

func TestParseWSLVersion(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "explicit wsl2", data: "Linux version 5.15.153.1-microsoft-standard-WSL2", want: "2"},
		{name: "explicit wsl10", data: "Linux version 6.8.0-custom WSL10", want: "10"},
		{name: "fallback microsoft", data: "Linux version 4.4.0-19041-Microsoft", want: "1"},
		{name: "non-wsl", data: "Linux version 6.8.0-generic", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseWSLVersion(tt.data); got != tt.want {
				t.Fatalf("parseWSLVersion(%q) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestGetWSLVersion(t *testing.T) {
	v := GetWSLVersion()
	if runtime.GOOS != "linux" {
		if v != "" {
			t.Fatalf("expected empty WSL version on non-linux, got %q", v)
		}
	}
}
