package srt

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestRestrictionPatternSemantics_NoSandboxNeeded(t *testing.T) {
	const cmd = "echo hello"

	switch GetPlatform() {
	case PlatformLinux:
		wrapped, err := WrapCommandWithSandboxLinux(context.Background(), LinuxSandboxParams{
			Command:                 cmd,
			NeedsNetworkRestriction: false,
			ReadConfig:              &FsReadRestrictionConfig{DenyOnly: []string{}},
			WriteConfig:             nil,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wrapped != cmd {
			t.Fatalf("expected command unchanged, got: %s", wrapped)
		}
	case PlatformMacOS:
		wrapped, err := WrapCommandWithSandboxMacOS(MacOSSandboxParams{
			Command:                 cmd,
			NeedsNetworkRestriction: false,
			ReadConfig:              &FsReadRestrictionConfig{DenyOnly: []string{}},
			WriteConfig:             nil,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wrapped != cmd {
			t.Fatalf("expected command unchanged, got: %s", wrapped)
		}
	default:
		t.Skip("unsupported sandbox platform")
	}
}

func TestWrapWithSandbox_CustomConfig(t *testing.T) {
	if !SandboxManager.IsSupportedPlatform() {
		t.Skip("unsupported platform")
	}
	if deps := SandboxManager.CheckDependencies(nil); len(deps.Errors) > 0 {
		t.Skipf("missing dependencies: %v", deps.Errors)
	}
	ctx := context.Background()
	defer SandboxManager.Reset(ctx)

	initCfg := SandboxRuntimeConfig{
		Network:    NetworkConfig{AllowedDomains: []string{"example.com"}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{"~/.ssh"}, AllowWrite: []string{".", "/tmp"}, DenyWrite: []string{".env"}},
	}
	if err := SandboxManager.Initialize(ctx, initCfg, nil); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	wrapped, err := SandboxManager.WrapWithSandbox(context.Background(), "echo hello", "", &SandboxRuntimeConfig{
		Network:    NetworkConfig{AllowedDomains: []string{}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	})
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}
	if wrapped == "echo hello" {
		t.Fatalf("expected wrapped command, got unchanged")
	}

	if GetPlatform() == PlatformLinux && !strings.Contains(wrapped, "bwrap") {
		t.Fatalf("expected Linux wrapper to contain bwrap, got: %s", wrapped)
	}
	if GetPlatform() == PlatformMacOS && !strings.Contains(wrapped, "sandbox-exec") {
		t.Fatalf("expected macOS wrapper to contain sandbox-exec, got: %s", wrapped)
	}
}

func TestWrapLinux_NetworkRestrictionWithoutProxySockets(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	if Which("bwrap") == "" {
		t.Skip("bwrap not available")
	}

	wrapped, err := WrapCommandWithSandboxLinux(context.Background(), LinuxSandboxParams{
		Command:                 "echo hello",
		NeedsNetworkRestriction: true,
		ReadConfig:              &FsReadRestrictionConfig{DenyOnly: []string{}},
		WriteConfig:             &FsWriteRestrictionConfig{AllowOnly: []string{"/tmp"}, DenyWithinAllow: []string{}},
	})
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}
	if !strings.Contains(wrapped, "--unshare-net") {
		t.Fatalf("expected --unshare-net in wrapped command: %s", wrapped)
	}
	if strings.Contains(wrapped, "HTTP_PROXY") {
		t.Fatalf("did not expect HTTP_PROXY when no proxy sockets are provided")
	}
}

func TestWrapMacOS_AllowLocalBindingAndPty(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only")
	}

	wrapped, err := WrapCommandWithSandboxMacOS(MacOSSandboxParams{
		Command:                 "echo hello",
		NeedsNetworkRestriction: true,
		AllowLocalBinding:       true,
		AllowPty:                true,
		ReadConfig:              &FsReadRestrictionConfig{DenyOnly: []string{}},
		WriteConfig:             &FsWriteRestrictionConfig{AllowOnly: []string{"/tmp"}, DenyWithinAllow: []string{}},
	})
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}
	if !strings.Contains(wrapped, "sandbox-exec") {
		t.Fatalf("expected sandbox-exec wrapper")
	}
	if !strings.Contains(wrapped, "network-bind") {
		t.Fatalf("expected local binding rule in profile")
	}
	if !strings.Contains(wrapped, "pseudo-tty") {
		t.Fatalf("expected pty rule in profile")
	}
}
