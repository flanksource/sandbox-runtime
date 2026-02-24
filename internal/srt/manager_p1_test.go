package srt

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestCheckDependencies_HonorsConfiguredRipgrepCommand(t *testing.T) {
	m := NewManager()
	if !m.IsSupportedPlatform() {
		t.Skip("unsupported platform")
	}

	cfg := DefaultConfig()
	cfg.Ripgrep = &RipgrepConfig{Command: "definitely-missing-rg-config-cmd"}
	if err := m.UpdateConfig(cfg); err != nil {
		t.Fatalf("update config failed: %v", err)
	}

	deps := m.CheckDependencies(nil)
	joined := strings.Join(deps.Errors, " | ")
	if !strings.Contains(joined, "ripgrep (definitely-missing-rg-config-cmd) not found") {
		t.Fatalf("expected configured ripgrep command in dependency errors, got: %v", deps.Errors)
	}
}

func TestCheckDependencies_ExplicitRipgrepArgumentOverridesConfig(t *testing.T) {
	m := NewManager()
	if !m.IsSupportedPlatform() {
		t.Skip("unsupported platform")
	}

	cfg := DefaultConfig()
	cfg.Ripgrep = &RipgrepConfig{Command: "definitely-missing-rg-config-cmd"}
	if err := m.UpdateConfig(cfg); err != nil {
		t.Fatalf("update config failed: %v", err)
	}

	override := &RipgrepConfig{Command: "definitely-missing-rg-override-cmd"}
	deps := m.CheckDependencies(override)
	joined := strings.Join(deps.Errors, " | ")
	if !strings.Contains(joined, "ripgrep (definitely-missing-rg-override-cmd) not found") {
		t.Fatalf("expected override ripgrep command in dependency errors, got: %v", deps.Errors)
	}
	if strings.Contains(joined, "definitely-missing-rg-config-cmd") {
		t.Fatalf("expected override command to take precedence, got: %v", deps.Errors)
	}
}

func TestWrapWithSandbox_NetworkRestrictionFollowsNetworkConfigPresence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	m := NewManager()
	if !m.IsSupportedPlatform() {
		t.Skip("unsupported platform")
	}
	if deps := m.CheckDependencies(nil); len(deps.Errors) > 0 {
		t.Skipf("missing dependencies: %v", deps.Errors)
	}

	cfgWithoutNetwork := SandboxRuntimeConfig{
		Filesystem: FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	}
	ctx := context.Background()
	if err := m.Initialize(ctx, cfgWithoutNetwork, nil); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}
	defer m.Reset(ctx)

	wrappedWithoutNetwork, err := m.WrapWithSandbox(context.Background(), "echo hello", "", nil)
	if err != nil {
		t.Fatalf("wrap without network config failed: %v", err)
	}
	if strings.Contains(wrappedWithoutNetwork, "--unshare-net") {
		t.Fatalf("did not expect network isolation when network config is absent, got: %s", wrappedWithoutNetwork)
	}

	wrappedWithNetwork, err := m.WrapWithSandbox(context.Background(), "echo hello", "", &SandboxRuntimeConfig{
		Network:    NetworkConfig{AllowedDomains: []string{}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	})
	if err != nil {
		t.Fatalf("wrap with network config failed: %v", err)
	}
	if !strings.Contains(wrappedWithNetwork, "--unshare-net") {
		t.Fatalf("expected network isolation when network config is present, got: %s", wrappedWithNetwork)
	}
}

func TestWrapWithSandbox_CustomConfigMergesWithBaseConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	m := NewManager()
	if !m.IsSupportedPlatform() {
		t.Skip("unsupported platform")
	}
	if deps := m.CheckDependencies(nil); len(deps.Errors) > 0 {
		t.Skipf("missing dependencies: %v", deps.Errors)
	}

	baseCfg := SandboxRuntimeConfig{
		Network:    NetworkConfig{AllowedDomains: []string{"example.com"}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	}
	ctx := context.Background()
	if err := m.Initialize(ctx, baseCfg, nil); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}
	defer m.Reset(ctx)

	wrapped, err := m.WrapWithSandbox(context.Background(), "echo hello", "", &SandboxRuntimeConfig{
		Filesystem: FilesystemConfig{AllowWrite: []string{"/tmp"}},
	})
	if err != nil {
		t.Fatalf("wrap with custom filesystem override failed: %v", err)
	}
	if !strings.Contains(wrapped, "--unshare-net") {
		t.Fatalf("expected custom config without network section to inherit base network restrictions, got: %s", wrapped)
	}
}
