package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/flanksource/sandbox-runtime/internal/srt"
)

func TestControlFDUpdatesConfig(t *testing.T) {
	ctx := context.Background()
	if !srt.SandboxManager.IsSupportedPlatform() {
		t.Skip("unsupported platform")
	}
	if deps := srt.SandboxManager.CheckDependencies(nil); len(deps.Errors) > 0 {
		t.Skipf("missing dependencies: %v", deps.Errors)
	}
	_ = srt.SandboxManager.Reset(ctx)
	defer srt.SandboxManager.Reset(ctx)

	cfg := srt.DefaultConfig()
	if err := srt.SandboxManager.Initialize(ctx, cfg, nil); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	defer w.Close()

	startControlFDReader(int(r.Fd()))

	update := `{"network":{"allowedDomains":["updated-domain.com"],"deniedDomains":[]},"filesystem":{"denyRead":[],"allowWrite":[],"denyWrite":[]}}`
	if _, err := io.WriteString(w, update+"\n"); err != nil {
		t.Fatalf("write control fd failed: %v", err)
	}
	_ = w.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cfg := srt.SandboxManager.GetConfig()
		if cfg != nil && len(cfg.Network.AllowedDomains) == 1 && cfg.Network.AllowedDomains[0] == "updated-domain.com" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	got := srt.SandboxManager.GetConfig()
	t.Fatalf("config update was not applied; final config = %+v", got)
}

func TestControlFDIgnoresInvalidJSON(t *testing.T) {
	ctx := context.Background()
	if !srt.SandboxManager.IsSupportedPlatform() {
		t.Skip("unsupported platform")
	}
	if deps := srt.SandboxManager.CheckDependencies(nil); len(deps.Errors) > 0 {
		t.Skipf("missing dependencies: %v", deps.Errors)
	}
	_ = srt.SandboxManager.Reset(ctx)
	defer srt.SandboxManager.Reset(ctx)

	cfg := srt.SandboxRuntimeConfig{
		Network:    srt.NetworkConfig{AllowedDomains: []string{"initial.com"}, DeniedDomains: []string{}},
		Filesystem: srt.FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	}
	if err := srt.SandboxManager.Initialize(ctx, cfg, nil); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	defer w.Close()

	startControlFDReader(int(r.Fd()))
	_, _ = io.WriteString(w, "{ invalid json }\n")
	_ = w.Close()

	time.Sleep(200 * time.Millisecond)

	finalCfg := srt.SandboxManager.GetConfig()
	if finalCfg == nil {
		t.Fatalf("expected config to remain set")
	}
	if len(finalCfg.Network.AllowedDomains) != 1 || finalCfg.Network.AllowedDomains[0] != "initial.com" {
		t.Fatalf("expected config to remain unchanged, got: %+v", finalCfg.Network.AllowedDomains)
	}
}

func TestControlFDReader_EmptyAndMixedLines(t *testing.T) {
	ctx := context.Background()
	if !srt.SandboxManager.IsSupportedPlatform() {
		t.Skip("unsupported platform")
	}
	if deps := srt.SandboxManager.CheckDependencies(nil); len(deps.Errors) > 0 {
		t.Skipf("missing dependencies: %v", deps.Errors)
	}
	_ = srt.SandboxManager.Reset(ctx)
	defer srt.SandboxManager.Reset(ctx)

	cfg := srt.SandboxRuntimeConfig{
		Network:    srt.NetworkConfig{AllowedDomains: []string{"initial.com"}, DeniedDomains: []string{}},
		Filesystem: srt.FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	}
	if err := srt.SandboxManager.Initialize(ctx, cfg, nil); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	defer w.Close()

	startControlFDReader(int(r.Fd()))
	_, _ = io.WriteString(w, "\n")
	_, _ = io.WriteString(w, "{not-json}\n")
	_, _ = io.WriteString(w, `{"network":{"allowedDomains":["after.com"],"deniedDomains":[]},"filesystem":{"denyRead":[],"allowWrite":[],"denyWrite":[]}}`+"\n")
	_ = w.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		finalCfg := srt.SandboxManager.GetConfig()
		if finalCfg != nil && len(finalCfg.Network.AllowedDomains) == 1 && finalCfg.Network.AllowedDomains[0] == "after.com" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("expected valid line to update config after empty/invalid lines")
}

func TestDefaultConfigPath(t *testing.T) {
	p := defaultConfigPath()
	if p == "" {
		t.Fatalf("defaultConfigPath should not be empty")
	}
	if !strings.HasSuffix(p, ".srt-settings.json") {
		t.Fatalf("expected default config path to end with .srt-settings.json, got %s", p)
	}
}

func TestParseArgsControlFDFlag(t *testing.T) {
	opts, _, err := parseArgs([]string{"--control-fd", "3", "echo", "ok"})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if !opts.hasControl || opts.controlFD != 3 {
		t.Fatalf("expected control-fd parsed, got hasControl=%v fd=%d", opts.hasControl, opts.controlFD)
	}

	opts, _, err = parseArgs([]string{"--control-fd", "3"})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if !opts.hasControl || opts.controlFD != 3 {
		t.Fatalf("expected control-fd parsed without command, got hasControl=%v fd=%d", opts.hasControl, opts.controlFD)
	}

	_, _, err = parseArgs([]string{"--control-fd"})
	if err == nil {
		t.Fatalf("expected missing value error")
	}
	_, _, err = parseArgs([]string{"--control-fd", "abc"})
	if err == nil {
		t.Fatalf("expected invalid fd error")
	}

	_ = fmt.Sprintf("%v", opts)
}
