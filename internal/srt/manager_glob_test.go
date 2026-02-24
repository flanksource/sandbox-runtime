package srt

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestManagerGetFsReadConfig_ExpandsGlobOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	tmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(tmp, "nested"))
	mustWriteFile(t, filepath.Join(tmp, "a.env"), "x")
	mustWriteFile(t, filepath.Join(tmp, "nested", "b.env"), "x")

	m := NewManager()
	err := m.UpdateConfig(SandboxRuntimeConfig{
		Network:    NetworkConfig{AllowedDomains: []string{}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{filepath.Join(tmp, "**", "*.env")}, AllowWrite: []string{}, DenyWrite: []string{}},
	})
	if err != nil {
		t.Fatalf("update config failed: %v", err)
	}

	readCfg := m.GetFsReadConfig()
	expected := []string{
		filepath.Join(tmp, "a.env"),
		filepath.Join(tmp, "nested", "b.env"),
	}
	for _, want := range expected {
		if !containsPath(readCfg.DenyOnly, want) {
			t.Fatalf("expected expanded denyRead path %q, got %#v", want, readCfg.DenyOnly)
		}
	}
}

func TestManagerWrapWithSandbox_CustomConfigExpandsDenyReadGlobOnLinux(t *testing.T) {
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
		Network:    NetworkConfig{AllowedDomains: []string{}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	}
	ctx := context.Background()
	if err := m.Initialize(ctx, baseCfg, nil); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}
	defer m.Reset(ctx)

	tmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(tmp, "nested"))
	mustWriteFile(t, filepath.Join(tmp, "x.env"), "x")
	mustWriteFile(t, filepath.Join(tmp, "nested", "y.env"), "x")

	customCfg := &SandboxRuntimeConfig{
		Network:    NetworkConfig{AllowedDomains: []string{}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{filepath.Join(tmp, "**", "*.env")}, AllowWrite: []string{}, DenyWrite: []string{}},
	}
	wrapped, err := m.WrapWithSandbox(context.Background(), "echo hello", "", customCfg)
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	if !strings.Contains(wrapped, filepath.Join(tmp, "x.env")) || !strings.Contains(wrapped, filepath.Join(tmp, "nested", "y.env")) {
		t.Fatalf("expected wrapped command to include expanded denyRead paths, got: %s", wrapped)
	}
}

func containsPath(paths []string, want string) bool {
	want = filepath.Clean(want)
	for _, p := range paths {
		if filepath.Clean(p) == want {
			return true
		}
	}
	return false
}
