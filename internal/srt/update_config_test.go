package srt

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestManagerUpdateConfig_Basic(t *testing.T) {
	m := NewManager()

	cfg1 := SandboxRuntimeConfig{
		Network:    NetworkConfig{AllowedDomains: []string{"example.com"}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	}
	if err := m.UpdateConfig(cfg1); err != nil {
		t.Fatalf("update config before init should not fail: %v", err)
	}
	if m.GetConfig() == nil {
		t.Fatalf("expected config to be set after update")
	}
	if p := m.GetProxyPort(); p != 0 {
		t.Fatalf("expected proxy port 0 before initialize, got %d", p)
	}

	if !m.IsSupportedPlatform() {
		t.Skip("unsupported platform")
	}
	if deps := m.CheckDependencies(nil); len(deps.Errors) > 0 {
		t.Skipf("missing dependencies: %v", deps.Errors)
	}

	cfg2 := SandboxRuntimeConfig{
		Network:    NetworkConfig{AllowedDomains: []string{"other.com"}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	}
	ctx := context.Background()
	if err := m.Initialize(ctx, cfg2, nil); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}
	defer m.Reset(ctx)

	finalCfg := m.GetConfig()
	if finalCfg == nil {
		t.Fatalf("expected config after initialize")
	}
	if len(finalCfg.Network.AllowedDomains) != 1 || finalCfg.Network.AllowedDomains[0] != "other.com" {
		t.Fatalf("expected initialize config to replace prior update config, got %#v", finalCfg.Network.AllowedDomains)
	}
}

func TestManagerUpdateConfig_ProxyFiltering(t *testing.T) {
	m := NewManager()
	if !m.IsSupportedPlatform() {
		t.Skip("unsupported platform")
	}
	if deps := m.CheckDependencies(nil); len(deps.Errors) > 0 {
		t.Skipf("missing dependencies: %v", deps.Errors)
	}

	cfg := SandboxRuntimeConfig{
		Network:    NetworkConfig{AllowedDomains: []string{"localhost"}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	}
	ctx := context.Background()
	if err := m.Initialize(ctx, cfg, nil); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}
	defer m.Reset(ctx)

	proxyPort := m.GetProxyPort()
	if proxyPort == 0 {
		t.Fatalf("expected proxy port after initialize")
	}

	status1, err := connectViaProxy(proxyPort, "localhost", 1)
	if err != nil {
		t.Fatalf("proxy request 1 failed: %v", err)
	}
	if status1 == 403 {
		t.Fatalf("expected localhost to be allowed initially, got 403")
	}

	if err := m.UpdateConfig(SandboxRuntimeConfig{
		Network:    NetworkConfig{AllowedDomains: []string{}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	}); err != nil {
		t.Fatalf("update config failed: %v", err)
	}

	status2, err := connectViaProxy(proxyPort, "localhost", 1)
	if err != nil {
		t.Fatalf("proxy request 2 failed: %v", err)
	}
	if status2 != 403 {
		t.Fatalf("expected localhost to be blocked after empty allowlist, got %d", status2)
	}

	if err := m.UpdateConfig(SandboxRuntimeConfig{
		Network:    NetworkConfig{AllowedDomains: []string{"localhost"}, DeniedDomains: []string{}},
		Filesystem: FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	}); err != nil {
		t.Fatalf("update config 2 failed: %v", err)
	}

	status3, err := connectViaProxy(proxyPort, "localhost", 1)
	if err != nil {
		t.Fatalf("proxy request 3 failed: %v", err)
	}
	if status3 == 403 {
		t.Fatalf("expected localhost to be allowed again after config update")
	}
}

func connectViaProxy(proxyPort int, host string, targetPort int) (int, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 2*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, targetPort, host, targetPort); err != nil {
		return 0, err
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return 0, err
	}
	line = strings.TrimSpace(line)
	var status int
	_, _ = fmt.Sscanf(line, "HTTP/1.1 %d", &status)
	if status == 0 {
		_, _ = fmt.Sscanf(line, "HTTP/1.0 %d", &status)
	}
	if status == 0 {
		return 0, fmt.Errorf("could not parse response line: %q", line)
	}
	return status, nil
}
