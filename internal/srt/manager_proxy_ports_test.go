package srt

import (
	"context"
	"net"
	"testing"
)

func TestManagerInitialize_UsesConfiguredExternalProxyPorts(t *testing.T) {
	m := NewManager()
	if !m.IsSupportedPlatform() {
		t.Skip("unsupported platform")
	}
	if deps := m.CheckDependencies(nil); len(deps.Errors) > 0 {
		t.Skipf("missing dependencies: %v", deps.Errors)
	}

	httpPort := reserveTCPPort(t)
	socksPort := reserveTCPPort(t)

	cfg := SandboxRuntimeConfig{
		Network: NetworkConfig{
			AllowedDomains: []string{"example.com"},
			DeniedDomains:  []string{},
			HTTPProxyPort:  &httpPort,
			SocksProxyPort: &socksPort,
		},
		Filesystem: FilesystemConfig{DenyRead: []string{}, AllowWrite: []string{}, DenyWrite: []string{}},
	}
	ctx := context.Background()
	if err := m.Initialize(ctx, cfg, nil); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}
	defer m.Reset(ctx)

	if got := m.GetProxyPort(); got != httpPort {
		t.Fatalf("expected configured HTTP proxy port %d, got %d", httpPort, got)
	}
	if got := m.GetSocksProxyPort(); got != socksPort {
		t.Fatalf("expected configured SOCKS proxy port %d, got %d", socksPort, got)
	}
	if m.httpProxy != nil {
		t.Fatalf("expected internal HTTP proxy server not to be started when httpProxyPort is configured")
	}
	if m.socksProxy != nil {
		t.Fatalf("expected internal SOCKS proxy server not to be started when socksProxyPort is configured")
	}
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
