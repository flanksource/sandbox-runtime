package srt

import (
	"encoding/json"
	"testing"
)

func TestConfigValidation_MinimalValidConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func TestConfigValidation_ValidDomains(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Network.AllowedDomains = []string{"example.com", "*.github.com", "localhost"}
	cfg.Network.DeniedDomains = []string{"evil.com"}
	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatalf("expected valid domain config, got error: %v", err)
	}
}

func TestConfigValidation_InvalidDomains(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{name: "not-a-domain", domain: "not-a-domain"},
		{name: "protocol", domain: "https://example.com"},
		{name: "invalid wildcard 1", domain: "*example.com"},
		{name: "invalid wildcard 2", domain: "*.com"},
		{name: "invalid wildcard 3", domain: "*."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Network.AllowedDomains = []string{tt.domain}
			if err := cfg.NormalizeAndValidate(); err == nil {
				t.Fatalf("expected invalid domain %q to fail validation", tt.domain)
			}
		})
	}
}

func TestConfigValidation_RejectsEmptyFilesystemPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Filesystem.DenyRead = []string{""}
	if err := cfg.NormalizeAndValidate(); err == nil {
		t.Fatalf("expected empty filesystem path to fail validation")
	}
}

func TestConfigValidation_OptionalFields(t *testing.T) {
	httpPort := 8080
	socksPort := 1080
	cfg := SandboxRuntimeConfig{
		Network: NetworkConfig{
			AllowedDomains:      []string{"example.com"},
			DeniedDomains:       []string{},
			AllowUnixSockets:    []string{"/var/run/docker.sock"},
			AllowAllUnixSockets: false,
			AllowLocalBinding:   true,
			HTTPProxyPort:       &httpPort,
			SocksProxyPort:      &socksPort,
		},
		Filesystem: FilesystemConfig{
			DenyRead:   []string{"/etc/shadow"},
			AllowWrite: []string{"/tmp"},
			DenyWrite:  []string{"/etc"},
		},
		IgnoreViolations: map[string][]string{
			"*":        {"/usr/bin"},
			"git push": {"/usr/bin/nc"},
		},
		EnableWeakerNestedSandbox:    true,
		EnableWeakerNetworkIsolation: true,
		Ripgrep: &RipgrepConfig{
			Command: "rg",
			Args:    []string{"--hidden"},
		},
		MandatoryDenySearchDepth: 3,
	}

	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatalf("expected optional fields config to validate, got: %v", err)
	}
}

func TestConfigValidation_RequiredFieldsInJSON(t *testing.T) {
	invalid := map[string]any{
		"network": map[string]any{
			"allowedDomains": []string{},
			// deniedDomains missing
		},
		"filesystem": map[string]any{
			"denyRead": []string{},
			// allowWrite/denyWrite missing
		},
	}
	b, _ := json.Marshal(invalid)
	cfg, err := LoadConfigFromString(string(b))
	if err == nil || cfg != nil {
		t.Fatalf("expected required-fields validation error, got cfg=%v err=%v", cfg, err)
	}
}

func TestConfigMergeFrom(t *testing.T) {
	base := DefaultConfig()
	base.Network.AllowedDomains = []string{"example.com"}
	base.Filesystem.AllowWrite = []string{"/tmp"}
	base.Env = map[string]string{"A": "1"}

	other := DefaultConfig()
	other.Network.AllowedDomains = []string{"example.com", "other.com"}
	other.Filesystem.AllowWrite = []string{"/home"}
	other.Env = map[string]string{"B": "2"}
	other.PassthroughEnv = []string{"GOPATH"}
	other.AllowPty = true

	base.MergeFrom(&other)

	if len(base.Network.AllowedDomains) != 2 {
		t.Fatalf("expected 2 allowed domains, got %v", base.Network.AllowedDomains)
	}
	if len(base.Filesystem.AllowWrite) != 2 {
		t.Fatalf("expected 2 write paths, got %v", base.Filesystem.AllowWrite)
	}
	if base.Env["A"] != "1" || base.Env["B"] != "2" {
		t.Fatalf("unexpected env: %v", base.Env)
	}
	if len(base.PassthroughEnv) != 1 || base.PassthroughEnv[0] != "GOPATH" {
		t.Fatalf("unexpected passthrough: %v", base.PassthroughEnv)
	}
	if !base.AllowPty {
		t.Fatalf("expected AllowPty=true")
	}
}

func TestConfigValidation_RipgrepDefaultsToNil(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}
	if cfg.Ripgrep != nil {
		t.Fatalf("expected ripgrep to be nil by default")
	}
}
