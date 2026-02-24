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

func TestConfigValidation_RipgrepDefaultsToNil(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}
	if cfg.Ripgrep != nil {
		t.Fatalf("expected ripgrep to be nil by default")
	}
}
