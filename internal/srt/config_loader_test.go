package srt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_FileBehaviors(t *testing.T) {
	t.Run("nonexistent file returns nil,nil", func(t *testing.T) {
		cfg, err := LoadConfig(filepath.Join(t.TempDir(), "does-not-exist.json"))
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if cfg != nil {
			t.Fatalf("expected nil config for missing file")
		}
	})

	t.Run("empty file returns nil,nil", func(t *testing.T) {
		tmp := t.TempDir()
		p := filepath.Join(tmp, "config.json")
		if err := os.WriteFile(p, []byte(""), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(p)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if cfg != nil {
			t.Fatalf("expected nil config for empty file")
		}
	})

	t.Run("invalid json returns error", func(t *testing.T) {
		tmp := t.TempDir()
		p := filepath.Join(tmp, "config.json")
		if err := os.WriteFile(p, []byte("{ invalid json }"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(p)
		if err == nil {
			t.Fatalf("expected error for invalid JSON")
		}
		if cfg != nil {
			t.Fatalf("expected nil config on invalid JSON")
		}
	})

	t.Run("valid config file loads", func(t *testing.T) {
		tmp := t.TempDir()
		p := filepath.Join(tmp, "config.json")
		content := `{"network":{"allowedDomains":["example.com"],"deniedDomains":[]},"filesystem":{"denyRead":[],"allowWrite":[],"denyWrite":[]}}`
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(p)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatalf("expected config to load")
		}
		if len(cfg.Network.AllowedDomains) != 1 || cfg.Network.AllowedDomains[0] != "example.com" {
			t.Fatalf("unexpected allowed domains: %#v", cfg.Network.AllowedDomains)
		}
	})
}

func TestLoadConfigFromString(t *testing.T) {
	t.Run("empty string returns nil,nil", func(t *testing.T) {
		cfg, err := LoadConfigFromString("")
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if cfg != nil {
			t.Fatalf("expected nil config")
		}
	})

	t.Run("invalid schema returns error", func(t *testing.T) {
		cfg, err := LoadConfigFromString(`{"network":{}}`)
		if err == nil {
			t.Fatalf("expected schema error")
		}
		if cfg != nil {
			t.Fatalf("expected nil config")
		}
	})

	t.Run("valid json returns config", func(t *testing.T) {
		cfg, err := LoadConfigFromString(`{"network":{"allowedDomains":[],"deniedDomains":[]},"filesystem":{"denyRead":[],"allowWrite":[],"denyWrite":[]}}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatalf("expected non-nil config")
		}
	})
}
