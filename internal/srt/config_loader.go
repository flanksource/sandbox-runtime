package srt

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func LoadConfigFromString(content string) (*SandboxRuntimeConfig, error) {
	if strings.TrimSpace(content) == "" {
		return nil, nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return nil, err
	}

	if err := validateRequiredConfigFields(raw); err != nil {
		return nil, err
	}

	var cfg SandboxRuntimeConfig
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, err
	}
	if err := cfg.NormalizeAndValidate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func LoadConfig(filePath string) (*SandboxRuntimeConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read config %s: %w", filePath, err)
	}

	if strings.TrimSpace(string(data)) == "" {
		return nil, nil
	}

	cfg, err := LoadConfigFromString(string(data))
	if err != nil {
		return nil, fmt.Errorf("invalid config in %s: %w", filePath, err)
	}
	return cfg, nil
}

func validateRequiredConfigFields(raw map[string]json.RawMessage) error {
	if _, ok := raw["network"]; !ok {
		return fmt.Errorf("missing required field: network")
	}
	if _, ok := raw["filesystem"]; !ok {
		return fmt.Errorf("missing required field: filesystem")
	}

	var network map[string]json.RawMessage
	if err := json.Unmarshal(raw["network"], &network); err != nil {
		return fmt.Errorf("invalid network section: %w", err)
	}
	if _, ok := network["allowedDomains"]; !ok {
		return fmt.Errorf("missing required field: network.allowedDomains")
	}
	if _, ok := network["deniedDomains"]; !ok {
		return fmt.Errorf("missing required field: network.deniedDomains")
	}

	var filesystem map[string]json.RawMessage
	if err := json.Unmarshal(raw["filesystem"], &filesystem); err != nil {
		return fmt.Errorf("invalid filesystem section: %w", err)
	}
	if _, ok := filesystem["denyRead"]; !ok {
		return fmt.Errorf("missing required field: filesystem.denyRead")
	}
	if _, ok := filesystem["allowWrite"]; !ok {
		return fmt.Errorf("missing required field: filesystem.allowWrite")
	}
	if _, ok := filesystem["denyWrite"]; !ok {
		return fmt.Errorf("missing required field: filesystem.denyWrite")
	}

	return nil
}
