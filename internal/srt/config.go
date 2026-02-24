package srt

import (
	"fmt"
	"strings"
)

type MitmProxyConfig struct {
	SocketPath string   `json:"socketPath"`
	Domains    []string `json:"domains"`
}

type NetworkConfig struct {
	AllowedDomains      []string         `json:"allowedDomains"`
	DeniedDomains       []string         `json:"deniedDomains"`
	AllowUnixSockets    []string         `json:"allowUnixSockets,omitempty"`
	AllowAllUnixSockets bool             `json:"allowAllUnixSockets,omitempty"`
	AllowLocalBinding   bool             `json:"allowLocalBinding,omitempty"`
	HTTPProxyPort       *int             `json:"httpProxyPort,omitempty"`
	SocksProxyPort      *int             `json:"socksProxyPort,omitempty"`
	MitmProxy           *MitmProxyConfig `json:"mitmProxy,omitempty"`
}

type FilesystemConfig struct {
	DenyRead       []string `json:"denyRead"`
	AllowWrite     []string `json:"allowWrite"`
	DenyWrite      []string `json:"denyWrite"`
	AllowGitConfig bool     `json:"allowGitConfig,omitempty"`
}

type RipgrepConfig struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

type SeccompConfig struct {
	BPFPath   string `json:"bpfPath,omitempty"`
	ApplyPath string `json:"applyPath,omitempty"`
}

type SandboxRuntimeConfig struct {
	Network                      NetworkConfig       `json:"network"`
	Filesystem                   FilesystemConfig    `json:"filesystem"`
	IgnoreViolations             map[string][]string `json:"ignoreViolations,omitempty"`
	EnableWeakerNestedSandbox    bool                `json:"enableWeakerNestedSandbox,omitempty"`
	EnableWeakerNetworkIsolation bool                `json:"enableWeakerNetworkIsolation,omitempty"`
	Ripgrep                      *RipgrepConfig      `json:"ripgrep,omitempty"`
	MandatoryDenySearchDepth     int                 `json:"mandatoryDenySearchDepth,omitempty"`
	AllowPty                     bool                `json:"allowPty,omitempty"`
	Seccomp                      *SeccompConfig      `json:"seccomp,omitempty"`
}

func DefaultConfig() SandboxRuntimeConfig {
	return SandboxRuntimeConfig{
		Network: NetworkConfig{
			AllowedDomains: []string{},
			DeniedDomains:  []string{},
		},
		Filesystem: FilesystemConfig{
			DenyRead:   []string{},
			AllowWrite: []string{},
			DenyWrite:  []string{},
		},
	}
}

func (c *SandboxRuntimeConfig) NormalizeAndValidate() error {
	for _, d := range c.Network.AllowedDomains {
		if !isValidDomainPattern(d) {
			return fmt.Errorf("invalid allowed domain pattern: %q", d)
		}
	}
	for _, d := range c.Network.DeniedDomains {
		if !isValidDomainPattern(d) {
			return fmt.Errorf("invalid denied domain pattern: %q", d)
		}
	}

	if c.Network.HTTPProxyPort != nil {
		if *c.Network.HTTPProxyPort < 1 || *c.Network.HTTPProxyPort > 65535 {
			return fmt.Errorf("httpProxyPort out of range: %d", *c.Network.HTTPProxyPort)
		}
	}
	if c.Network.SocksProxyPort != nil {
		if *c.Network.SocksProxyPort < 1 || *c.Network.SocksProxyPort > 65535 {
			return fmt.Errorf("socksProxyPort out of range: %d", *c.Network.SocksProxyPort)
		}
	}

	if c.Network.MitmProxy != nil {
		if strings.TrimSpace(c.Network.MitmProxy.SocketPath) == "" {
			return fmt.Errorf("mitmProxy.socketPath cannot be empty")
		}
		if len(c.Network.MitmProxy.Domains) == 0 {
			return fmt.Errorf("mitmProxy.domains cannot be empty")
		}
		for _, d := range c.Network.MitmProxy.Domains {
			if !isValidDomainPattern(d) {
				return fmt.Errorf("invalid mitmProxy domain pattern: %q", d)
			}
		}
	}

	if c.MandatoryDenySearchDepth != 0 {
		if c.MandatoryDenySearchDepth < 1 || c.MandatoryDenySearchDepth > 10 {
			return fmt.Errorf("mandatoryDenySearchDepth must be between 1 and 10")
		}
	}

	if c.Ripgrep != nil {
		if strings.TrimSpace(c.Ripgrep.Command) == "" {
			return fmt.Errorf("ripgrep.command cannot be empty")
		}
	}

	for _, p := range c.Filesystem.DenyRead {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("filesystem.denyRead contains empty path")
		}
	}
	for _, p := range c.Filesystem.AllowWrite {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("filesystem.allowWrite contains empty path")
		}
	}
	for _, p := range c.Filesystem.DenyWrite {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("filesystem.denyWrite contains empty path")
		}
	}

	return nil
}

func isValidDomainPattern(val string) bool {
	if strings.Contains(val, "://") || strings.Contains(val, "/") || strings.Contains(val, ":") {
		return false
	}
	if val == "localhost" {
		return true
	}

	if strings.HasPrefix(val, "*.") {
		domain := strings.TrimPrefix(val, "*.")
		if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
			return false
		}
		parts := strings.Split(domain, ".")
		if len(parts) < 2 {
			return false
		}
		for _, p := range parts {
			if p == "" {
				return false
			}
		}
		return true
	}

	if strings.Contains(val, "*") {
		return false
	}

	return strings.Contains(val, ".") && !strings.HasPrefix(val, ".") && !strings.HasSuffix(val, ".")
}
