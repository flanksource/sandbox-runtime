package srt

type Profile struct {
	Allow                        []string            `yaml:"allow,omitempty"`
	Network                      *NetworkConfig      `yaml:"network,omitempty"`
	Filesystem                   *FilesystemConfig   `yaml:"filesystem,omitempty"`
	Env                          map[string]string   `yaml:"env,omitempty"`
	PassthroughEnv               []string            `yaml:"passthroughEnv,omitempty"`
	IgnoreViolations             map[string][]string `yaml:"ignoreViolations,omitempty"`
	EnableWeakerNestedSandbox    bool                `yaml:"enableWeakerNestedSandbox,omitempty"`
	EnableWeakerNetworkIsolation bool                `yaml:"enableWeakerNetworkIsolation,omitempty"`
	AllowPty                     bool                `yaml:"allowPty,omitempty"`
}

func MergeProfiles(profiles ...*Profile) *Profile {
	result := &Profile{}
	for _, p := range profiles {
		if p == nil {
			continue
		}
		result.Allow = mergeStringSlicesDedup(result.Allow, p.Allow)
		result.PassthroughEnv = mergeStringSlicesDedup(result.PassthroughEnv, p.PassthroughEnv)
		result.EnableWeakerNestedSandbox = result.EnableWeakerNestedSandbox || p.EnableWeakerNestedSandbox
		result.EnableWeakerNetworkIsolation = result.EnableWeakerNetworkIsolation || p.EnableWeakerNetworkIsolation
		result.AllowPty = result.AllowPty || p.AllowPty

		if p.Network != nil {
			if result.Network == nil {
				result.Network = &NetworkConfig{}
			}
			result.Network.AllowedDomains = mergeStringSlicesDedup(result.Network.AllowedDomains, p.Network.AllowedDomains)
			result.Network.DeniedDomains = mergeStringSlicesDedup(result.Network.DeniedDomains, p.Network.DeniedDomains)
			result.Network.AllowUnixSockets = mergeStringSlicesDedup(result.Network.AllowUnixSockets, p.Network.AllowUnixSockets)
			result.Network.AllowAllUnixSockets = result.Network.AllowAllUnixSockets || p.Network.AllowAllUnixSockets
			result.Network.AllowLocalBinding = result.Network.AllowLocalBinding || p.Network.AllowLocalBinding
			if p.Network.HTTPProxyPort != nil {
				result.Network.HTTPProxyPort = p.Network.HTTPProxyPort
			}
			if p.Network.SocksProxyPort != nil {
				result.Network.SocksProxyPort = p.Network.SocksProxyPort
			}
			if p.Network.MitmProxy != nil {
				result.Network.MitmProxy = p.Network.MitmProxy
			}
		}

		if p.Filesystem != nil {
			if result.Filesystem == nil {
				result.Filesystem = &FilesystemConfig{}
			}
			result.Filesystem.DenyRead = mergeStringSlicesDedup(result.Filesystem.DenyRead, p.Filesystem.DenyRead)
			result.Filesystem.AllowWrite = mergeStringSlicesDedup(result.Filesystem.AllowWrite, p.Filesystem.AllowWrite)
			result.Filesystem.DenyWrite = mergeStringSlicesDedup(result.Filesystem.DenyWrite, p.Filesystem.DenyWrite)
			result.Filesystem.AllowGitConfig = result.Filesystem.AllowGitConfig || p.Filesystem.AllowGitConfig
		}

		if p.Env != nil {
			if result.Env == nil {
				result.Env = make(map[string]string)
			}
			for k, v := range p.Env {
				result.Env[k] = v
			}
		}

		if p.IgnoreViolations != nil {
			if result.IgnoreViolations == nil {
				result.IgnoreViolations = make(map[string][]string)
			}
			for k, v := range p.IgnoreViolations {
				result.IgnoreViolations[k] = mergeStringSlicesDedup(result.IgnoreViolations[k], v)
			}
		}
	}
	return result
}

func ResolveProfile(p *Profile) (*SandboxRuntimeConfig, error) {
	expanded := &Profile{}
	for _, name := range p.Allow {
		preset, err := GetPreset(name)
		if err != nil {
			return nil, err
		}
		expanded = MergeProfiles(expanded, preset)
	}
	expanded = MergeProfiles(expanded, &Profile{
		Network:                      p.Network,
		Filesystem:                   p.Filesystem,
		Env:                          p.Env,
		PassthroughEnv:               p.PassthroughEnv,
		IgnoreViolations:             p.IgnoreViolations,
		EnableWeakerNestedSandbox:    p.EnableWeakerNestedSandbox,
		EnableWeakerNetworkIsolation: p.EnableWeakerNetworkIsolation,
		AllowPty:                     p.AllowPty,
	})

	cfg := DefaultConfig()
	cfg.EnableWeakerNestedSandbox = expanded.EnableWeakerNestedSandbox
	cfg.EnableWeakerNetworkIsolation = expanded.EnableWeakerNetworkIsolation
	cfg.AllowPty = expanded.AllowPty
	if expanded.Network != nil {
		cfg.Network = *expanded.Network
	}
	if expanded.Filesystem != nil {
		cfg.Filesystem = *expanded.Filesystem
	}
	if expanded.IgnoreViolations != nil {
		cfg.IgnoreViolations = expanded.IgnoreViolations
	}
	if expanded.Env != nil {
		cfg.Env = expanded.Env
	}
	if len(expanded.PassthroughEnv) > 0 {
		cfg.PassthroughEnv = expanded.PassthroughEnv
	}
	return &cfg, nil
}

func mergeStringSlicesDedup(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	result := append([]string{}, a...)
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
