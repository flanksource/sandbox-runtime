package sandbox

import "github.com/flanksource/sandbox-runtime/internal/srt"

// MitmProxyConfig routes matching domains through an external MITM unix socket.
type MitmProxyConfig struct {
	SocketPath string
	Domains    []string
}

// RipgrepConfig customizes the ripgrep binary/args used for mandatory deny scans.
type RipgrepConfig struct {
	Command string
	Args    []string
}

// SeccompConfig overrides paths to seccomp helper binaries on Linux.
type SeccompConfig struct {
	BPFPath   string
	ApplyPath string
}

// Config describes sandbox restrictions for network and filesystem access.
type Config struct {
	// Network restrictions: domain patterns like "github.com" or "*.docker.io"
	AllowedDomains []string
	DeniedDomains  []string

	// Unix socket controls
	AllowUnixSockets    []string
	AllowAllUnixSockets bool

	// Network behavior toggles
	AllowLocalBinding bool

	// Optional externally-managed proxy ports (when set, SDK will not start internal proxy servers)
	HTTPProxyPort  *int
	SocksProxyPort *int

	// Optional MITM proxy socket routing
	MitmProxy *MitmProxyConfig

	// Filesystem restrictions: absolute paths or ~ prefixed paths
	AllowWrite []string // writable paths (beyond defaults like /tmp/claude, /dev/null)
	DenyWrite  []string // deny within allowed paths
	DenyRead   []string // paths to block reading entirely

	// Allow sandboxed processes to read ~/.gitconfig and related git config paths
	AllowGitConfig bool

	// Ignore violation patterns in monitor output
	IgnoreViolations map[string][]string

	// Runtime behavior toggles
	EnableWeakerNestedSandbox    bool
	EnableWeakerNetworkIsolation bool
	AllowPty                     bool

	// Linux mandatory deny behavior
	MandatoryDenySearchDepth int
	Ripgrep                  *RipgrepConfig
	Seccomp                  *SeccompConfig

	// Enable debug logging to stderr
	Debug bool
}

func (c Config) toInternal() srt.SandboxRuntimeConfig {
	var mitm *srt.MitmProxyConfig
	if c.MitmProxy != nil {
		mitm = &srt.MitmProxyConfig{
			SocketPath: c.MitmProxy.SocketPath,
			Domains:    append([]string{}, c.MitmProxy.Domains...),
		}
	}

	var rg *srt.RipgrepConfig
	if c.Ripgrep != nil {
		rg = &srt.RipgrepConfig{
			Command: c.Ripgrep.Command,
			Args:    append([]string{}, c.Ripgrep.Args...),
		}
	}

	var seccomp *srt.SeccompConfig
	if c.Seccomp != nil {
		seccomp = &srt.SeccompConfig{BPFPath: c.Seccomp.BPFPath, ApplyPath: c.Seccomp.ApplyPath}
	}

	ignore := map[string][]string(nil)
	if c.IgnoreViolations != nil {
		ignore = make(map[string][]string, len(c.IgnoreViolations))
		for k, v := range c.IgnoreViolations {
			ignore[k] = append([]string{}, v...)
		}
	}

	return srt.SandboxRuntimeConfig{
		Network: srt.NetworkConfig{
			AllowedDomains:      append([]string{}, c.AllowedDomains...),
			DeniedDomains:       append([]string{}, c.DeniedDomains...),
			AllowUnixSockets:    append([]string{}, c.AllowUnixSockets...),
			AllowAllUnixSockets: c.AllowAllUnixSockets,
			AllowLocalBinding:   c.AllowLocalBinding,
			HTTPProxyPort:       c.HTTPProxyPort,
			SocksProxyPort:      c.SocksProxyPort,
			MitmProxy:           mitm,
		},
		Filesystem: srt.FilesystemConfig{
			AllowWrite:     append([]string{}, c.AllowWrite...),
			DenyWrite:      append([]string{}, c.DenyWrite...),
			DenyRead:       append([]string{}, c.DenyRead...),
			AllowGitConfig: c.AllowGitConfig,
		},
		IgnoreViolations:             ignore,
		EnableWeakerNestedSandbox:    c.EnableWeakerNestedSandbox,
		EnableWeakerNetworkIsolation: c.EnableWeakerNetworkIsolation,
		AllowPty:                     c.AllowPty,
		MandatoryDenySearchDepth:     c.MandatoryDenySearchDepth,
		Ripgrep:                      rg,
		Seccomp:                      seccomp,
	}
}
