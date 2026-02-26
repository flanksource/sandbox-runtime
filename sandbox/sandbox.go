// Package sandbox provides a minimal SDK for running shell commands
// inside an OS-level sandbox with network and filesystem restrictions.
//
// On Linux, commands are wrapped with bubblewrap (bwrap) for namespace
// isolation. On macOS, commands use sandbox-exec with a generated
// seatbelt profile. Network access is filtered through local HTTP
// and SOCKS5 proxy servers that enforce domain allow/deny lists.
package sandbox

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/flanksource/sandbox-runtime/internal/srt"
)

// AskParams describes a single dynamic network decision request.
type AskParams struct {
	Host string
	Port int
}

// AskCallback is invoked when a host is not matched by allowed/denied config.
// Returning true allows the request; false blocks it.
type AskCallback func(params AskParams) bool

type newOptions struct {
	ask AskCallback
}

// Option configures optional SDK behavior when creating a sandbox.
type Option func(*newOptions)

// WithAskCallback configures a dynamic network policy callback.
func WithAskCallback(callback AskCallback) Option {
	return func(o *newOptions) {
		o.ask = callback
	}
}

type manager interface {
	Initialize(ctx context.Context, runtimeConfig srt.SandboxRuntimeConfig, sandboxAskCallback srt.SandboxAskCallback) error
	WrapWithSandbox(ctx context.Context, command, binShell string, customConfig *srt.SandboxRuntimeConfig) (string, error)
	Reset(ctx context.Context) error
}

var newManager = func() manager {
	return srt.NewManager()
}

// Sandbox manages proxy servers and wraps commands with OS-level isolation.
// It must remain open while sandboxed commands are running, as it maintains
// the proxy servers needed for network filtering.
type Sandbox struct {
	manager manager
}

// New creates and initializes a Sandbox. It starts HTTP and SOCKS5 proxy
// servers for network filtering, and on Linux, sets up socat bridges for
// forwarding traffic into the network namespace.
//
// The provided context controls the lifetime of the proxy servers: when the
// context is cancelled, the servers will shut down gracefully.
//
// Returns an error if the platform is unsupported or required dependencies
// are missing (bwrap, socat, rg on Linux).
func New(ctx context.Context, cfg Config, opts ...Option) (*Sandbox, error) {
	if cfg.Debug {
		os.Setenv("SRT_DEBUG", "1")
	}

	resolved := newOptions{}
	for _, o := range opts {
		o(&resolved)
	}

	var ask srt.SandboxAskCallback
	if resolved.ask != nil {
		ask = func(params srt.NetworkHostPattern) bool {
			return resolved.ask(AskParams{Host: params.Host, Port: params.Port})
		}
	}

	m := newManager()
	if err := m.Initialize(ctx, cfg.toInternal(), ask); err != nil {
		return nil, err
	}

	return &Sandbox{manager: m}, nil
}

// Command returns an *exec.Cmd that will execute name with the given args
// inside the sandbox. The caller has full control over Stdin, Stdout,
// Stderr, and process lifecycle (Start/Wait/Run/Output).
//
// The returned Cmd uses "sh -c <wrapped>" where <wrapped> is the
// platform-specific sandboxed command (bwrap on Linux, sandbox-exec on macOS).
func (s *Sandbox) Command(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellQuote(name))
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	wrapped, err := s.manager.WrapWithSandbox(ctx, strings.Join(parts, " "), "", nil)
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, "sh", "-c", wrapped), nil
}

// shellQuote returns a shell-safe version of s for use in "sh -c" commands.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '/' || r == ':' || r == '@' || r == '=') {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// Close tears down proxy servers, network bridges, and temporary state.
// Any commands still running when Close is called may lose network access.
// The provided context controls the shutdown deadline for proxy servers.
func (s *Sandbox) Close(ctx context.Context) error {
	return s.manager.Reset(ctx)
}
