package sandbox

import "github.com/flanksource/sandbox-runtime/internal/srt"

// Config describes sandbox restrictions for network and filesystem access.
// It is an alias for the internal SandboxRuntimeConfig, so it shares the same
// JSON structure as the srt CLI config file (~/.srt-settings.json).
type Config = srt.SandboxRuntimeConfig

// NetworkConfig holds domain and socket-level network restrictions.
type NetworkConfig = srt.NetworkConfig

// FilesystemConfig holds path-level read/write restrictions.
type FilesystemConfig = srt.FilesystemConfig

// MitmProxyConfig routes matching domains through an external MITM unix socket.
type MitmProxyConfig = srt.MitmProxyConfig

// RipgrepConfig customizes the ripgrep binary/args used for mandatory deny scans.
type RipgrepConfig = srt.RipgrepConfig

// SeccompConfig overrides paths to seccomp helper binaries on Linux.
type SeccompConfig = srt.SeccompConfig
