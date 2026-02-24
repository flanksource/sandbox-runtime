package srt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type hostNetworkManagerContext struct {
	HTTPProxyPort  int
	SOCKSProxyPort int
	LinuxBridge    *LinuxNetworkBridgeContext
}

type Manager struct {
	mu              sync.RWMutex
	config          *SandboxRuntimeConfig
	httpProxy       *HTTPProxyServer
	socksProxy      *SocksProxyServer
	networkContext  *hostNetworkManagerContext
	ask             SandboxAskCallback
	violations      *SandboxViolationStore
	macLogMonitor   *macOSSandboxLogMonitor
	cleanupOnce     sync.Once
	cleanupStopChan chan struct{} // closed when cleanup signal goroutine should stop
}

func NewManager() *Manager {
	return &Manager{violations: NewSandboxViolationStore()}
}

var SandboxManager = NewManager()

// registerCleanup starts a goroutine (at most once) that listens for
// SIGINT and SIGTERM and calls Reset. This mirrors the JS version's
// process.once('exit'/'SIGINT'/'SIGTERM') cleanup registration.
// The provided context is used as the parent for the cleanup timeout.
func (m *Manager) registerCleanup(ctx context.Context) {
	m.cleanupOnce.Do(func() {
		m.cleanupStopChan = make(chan struct{})
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			select {
			case <-sigCh:
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				if err := m.Reset(cleanupCtx); err != nil {
					Debugf("Cleanup failed in registerCleanup: %v", err)
				}
				cancel()
			case <-m.cleanupStopChan:
			}
			signal.Stop(sigCh)
		}()
	})
}

func (m *Manager) Initialize(ctx context.Context, runtimeConfig SandboxRuntimeConfig, sandboxAskCallback SandboxAskCallback) error {
	if err := runtimeConfig.NormalizeAndValidate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.networkContext != nil {
		return nil
	}

	m.config = &runtimeConfig
	m.ask = sandboxAskCallback

	deps := m.checkDependenciesLocked(nil)
	if len(deps.Errors) > 0 {
		return fmt.Errorf("sandbox dependencies not available: %s", strings.Join(deps.Errors, ", "))
	}

	// Register process-exit cleanup handlers (once per Manager lifetime).
	m.registerCleanup(ctx)

	httpPort := 0
	if runtimeConfig.Network.HTTPProxyPort != nil {
		httpPort = *runtimeConfig.Network.HTTPProxyPort
		Debugf("Using external HTTP proxy on port %d", httpPort)
	} else {
		httpServer, port, err := StartHTTPProxyServer(ctx, HTTPProxyOptions{
			Filter: func(port int, host string) bool {
				return m.filterNetworkRequest(port, host)
			},
			GetMitmSocketPath: func(host string) string {
				return m.getMitmSocketPath(host)
			},
		})
		if err != nil {
			return err
		}
		m.httpProxy = httpServer
		httpPort = port
	}

	socksPort := 0
	if runtimeConfig.Network.SocksProxyPort != nil {
		socksPort = *runtimeConfig.Network.SocksProxyPort
		Debugf("Using external SOCKS proxy on port %d", socksPort)
	} else {
		socksServer, port, err := StartSocksProxyServer(SocksProxyOptions{
			Filter: func(port int, host string) bool {
				return m.filterNetworkRequest(port, host)
			},
		})
		if err != nil {
			if m.httpProxy != nil {
				_ = m.httpProxy.Close(ctx)
				m.httpProxy = nil
			}
			return err
		}
		m.socksProxy = socksServer
		socksPort = port
	}

	var bridge *LinuxNetworkBridgeContext
	if GetPlatform() == PlatformLinux {
		linuxBridge, err := InitializeLinuxNetworkBridge(httpPort, socksPort)
		if err != nil {
			if m.httpProxy != nil {
				_ = m.httpProxy.Close(ctx)
				m.httpProxy = nil
			}
			if m.socksProxy != nil {
				_ = m.socksProxy.Close()
				m.socksProxy = nil
			}
			return err
		}
		bridge = linuxBridge
	}

	m.networkContext = &hostNetworkManagerContext{
		HTTPProxyPort:  httpPort,
		SOCKSProxyPort: socksPort,
		LinuxBridge:    bridge,
	}

	if GetPlatform() == PlatformMacOS && m.macLogMonitor == nil {
		m.macLogMonitor = startMacOSSandboxLogMonitor(func(v SandboxViolationEvent) {
			m.violations.AddViolation(v)
		}, runtimeConfig.IgnoreViolations)
	}

	return nil
}

func (m *Manager) IsSupportedPlatform() bool {
	platform := GetPlatform()
	if platform == PlatformLinux {
		return GetWSLVersion() != "1"
	}
	return platform == PlatformMacOS
}

func (m *Manager) IsSandboxingEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config != nil
}

func (m *Manager) CheckDependencies(ripgrepConfig *RipgrepConfig) SandboxDependencyCheck {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.checkDependenciesLocked(ripgrepConfig)
}

func (m *Manager) checkDependenciesLocked(ripgrepConfig *RipgrepConfig) SandboxDependencyCheck {
	if !m.IsSupportedPlatform() {
		return SandboxDependencyCheck{Errors: []string{"unsupported platform"}, Warnings: []string{}}
	}

	errorsList := []string{}
	warnings := []string{}

	rgToCheck := "rg"
	if ripgrepConfig != nil && strings.TrimSpace(ripgrepConfig.Command) != "" {
		rgToCheck = ripgrepConfig.Command
	} else if m.config != nil && m.config.Ripgrep != nil && strings.TrimSpace(m.config.Ripgrep.Command) != "" {
		rgToCheck = m.config.Ripgrep.Command
	}
	if Which(rgToCheck) == "" {
		errorsList = append(errorsList, fmt.Sprintf("ripgrep (%s) not found", rgToCheck))
	}

	if GetPlatform() == PlatformLinux {
		var seccompCfg *SeccompConfig
		if m.config != nil {
			seccompCfg = m.config.Seccomp
		}
		linuxDeps := CheckLinuxDependencies(seccompCfg)
		errorsList = append(errorsList, linuxDeps.Errors...)
		warnings = append(warnings, linuxDeps.Warnings...)
	}

	return SandboxDependencyCheck{Errors: errorsList, Warnings: warnings}
}

func (m *Manager) GetFsReadConfig() FsReadRestrictionConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config == nil {
		return FsReadRestrictionConfig{DenyOnly: []string{}}
	}

	denyPaths := make([]string, 0, len(m.config.Filesystem.DenyRead))
	for _, p := range m.config.Filesystem.DenyRead {
		stripped := RemoveTrailingGlobSuffix(p)
		if GetPlatform() == PlatformLinux && ContainsGlobChars(stripped) {
			expanded := ExpandGlobPattern(p)
			Debugf("[Sandbox] expanded glob denyRead pattern %q to %d paths on Linux", p, len(expanded))
			denyPaths = append(denyPaths, expanded...)
			continue
		}
		denyPaths = append(denyPaths, stripped)
	}
	return FsReadRestrictionConfig{DenyOnly: uniqueStrings(denyPaths)}
}

func (m *Manager) GetFsWriteConfig() FsWriteRestrictionConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config == nil {
		return FsWriteRestrictionConfig{AllowOnly: GetDefaultWritePaths(), DenyWithinAllow: []string{}}
	}

	allowPaths := make([]string, 0, len(m.config.Filesystem.AllowWrite))
	for _, p := range m.config.Filesystem.AllowWrite {
		stripped := RemoveTrailingGlobSuffix(p)
		if GetPlatform() == PlatformLinux && ContainsGlobChars(stripped) {
			Debugf("[Sandbox] skipping glob allowWrite pattern on Linux: %s", p)
			continue
		}
		allowPaths = append(allowPaths, stripped)
	}

	denyPaths := make([]string, 0, len(m.config.Filesystem.DenyWrite))
	for _, p := range m.config.Filesystem.DenyWrite {
		stripped := RemoveTrailingGlobSuffix(p)
		if GetPlatform() == PlatformLinux && ContainsGlobChars(stripped) {
			Debugf("[Sandbox] skipping glob denyWrite pattern on Linux: %s", p)
			continue
		}
		denyPaths = append(denyPaths, stripped)
	}

	allowOnly := append([]string{}, GetDefaultWritePaths()...)
	allowOnly = append(allowOnly, allowPaths...)

	return FsWriteRestrictionConfig{AllowOnly: allowOnly, DenyWithinAllow: denyPaths}
}

func (m *Manager) GetNetworkRestrictionConfig() NetworkRestrictionConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config == nil {
		return NetworkRestrictionConfig{}
	}
	var allowed []string
	var denied []string
	if len(m.config.Network.AllowedDomains) > 0 {
		allowed = append([]string{}, m.config.Network.AllowedDomains...)
	}
	if len(m.config.Network.DeniedDomains) > 0 {
		denied = append([]string{}, m.config.Network.DeniedDomains...)
	}
	return NetworkRestrictionConfig{
		AllowedHosts: allowed,
		DeniedHosts:  denied,
	}
}

func (m *Manager) GetConfig() *SandboxRuntimeConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config == nil {
		return nil
	}
	copy := *m.config
	return &copy
}

func (m *Manager) UpdateConfig(newConfig SandboxRuntimeConfig) error {
	if err := newConfig.NormalizeAndValidate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = &newConfig

	if GetPlatform() == PlatformMacOS && m.networkContext != nil {
		if m.macLogMonitor != nil {
			m.macLogMonitor.Stop()
		}
		m.macLogMonitor = startMacOSSandboxLogMonitor(func(v SandboxViolationEvent) {
			m.violations.AddViolation(v)
		}, newConfig.IgnoreViolations)
	}

	return nil
}

func (m *Manager) WaitForNetworkInitialization() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.networkContext != nil
}

func (m *Manager) GetProxyPort() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.networkContext == nil {
		return 0
	}
	return m.networkContext.HTTPProxyPort
}

func (m *Manager) GetSocksProxyPort() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.networkContext == nil {
		return 0
	}
	return m.networkContext.SOCKSProxyPort
}

func (m *Manager) GetLinuxHTTPSocketPath() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.networkContext == nil || m.networkContext.LinuxBridge == nil {
		return ""
	}
	return m.networkContext.LinuxBridge.HTTPSocketPath
}

func (m *Manager) GetLinuxSOCKSSocketPath() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.networkContext == nil || m.networkContext.LinuxBridge == nil {
		return ""
	}
	return m.networkContext.LinuxBridge.SOCKSSocketPath
}

// WrapWithSandbox returns a platform-specific wrapped command.
//
// ctx is used to cancel long-running sub-tasks such as the ripgrep mandatory-deny
// scan on Linux.
//
// If customConfig is provided, it is merged onto the manager config (partial override semantics):
// nil slices/pointers in customConfig inherit from base config, while non-nil slices/pointers override.
func (m *Manager) WrapWithSandbox(ctx context.Context, command, binShell string, customConfig *SandboxRuntimeConfig) (string, error) {
	m.mu.RLock()
	cfg := m.config
	mctx := m.networkContext
	m.mu.RUnlock()

	if cfg == nil {
		return "", errors.New("sandbox manager is not initialized")
	}

	active := cfg
	if customConfig != nil {
		if err := customConfig.NormalizeAndValidate(); err != nil {
			return "", err
		}
		merged := mergeRuntimeConfig(cfg, customConfig)
		active = &merged
	}

	expandedDenyRead := make([]string, 0, len(active.Filesystem.DenyRead))
	for _, p := range active.Filesystem.DenyRead {
		stripped := RemoveTrailingGlobSuffix(p)
		if GetPlatform() == PlatformLinux && ContainsGlobChars(stripped) {
			expandedDenyRead = append(expandedDenyRead, ExpandGlobPattern(p)...)
			continue
		}
		expandedDenyRead = append(expandedDenyRead, stripped)
	}
	readConfig := &FsReadRestrictionConfig{DenyOnly: uniqueStrings(expandedDenyRead)}
	writeConfig := &FsWriteRestrictionConfig{
		AllowOnly:       append(append([]string{}, GetDefaultWritePaths()...), active.Filesystem.AllowWrite...),
		DenyWithinAllow: append([]string{}, active.Filesystem.DenyWrite...),
	}

	needsNetworkRestriction := hasNetworkConfig(active)
	needsNetworkProxy := needsNetworkRestriction

	httpProxyPort := 0
	socksProxyPort := 0
	httpSocketPath := ""
	socksSocketPath := ""
	if needsNetworkProxy && mctx != nil {
		httpProxyPort = mctx.HTTPProxyPort
		socksProxyPort = mctx.SOCKSProxyPort
		if mctx.LinuxBridge != nil {
			httpSocketPath = mctx.LinuxBridge.HTTPSocketPath
			socksSocketPath = mctx.LinuxBridge.SOCKSSocketPath
		}
	}

	switch GetPlatform() {
	case PlatformMacOS:
		return WrapCommandWithSandboxMacOS(MacOSSandboxParams{
			Command:                      command,
			NeedsNetworkRestriction:      needsNetworkRestriction,
			HTTPProxyPort:                httpProxyPort,
			SOCKSProxyPort:               socksProxyPort,
			AllowUnixSockets:             active.Network.AllowUnixSockets,
			AllowAllUnixSockets:          active.Network.AllowAllUnixSockets,
			AllowLocalBinding:            active.Network.AllowLocalBinding,
			ReadConfig:                   readConfig,
			WriteConfig:                  writeConfig,
			AllowPty:                     active.AllowPty,
			AllowGitConfig:               active.Filesystem.AllowGitConfig,
			EnableWeakerNetworkIsolation: active.EnableWeakerNetworkIsolation,
			BinShell:                     binShell,
		})
	case PlatformLinux:
		return WrapCommandWithSandboxLinux(ctx, LinuxSandboxParams{
			Command:                   command,
			NeedsNetworkRestriction:   needsNetworkRestriction,
			HTTPSocketPath:            httpSocketPath,
			SOCKSSocketPath:           socksSocketPath,
			HTTPProxyPort:             httpProxyPort,
			SOCKSProxyPort:            socksProxyPort,
			ReadConfig:                readConfig,
			WriteConfig:               writeConfig,
			EnableWeakerNestedSandbox: active.EnableWeakerNestedSandbox,
			AllowAllUnixSockets:       active.Network.AllowAllUnixSockets,
			BinShell:                  binShell,
			AllowGitConfig:            active.Filesystem.AllowGitConfig,
			RipgrepConfig:             active.Ripgrep,
			MandatoryDenySearchDepth:  active.MandatoryDenySearchDepth,
			SeccompConfig:             active.Seccomp,
		})
	default:
		return "", fmt.Errorf("sandbox configuration is not supported on platform: %s", GetPlatform())
	}
}

func (m *Manager) CleanupAfterCommand() {
	CleanupBwrapMountPoints()
}

func (m *Manager) Reset(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	CleanupBwrapMountPoints()

	if m.macLogMonitor != nil {
		m.macLogMonitor.Stop()
		m.macLogMonitor = nil
	}

	if m.networkContext != nil && m.networkContext.LinuxBridge != nil {
		terminateLinuxBridge(m.networkContext.LinuxBridge)
	}

	if m.httpProxy != nil {
		_ = m.httpProxy.Close(ctx)
		m.httpProxy = nil
	}
	if m.socksProxy != nil {
		_ = m.socksProxy.Close()
		m.socksProxy = nil
	}

	// Stop the signal-cleanup goroutine and allow re-registration on the
	// next Initialize call.
	if m.cleanupStopChan != nil {
		close(m.cleanupStopChan)
		m.cleanupStopChan = nil
	}
	m.cleanupOnce = sync.Once{}

	m.networkContext = nil
	m.config = nil
	return nil
}

func (m *Manager) GetSandboxViolationStore() *SandboxViolationStore {
	return m.violations
}

func (m *Manager) AnnotateStderrWithSandboxFailures(command, stderr string) string {
	violations := m.violations.GetViolationsForCommand(command)
	if len(violations) == 0 {
		return stderr
	}
	out := stderr + "\n<sandbox_violations>\n"
	for _, v := range violations {
		out += v.Line + "\n"
	}
	out += "</sandbox_violations>"
	return out
}

func (m *Manager) filterNetworkRequest(port int, host string) bool {
	m.mu.RLock()
	cfg := m.config
	ask := m.ask
	m.mu.RUnlock()

	if cfg == nil {
		return false
	}

	for _, denied := range cfg.Network.DeniedDomains {
		if matchesDomainPattern(host, denied) {
			Debugf("Denied by config rule: %s:%d", host, port)
			return false
		}
	}
	for _, allowed := range cfg.Network.AllowedDomains {
		if matchesDomainPattern(host, allowed) {
			Debugf("Allowed by config rule: %s:%d", host, port)
			return true
		}
	}

	if ask == nil {
		return false
	}
	return ask(NetworkHostPattern{Host: host, Port: port})
}

func (m *Manager) getMitmSocketPath(host string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config == nil || m.config.Network.MitmProxy == nil {
		return ""
	}
	for _, pattern := range m.config.Network.MitmProxy.Domains {
		if matchesDomainPattern(host, pattern) {
			return m.config.Network.MitmProxy.SocketPath
		}
	}
	return ""
}

func mergeRuntimeConfig(base *SandboxRuntimeConfig, override *SandboxRuntimeConfig) SandboxRuntimeConfig {
	if base == nil {
		if override == nil {
			return SandboxRuntimeConfig{}
		}
		copied := *override
		return copied
	}

	merged := *base
	if override == nil {
		return merged
	}

	if override.Network.AllowedDomains != nil {
		merged.Network.AllowedDomains = append([]string{}, override.Network.AllowedDomains...)
	}
	if override.Network.DeniedDomains != nil {
		merged.Network.DeniedDomains = append([]string{}, override.Network.DeniedDomains...)
	}
	if override.Network.AllowUnixSockets != nil {
		merged.Network.AllowUnixSockets = append([]string{}, override.Network.AllowUnixSockets...)
	}
	if override.Network.HTTPProxyPort != nil {
		merged.Network.HTTPProxyPort = override.Network.HTTPProxyPort
	}
	if override.Network.SocksProxyPort != nil {
		merged.Network.SocksProxyPort = override.Network.SocksProxyPort
	}
	if override.Network.MitmProxy != nil {
		copiedDomains := append([]string{}, override.Network.MitmProxy.Domains...)
		merged.Network.MitmProxy = &MitmProxyConfig{SocketPath: override.Network.MitmProxy.SocketPath, Domains: copiedDomains}
	}
	if override.Network.AllowAllUnixSockets {
		merged.Network.AllowAllUnixSockets = true
	}
	if override.Network.AllowLocalBinding {
		merged.Network.AllowLocalBinding = true
	}

	if override.Filesystem.DenyRead != nil {
		merged.Filesystem.DenyRead = append([]string{}, override.Filesystem.DenyRead...)
	}
	if override.Filesystem.AllowWrite != nil {
		merged.Filesystem.AllowWrite = append([]string{}, override.Filesystem.AllowWrite...)
	}
	if override.Filesystem.DenyWrite != nil {
		merged.Filesystem.DenyWrite = append([]string{}, override.Filesystem.DenyWrite...)
	}
	if override.Filesystem.AllowGitConfig {
		merged.Filesystem.AllowGitConfig = true
	}

	if override.IgnoreViolations != nil {
		copiedIgnore := make(map[string][]string, len(override.IgnoreViolations))
		for k, v := range override.IgnoreViolations {
			copiedIgnore[k] = append([]string{}, v...)
		}
		merged.IgnoreViolations = copiedIgnore
	}
	if override.EnableWeakerNestedSandbox {
		merged.EnableWeakerNestedSandbox = true
	}
	if override.EnableWeakerNetworkIsolation {
		merged.EnableWeakerNetworkIsolation = true
	}
	if override.Ripgrep != nil {
		copiedArgs := append([]string{}, override.Ripgrep.Args...)
		merged.Ripgrep = &RipgrepConfig{Command: override.Ripgrep.Command, Args: copiedArgs}
	}
	if override.MandatoryDenySearchDepth != 0 {
		merged.MandatoryDenySearchDepth = override.MandatoryDenySearchDepth
	}
	if override.AllowPty {
		merged.AllowPty = true
	}
	if override.Seccomp != nil {
		merged.Seccomp = &SeccompConfig{BPFPath: override.Seccomp.BPFPath, ApplyPath: override.Seccomp.ApplyPath}
	}

	return merged
}

func hasNetworkConfig(cfg *SandboxRuntimeConfig) bool {
	if cfg == nil {
		return false
	}

	if cfg.Network.AllowedDomains != nil || cfg.Network.DeniedDomains != nil {
		return true
	}
	if cfg.Network.HTTPProxyPort != nil || cfg.Network.SocksProxyPort != nil || cfg.Network.MitmProxy != nil {
		return true
	}
	if cfg.Network.AllowUnixSockets != nil || cfg.Network.AllowAllUnixSockets || cfg.Network.AllowLocalBinding {
		return true
	}

	return false
}

func matchesDomainPattern(hostname, pattern string) bool {
	hostname = strings.ToLower(hostname)
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(hostname, "."+base)
	}
	return hostname == pattern
}
