package srt

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type LinuxNetworkBridgeContext struct {
	HTTPSocketPath  string
	SOCKSSocketPath string
	HTTPBridgeCmd   *exec.Cmd
	SOCKSBridgeCmd  *exec.Cmd
	HTTPProxyPort   int
	SOCKSProxyPort  int
}

type LinuxDependencyStatus struct {
	HasBwrap        bool
	HasSocat        bool
	HasSeccompBPF   bool
	HasSeccompApply bool
}

const defaultMandatoryDenySearchDepth = 3

type SandboxDependencyCheck struct {
	Warnings []string
	Errors   []string
}

type LinuxSandboxParams struct {
	Command                   string
	NeedsNetworkRestriction   bool
	HTTPSocketPath            string
	SOCKSSocketPath           string
	HTTPProxyPort             int
	SOCKSProxyPort            int
	ReadConfig                *FsReadRestrictionConfig
	WriteConfig               *FsWriteRestrictionConfig
	EnableWeakerNestedSandbox bool
	AllowAllUnixSockets       bool
	BinShell                  string
	AllowGitConfig            bool
	RipgrepConfig             *RipgrepConfig
	MandatoryDenySearchDepth  int
	SeccompConfig             *SeccompConfig
}

func GetLinuxDependencyStatus(seccompConfig *SeccompConfig) LinuxDependencyStatus {
	var bpfPath, applyPath string
	if seccompConfig != nil {
		bpfPath = seccompConfig.BPFPath
		applyPath = seccompConfig.ApplyPath
	}
	return LinuxDependencyStatus{
		HasBwrap:        Which("bwrap") != "",
		HasSocat:        Which("socat") != "",
		HasSeccompBPF:   GetPreGeneratedBPFPath(bpfPath) != "",
		HasSeccompApply: GetApplySeccompBinaryPath(applyPath) != "",
	}
}

func CheckLinuxDependencies(seccompConfig *SeccompConfig) SandboxDependencyCheck {
	res := SandboxDependencyCheck{Warnings: []string{}, Errors: []string{}}
	if Which("bwrap") == "" {
		res.Errors = append(res.Errors, "bubblewrap (bwrap) not installed")
	}
	if Which("socat") == "" {
		res.Errors = append(res.Errors, "socat not installed")
	}

	var bpfPath, applyPath string
	if seccompConfig != nil {
		bpfPath = seccompConfig.BPFPath
		applyPath = seccompConfig.ApplyPath
	}
	if GetPreGeneratedBPFPath(bpfPath) == "" || GetApplySeccompBinaryPath(applyPath) == "" {
		res.Warnings = append(res.Warnings, "seccomp not available - unix socket access not restricted")
	}
	return res
}

func InitializeLinuxNetworkBridge(httpProxyPort, socksProxyPort int) (*LinuxNetworkBridgeContext, error) {
	socketID := randomHex(8)
	httpSocketPath := filepath.Join(os.TempDir(), "srt-http-"+socketID+".sock")
	socksSocketPath := filepath.Join(os.TempDir(), "srt-socks-"+socketID+".sock")

	httpArgs := []string{
		"UNIX-LISTEN:" + httpSocketPath + ",fork,reuseaddr",
		fmt.Sprintf("TCP:localhost:%d,keepalive,keepidle=10,keepintvl=5,keepcnt=3", httpProxyPort),
	}
	httpCmd := exec.Command("socat", httpArgs...)
	if err := httpCmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start HTTP bridge: %w", err)
	}

	socksArgs := []string{
		"UNIX-LISTEN:" + socksSocketPath + ",fork,reuseaddr",
		fmt.Sprintf("TCP:localhost:%d,keepalive,keepidle=10,keepintvl=5,keepcnt=3", socksProxyPort),
	}
	socksCmd := exec.Command("socat", socksArgs...)
	if err := socksCmd.Start(); err != nil {
		_ = terminateCmd(httpCmd)
		return nil, fmt.Errorf("failed to start SOCKS bridge: %w", err)
	}

	for i := 0; i < 20; i++ {
		if fileExists(httpSocketPath) && fileExists(socksSocketPath) {
			return &LinuxNetworkBridgeContext{
				HTTPSocketPath:  httpSocketPath,
				SOCKSSocketPath: socksSocketPath,
				HTTPBridgeCmd:   httpCmd,
				SOCKSBridgeCmd:  socksCmd,
				HTTPProxyPort:   httpProxyPort,
				SOCKSProxyPort:  socksProxyPort,
			}, nil
		}
		time.Sleep(time.Duration(i+1) * 30 * time.Millisecond)
	}

	_ = terminateCmd(httpCmd)
	_ = terminateCmd(socksCmd)
	return nil, errors.New("failed to create Linux bridge sockets")
}

func buildLinuxSandboxCommand(httpSocketPath, socksSocketPath, userCommand, seccompFilterPath, shellPath, applySeccompPath string) string {
	socatCommands := []string{
		"socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:" + httpSocketPath + " >/dev/null 2>&1 &",
		"socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:" + socksSocketPath + " >/dev/null 2>&1 &",
		"trap \"kill %1 %2 2>/dev/null; exit\" EXIT",
	}

	if seccompFilterPath != "" {
		applyBin := GetApplySeccompBinaryPath(applySeccompPath)
		applyCmd := quoteShellArgs(applyBin, seccompFilterPath, shellPath, "-c", userCommand)
		inner := strings.Join(append(socatCommands, applyCmd), "\n")
		return quoteShellArgs(shellPath, "-c", inner)
	}

	inner := strings.Join(append(socatCommands, "eval "+quoteShellArg(userCommand)), "\n")
	return quoteShellArgs(shellPath, "-c", inner)
}

func linuxGetMandatoryDenyPaths(ctx context.Context, ripgrepConfig *RipgrepConfig, maxDepth int, allowGitConfig bool) []string {
	cwd, err := os.Getwd()
	if err != nil {
		Debugf("[Linux] failed to get cwd for mandatory deny paths: %v", err)
		return []string{}
	}

	if maxDepth <= 0 {
		maxDepth = defaultMandatoryDenySearchDepth
	}

	dangerousDirectories := GetDangerousDirectories()
	denyPaths := make([]string, 0, len(DangerousFiles)+len(dangerousDirectories)+4)

	for _, fileName := range DangerousFiles {
		denyPaths = append(denyPaths, filepath.Join(cwd, fileName))
	}
	for _, dirName := range dangerousDirectories {
		denyPaths = append(denyPaths, filepath.Join(cwd, dirName))
	}

	dotGitPath := filepath.Join(cwd, ".git")
	if stat, err := os.Stat(dotGitPath); err == nil && stat.IsDir() {
		denyPaths = append(denyPaths, filepath.Join(dotGitPath, "hooks"))
		if !allowGitConfig {
			denyPaths = append(denyPaths, filepath.Join(dotGitPath, "config"))
		}
	}

	iglobArgs := make([]string, 0, len(DangerousFiles)*2+len(dangerousDirectories)*2+4)
	for _, fileName := range DangerousFiles {
		iglobArgs = append(iglobArgs, "--iglob", fileName)
	}
	for _, dirName := range dangerousDirectories {
		iglobArgs = append(iglobArgs, "--iglob", "**/"+filepath.ToSlash(dirName)+"/**")
	}
	iglobArgs = append(iglobArgs, "--iglob", "**/.git/hooks/**")
	if !allowGitConfig {
		iglobArgs = append(iglobArgs, "--iglob", "**/.git/config")
	}

	rgArgs := []string{"--files", "--hidden", "--max-depth", strconv.Itoa(maxDepth)}
	rgArgs = append(rgArgs, iglobArgs...)
	rgArgs = append(rgArgs, "-g", "!**/node_modules/**")

	matches, err := ripGrepCtx(ctx, rgArgs, cwd, ripgrepConfig)
	if err != nil {
		Debugf("[Linux] mandatory deny ripgrep scan failed: %v", err)
		return uniqueStrings(denyPaths)
	}

	directoryPatterns := append([]string{}, dangerousDirectories...)
	directoryPatterns = append(directoryPatterns, ".git")

	for _, match := range matches {
		absolutePath := match
		if !filepath.IsAbs(absolutePath) {
			absolutePath = filepath.Join(cwd, absolutePath)
		}
		absolutePath = filepath.Clean(absolutePath)

		pathSegments := strings.Split(filepath.ToSlash(absolutePath), "/")
		foundDirectory := false

		for _, dirPattern := range directoryPatterns {
			dirSegments := strings.Split(filepath.ToSlash(dirPattern), "/")
			dirMatchIndex := indexPathSegmentSequence(pathSegments, dirSegments)
			if dirMatchIndex == -1 {
				continue
			}

			if dirPattern == ".git" {
				gitDir := filepath.FromSlash(strings.Join(pathSegments[:dirMatchIndex+len(dirSegments)], "/"))
				normalizedMatch := filepath.ToSlash(match)
				if strings.Contains(normalizedMatch, ".git/hooks") {
					denyPaths = append(denyPaths, filepath.Join(gitDir, "hooks"))
				} else if strings.Contains(normalizedMatch, ".git/config") {
					denyPaths = append(denyPaths, filepath.Join(gitDir, "config"))
				}
			} else {
				dirPath := filepath.FromSlash(strings.Join(pathSegments[:dirMatchIndex+len(dirSegments)], "/"))
				denyPaths = append(denyPaths, dirPath)
			}
			foundDirectory = true
			break
		}

		if !foundDirectory {
			denyPaths = append(denyPaths, absolutePath)
		}
	}

	return uniqueStrings(denyPaths)
}

func indexPathSegmentSequence(pathSegments []string, wantSegments []string) int {
	if len(pathSegments) == 0 || len(wantSegments) == 0 || len(wantSegments) > len(pathSegments) {
		return -1
	}
	for i := 0; i <= len(pathSegments)-len(wantSegments); i++ {
		matched := true
		for j := range wantSegments {
			if NormalizeCaseForComparison(pathSegments[i+j]) != NormalizeCaseForComparison(wantSegments[j]) {
				matched = false
				break
			}
		}
		if matched {
			return i
		}
	}
	return -1
}

func generateFilesystemArgsLinux(ctx context.Context, readConfig *FsReadRestrictionConfig, writeConfig *FsWriteRestrictionConfig, ripgrepConfig *RipgrepConfig, mandatoryDenySearchDepth int, allowGitConfig bool) []string {
	args := []string{}

	if writeConfig != nil {
		args = append(args, "--ro-bind", "/", "/")
		allowed := map[string]struct{}{}
		for _, p := range writeConfig.AllowOnly {
			norm := NormalizePathForSandbox(RemoveTrailingGlobSuffix(p))
			if ContainsGlobChars(norm) {
				Debugf("[Linux] skipping glob allowWrite path: %s", p)
				continue
			}
			if !fileExistsOrDir(norm) {
				continue
			}

			// bwrap follows symlinks for bind targets. If a configured allow path
			// resolves outside its expected boundary, skip it to avoid broadening
			// write scope unexpectedly.
			resolvedPath, err := filepath.EvalSymlinks(norm)
			if err != nil {
				Debugf("[Linux] skipping write path that could not be resolved: %s", norm)
				continue
			}
			if normalizePathForBoundaryChecks(resolvedPath) != normalizePathForBoundaryChecks(norm) &&
				IsSymlinkOutsideBoundary(norm, resolvedPath) {
				Debugf("[Linux] skipping symlink write path pointing outside expected location: %s -> %s", p, resolvedPath)
				continue
			}

			args = append(args, "--bind", norm, norm)
			allowed[norm] = struct{}{}
		}

		denyPaths := append([]string{}, writeConfig.DenyWithinAllow...)
		denyPaths = append(denyPaths, linuxGetMandatoryDenyPaths(ctx, ripgrepConfig, mandatoryDenySearchDepth, allowGitConfig)...)

		// Collect normalized allowed write paths as a slice for ancestor
		// checking (the map only has normalised paths already).
		allowedWritePaths := make([]string, 0, len(allowed))
		for p := range allowed {
			allowedWritePaths = append(allowedWritePaths, p)
		}

		for _, p := range uniqueStrings(denyPaths) {
			norm := NormalizePathForSandbox(RemoveTrailingGlobSuffix(p))
			if ContainsGlobChars(norm) {
				Debugf("[Linux] skipping glob denyWrite path: %s", p)
				continue
			}

			// Skip /dev/* paths — --dev /dev already handles them.
			if strings.HasPrefix(norm, "/dev/") {
				continue
			}

			// If a deny path traverses an allowed symlink, block writes at the
			// symlink itself. This prevents symlink replacement attacks where the
			// symlink is deleted and replaced with a real directory.
			symlinkInPath := findSymlinkInPath(norm, allowedWritePaths)
			if symlinkInPath != "" {
				args = append(args, "--ro-bind", "/dev/null", symlinkInPath)
				Debugf("[Linux] Mounted /dev/null at symlink %s to prevent symlink replacement attack", symlinkInPath)
				continue
			}

			// --- Handle non-existent deny paths ---
			if !fileExistsOrDir(norm) {
				// If any ancestor component is a regular file the target can
				// never be created (e.g. git worktree .git is a file).
				if hasFileAncestor(norm) {
					Debugf("[Linux] Skipping deny path with file ancestor (cannot create paths under a file): %s", norm)
					continue
				}

				// Walk up to find the deepest existing ancestor.
				ancestor := filepath.Dir(norm)
				for ancestor != "/" && !fileExistsOrDir(ancestor) {
					ancestor = filepath.Dir(ancestor)
				}

				// Only protect if the existing ancestor is within an allowed
				// write path; otherwise the root --ro-bind / / already blocks
				// creation.
				ancestorWithinAllowed := false
				for _, ap := range allowedWritePaths {
					if ancestor == ap || strings.HasPrefix(ancestor, ap+"/") || strings.HasPrefix(norm, ap+"/") {
						ancestorWithinAllowed = true
						break
					}
				}
				if !ancestorWithinAllowed {
					Debugf("[Linux] Skipping non-existent deny path not within allowed paths: %s", norm)
					continue
				}

				firstMissing := findFirstNonExistentComponent(norm)

				if firstMissing != norm {
					// Intermediate component — mount a read-only empty dir so
					// tools that traverse this path still see a directory
					// rather than a file.
					emptyDir, err := os.MkdirTemp("", "srt-empty-")
					if err != nil {
						Debugf("[Linux] failed to create empty temp dir for %s: %v", norm, err)
						continue
					}
					args = append(args, "--ro-bind", emptyDir, firstMissing)
					trackBwrapMountPoint(firstMissing)
					trackBwrapSyntheticSource(emptyDir)
					Debugf("[Linux] Mounted empty dir at %s to block creation of %s", firstMissing, norm)
				} else {
					// Leaf component — mount /dev/null to prevent creation.
					args = append(args, "--ro-bind", "/dev/null", firstMissing)
					trackBwrapMountPoint(firstMissing)
					Debugf("[Linux] Mounted /dev/null at %s to block creation of %s", firstMissing, norm)
				}
				continue
			}

			// --- Existing path: deny writes by binding read-only ---
			if isWithinAnyAllowedPath(norm, allowed) {
				args = append(args, "--ro-bind", norm, norm)
			}
		}
	} else {
		args = append(args, "--bind", "/", "/")
	}

	// Collect read deny paths, including implicit system entries.
	readDenyPaths := []string{}
	if readConfig != nil {
		readDenyPaths = append(readDenyPaths, readConfig.DenyOnly...)
	}

	// Always hide /etc/ssh/ssh_config.d to avoid permission issues with OrbStack.
	// SSH is very strict about config file permissions and ownership, and they can
	// appear wrong inside the sandbox causing "Bad owner or permissions" errors.
	if fileExistsOrDir("/etc/ssh/ssh_config.d") {
		readDenyPaths = append(readDenyPaths, "/etc/ssh/ssh_config.d")
	}

	for _, p := range readDenyPaths {
		norm := NormalizePathForSandbox(RemoveTrailingGlobSuffix(p))
		if !fileExistsOrDir(norm) {
			continue
		}
		st, err := os.Stat(norm)
		if err != nil {
			continue
		}
		if st.IsDir() {
			args = append(args, "--tmpfs", norm)
		} else {
			args = append(args, "--ro-bind", "/dev/null", norm)
		}
	}

	return args
}

func WrapCommandWithSandboxLinux(ctx context.Context, params LinuxSandboxParams) (string, error) {
	hasReadRestrictions := params.ReadConfig != nil && len(params.ReadConfig.DenyOnly) > 0
	hasWriteRestrictions := params.WriteConfig != nil
	if !params.NeedsNetworkRestriction && !hasReadRestrictions && !hasWriteRestrictions {
		return params.Command, nil
	}

	bwrapPath := Which("bwrap")
	if bwrapPath == "" {
		return "", errors.New("bubblewrap (bwrap) not found")
	}

	shellName := params.BinShell
	if shellName == "" {
		shellName = "bash"
	}
	shellPath := Which(shellName)
	if shellPath == "" {
		return "", fmt.Errorf("shell %q not found in PATH", shellName)
	}

	bwrapArgs := []string{"--new-session", "--die-with-parent"}

	var seccompFilterPath string
	var applySeccompPath string
	if !params.AllowAllUnixSockets {
		if params.SeccompConfig != nil {
			seccompFilterPath = GetPreGeneratedBPFPath(params.SeccompConfig.BPFPath)
			applySeccompPath = GetApplySeccompBinaryPath(params.SeccompConfig.ApplyPath)
		} else {
			seccompFilterPath = GetPreGeneratedBPFPath("")
			applySeccompPath = GetApplySeccompBinaryPath("")
		}
		if seccompFilterPath == "" || applySeccompPath == "" {
			seccompFilterPath = ""
			applySeccompPath = ""
		}
	}

	if params.NeedsNetworkRestriction {
		bwrapArgs = append(bwrapArgs, "--unshare-net")
		if params.HTTPSocketPath != "" && params.SOCKSSocketPath != "" {
			if !fileExists(params.HTTPSocketPath) {
				return "", fmt.Errorf("HTTP bridge socket does not exist: %s", params.HTTPSocketPath)
			}
			if !fileExists(params.SOCKSSocketPath) {
				return "", fmt.Errorf("SOCKS bridge socket does not exist: %s", params.SOCKSSocketPath)
			}
			bwrapArgs = append(bwrapArgs,
				"--bind", params.HTTPSocketPath, params.HTTPSocketPath,
				"--bind", params.SOCKSSocketPath, params.SOCKSSocketPath,
			)

			for _, envKV := range GenerateProxyEnvVars(3128, 1080) {
				parts := strings.SplitN(envKV, "=", 2)
				if len(parts) == 2 {
					bwrapArgs = append(bwrapArgs, "--setenv", parts[0], parts[1])
				}
			}
			if params.HTTPProxyPort != 0 {
				bwrapArgs = append(bwrapArgs, "--setenv", "CLAUDE_CODE_HOST_HTTP_PROXY_PORT", itoa(params.HTTPProxyPort))
			}
			if params.SOCKSProxyPort != 0 {
				bwrapArgs = append(bwrapArgs, "--setenv", "CLAUDE_CODE_HOST_SOCKS_PROXY_PORT", itoa(params.SOCKSProxyPort))
			}
		}
	}

	bwrapArgs = append(bwrapArgs, generateFilesystemArgsLinux(
		ctx,
		params.ReadConfig,
		params.WriteConfig,
		params.RipgrepConfig,
		params.MandatoryDenySearchDepth,
		params.AllowGitConfig,
	)...)
	bwrapArgs = append(bwrapArgs, "--dev", "/dev", "--unshare-pid")
	if !params.EnableWeakerNestedSandbox {
		bwrapArgs = append(bwrapArgs, "--proc", "/proc")
	}

	bwrapArgs = append(bwrapArgs, "--", shellPath, "-c")

	if params.NeedsNetworkRestriction && params.HTTPSocketPath != "" && params.SOCKSSocketPath != "" {
		sandboxCommand := buildLinuxSandboxCommand(
			params.HTTPSocketPath,
			params.SOCKSSocketPath,
			params.Command,
			seccompFilterPath,
			shellPath,
			applySeccompPath,
		)
		bwrapArgs = append(bwrapArgs, sandboxCommand)
	} else if seccompFilterPath != "" && applySeccompPath != "" {
		applyCmd := quoteShellArgs(applySeccompPath, seccompFilterPath, shellPath, "-c", params.Command)
		bwrapArgs = append(bwrapArgs, applyCmd)
	} else {
		bwrapArgs = append(bwrapArgs, params.Command)
	}

	wrapped := quoteShellArgs(append([]string{bwrapPath}, bwrapArgs...)...)
	return wrapped, nil
}

// bwrapMountPoints tracks destination paths created on the host by bwrap for
// non-existent deny path blocking.
//
// bwrapSyntheticSources tracks temporary source directories created on the host
// for intermediate non-existent deny path blocking. Both sets must be cleaned
// up after each sandboxed command completes.
var (
	bwrapMountPoints      = map[string]struct{}{}
	bwrapSyntheticSources = map[string]struct{}{}
	bwrapCleanupMu        sync.Mutex
)

// trackBwrapMountPoint records a host path created as a bwrap mount point so
// CleanupBwrapMountPoints can remove it later.
func trackBwrapMountPoint(p string) {
	if p == "" {
		return
	}
	bwrapCleanupMu.Lock()
	bwrapMountPoints[p] = struct{}{}
	bwrapCleanupMu.Unlock()
}

// trackBwrapSyntheticSource records a temporary source directory used for
// read-only synthetic binds.
func trackBwrapSyntheticSource(p string) {
	if p == "" {
		return
	}
	bwrapCleanupMu.Lock()
	bwrapSyntheticSources[p] = struct{}{}
	bwrapCleanupMu.Unlock()
}

// CleanupBwrapMountPoints removes host artefacts created by bwrap for
// non-existent deny path blocking. Only empty files (size == 0) and empty
// directories are removed — if something has written real content the path is
// left alone. Safe to call at any time.
func CleanupBwrapMountPoints() {
	bwrapCleanupMu.Lock()
	mountPoints := make([]string, 0, len(bwrapMountPoints))
	for mp := range bwrapMountPoints {
		mountPoints = append(mountPoints, mp)
	}
	syntheticSources := make([]string, 0, len(bwrapSyntheticSources))
	for src := range bwrapSyntheticSources {
		syntheticSources = append(syntheticSources, src)
	}
	bwrapMountPoints = map[string]struct{}{}
	bwrapSyntheticSources = map[string]struct{}{}
	bwrapCleanupMu.Unlock()

	for _, mp := range mountPoints {
		cleanupBwrapArtifact(mp, "bwrap mount point")
	}
	for _, src := range syntheticSources {
		cleanupBwrapArtifact(src, "bwrap synthetic source")
	}
}

func cleanupBwrapArtifact(path string, label string) {
	info, err := os.Stat(path)
	if err != nil {
		// Already gone — nothing to do.
		return
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err == nil && len(entries) == 0 {
			_ = os.Remove(path)
			Debugf("[Linux] Cleaned up %s (dir): %s", label, path)
		}
		return
	}
	if info.Mode().IsRegular() && info.Size() == 0 {
		_ = os.Remove(path)
		Debugf("[Linux] Cleaned up %s (file): %s", label, path)
	}
}

// findSymlinkInPath checks each existing component of targetPath and returns
// the first symlink path that is also within allowedWritePaths.
func findSymlinkInPath(targetPath string, allowedWritePaths []string) string {
	parts := strings.Split(filepath.ToSlash(targetPath), "/")
	currentPath := ""

	for _, part := range parts {
		if part == "" {
			continue
		}
		nextPath := currentPath + "/" + part
		info, err := os.Lstat(nextPath)
		if err != nil {
			break
		}
		if info.Mode()&os.ModeSymlink != 0 {
			normalizedSymlink := filepath.Clean(filepath.FromSlash(nextPath))
			normalizedSymlinkForCompare := normalizePathForBoundaryChecks(normalizedSymlink)
			for _, allowedPath := range allowedWritePaths {
				normalizedAllowedForCompare := normalizePathForBoundaryChecks(filepath.Clean(allowedPath))
				if hasPathPrefix(normalizedSymlinkForCompare, normalizedAllowedForCompare) {
					return normalizedSymlink
				}
			}
		}
		currentPath = nextPath
	}

	return ""
}

// hasFileAncestor returns true if any existing component of targetPath is a
// regular file (not a directory). When that is the case the target can never be
// created because you cannot mkdir under a file. This handles the git-worktree
// case where .git is a file so .git/hooks can never exist.
func hasFileAncestor(targetPath string) bool {
	parts := strings.Split(filepath.ToSlash(targetPath), "/")
	current := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		next := current + "/" + part
		info, err := os.Stat(next)
		if err != nil {
			break // path doesn't exist — stop checking
		}
		if !info.IsDir() {
			return true
		}
		current = next
	}
	return false
}

// findFirstNonExistentComponent walks targetPath from the root and returns the
// first component that does not exist on disk. For example given
// "/existing/parent/missing/child" where /existing/parent exists it returns
// "/existing/parent/missing".
func findFirstNonExistentComponent(targetPath string) string {
	parts := strings.Split(filepath.ToSlash(targetPath), "/")
	current := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		next := current + "/" + part
		if !fileExistsOrDir(next) {
			return filepath.FromSlash(next)
		}
		current = next
	}
	return targetPath
}

func terminateLinuxBridge(ctx *LinuxNetworkBridgeContext) {
	if ctx == nil {
		return
	}
	_ = terminateCmd(ctx.HTTPBridgeCmd)
	_ = terminateCmd(ctx.SOCKSBridgeCmd)
	if ctx.HTTPSocketPath != "" {
		_ = os.Remove(ctx.HTTPSocketPath)
	}
	if ctx.SOCKSSocketPath != "" {
		_ = os.Remove(ctx.SOCKSSocketPath)
	}
}

func terminateCmd(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		return nil
	case <-done:
		return nil
	}
}

func randomHex(n int) string {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	const hex = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, b := range buf {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

func fileExistsOrDir(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isWithinAnyAllowedPath(path string, allowed map[string]struct{}) bool {
	for base := range allowed {
		if path == base || strings.HasPrefix(path, base+"/") {
			return true
		}
	}
	return false
}
