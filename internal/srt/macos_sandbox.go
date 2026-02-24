package srt

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type MacOSSandboxParams struct {
	Command                      string
	NeedsNetworkRestriction      bool
	HTTPProxyPort                int
	SOCKSProxyPort               int
	AllowUnixSockets             []string
	AllowAllUnixSockets          bool
	AllowLocalBinding            bool
	ReadConfig                   *FsReadRestrictionConfig
	WriteConfig                  *FsWriteRestrictionConfig
	AllowPty                     bool
	AllowGitConfig               bool
	EnableWeakerNetworkIsolation bool
	BinShell                     string
}

func macMandatoryDenyPatterns(allowGitConfig bool) []string {
	cwd, err := os.Getwd()
	if err != nil {
		Debugf("[macOS] failed to get cwd for mandatory deny patterns: %v", err)
		return []string{}
	}
	deny := make([]string, 0, 16)
	for _, f := range DangerousFiles {
		deny = append(deny, filepath.Join(cwd, f), "**/"+f)
	}
	for _, d := range GetDangerousDirectories() {
		deny = append(deny, filepath.Join(cwd, d), "**/"+d+"/**")
	}
	deny = append(deny, filepath.Join(cwd, ".git", "hooks"), "**/.git/hooks/**")
	if !allowGitConfig {
		deny = append(deny, filepath.Join(cwd, ".git", "config"), "**/.git/config")
	}
	return uniqueStrings(deny)
}

func getAncestorDirectories(pathStr string) []string {
	ancestors := []string{}
	currentPath := filepath.Dir(pathStr)

	for currentPath != "/" && currentPath != "." {
		ancestors = append(ancestors, currentPath)
		parentPath := filepath.Dir(currentPath)
		if parentPath == currentPath {
			break
		}
		currentPath = parentPath
	}

	return ancestors
}

func getTmpdirParentIfMacOSPattern() []string {
	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		return []string{}
	}

	normalizedTmpdir := strings.TrimSuffix(tmpdir, "/")
	macTmpPattern := regexp.MustCompile(`^/(private/)?var/folders/[^/]{2}/[^/]+/T$`)
	if !macTmpPattern.MatchString(normalizedTmpdir) {
		return []string{}
	}

	parent := strings.TrimSuffix(normalizedTmpdir, "/T")
	if strings.HasPrefix(parent, "/private/var/") {
		return uniqueStrings([]string{parent, strings.TrimPrefix(parent, "/private")})
	}
	if strings.HasPrefix(parent, "/var/") {
		return uniqueStrings([]string{parent, "/private" + parent})
	}
	return []string{parent}
}

func generateMoveBlockingRules(pathPatterns []string, logTag string) []string {
	rules := []string{}

	for _, pathPattern := range pathPatterns {
		normalizedPath := NormalizePathForSandbox(pathPattern)

		if ContainsGlobChars(normalizedPath) {
			regexPattern := GlobToRegex(normalizedPath)
			rules = append(rules,
				"(deny file-write-unlink",
				fmt.Sprintf("  (regex %q)", regexPattern),
				fmt.Sprintf("  (with message %q))", logTag),
			)

			staticPrefix := normalizedPath
			if idx := strings.IndexAny(normalizedPath, "*?[]"); idx >= 0 {
				staticPrefix = normalizedPath[:idx]
			}

			if staticPrefix != "" && staticPrefix != "/" {
				baseDir := ""
				if strings.HasSuffix(staticPrefix, "/") {
					baseDir = strings.TrimSuffix(staticPrefix, "/")
				} else {
					baseDir = filepath.Dir(staticPrefix)
				}

				if baseDir != "" {
					rules = append(rules,
						"(deny file-write-unlink",
						fmt.Sprintf("  (literal %q)", baseDir),
						fmt.Sprintf("  (with message %q))", logTag),
					)
					for _, ancestorDir := range getAncestorDirectories(baseDir) {
						rules = append(rules,
							"(deny file-write-unlink",
							fmt.Sprintf("  (literal %q)", ancestorDir),
							fmt.Sprintf("  (with message %q))", logTag),
						)
					}
				}
			}

			continue
		}

		rules = append(rules,
			"(deny file-write-unlink",
			fmt.Sprintf("  (subpath %q)", normalizedPath),
			fmt.Sprintf("  (with message %q))", logTag),
		)

		for _, ancestorDir := range getAncestorDirectories(normalizedPath) {
			rules = append(rules,
				"(deny file-write-unlink",
				fmt.Sprintf("  (literal %q)", ancestorDir),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		}
	}

	return rules
}

func generateMacOSReadRules(config *FsReadRestrictionConfig, logTag string) []string {
	if config == nil {
		return []string{"(allow file-read*)"}
	}

	rules := []string{"(allow file-read*)"}

	for _, pathPattern := range config.DenyOnly {
		normalizedPath := NormalizePathForSandbox(pathPattern)
		if ContainsGlobChars(normalizedPath) {
			rules = append(rules,
				"(deny file-read*",
				fmt.Sprintf("  (regex %q)", GlobToRegex(normalizedPath)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		} else {
			rules = append(rules,
				"(deny file-read*",
				fmt.Sprintf("  (subpath %q)", normalizedPath),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		}
	}

	rules = append(rules, generateMoveBlockingRules(config.DenyOnly, logTag)...)
	return rules
}

func generateMacOSWriteRules(config *FsWriteRestrictionConfig, logTag string, allowGitConfig bool) []string {
	if config == nil {
		return []string{"(allow file-write*)"}
	}

	rules := []string{}

	for _, tmpdirParent := range getTmpdirParentIfMacOSPattern() {
		normalizedPath := NormalizePathForSandbox(tmpdirParent)
		rules = append(rules,
			"(allow file-write*",
			fmt.Sprintf("  (subpath %q)", normalizedPath),
			fmt.Sprintf("  (with message %q))", logTag),
		)
	}

	for _, pathPattern := range config.AllowOnly {
		normalizedPath := NormalizePathForSandbox(pathPattern)
		if ContainsGlobChars(normalizedPath) {
			rules = append(rules,
				"(allow file-write*",
				fmt.Sprintf("  (regex %q)", GlobToRegex(normalizedPath)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		} else {
			rules = append(rules,
				"(allow file-write*",
				fmt.Sprintf("  (subpath %q)", normalizedPath),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		}
	}

	denyPaths := append([]string{}, config.DenyWithinAllow...)
	denyPaths = append(denyPaths, macMandatoryDenyPatterns(allowGitConfig)...)

	for _, pathPattern := range denyPaths {
		normalizedPath := NormalizePathForSandbox(pathPattern)
		if ContainsGlobChars(normalizedPath) {
			rules = append(rules,
				"(deny file-write*",
				fmt.Sprintf("  (regex %q)", GlobToRegex(normalizedPath)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		} else {
			rules = append(rules,
				"(deny file-write*",
				fmt.Sprintf("  (subpath %q)", normalizedPath),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		}
	}

	rules = append(rules, generateMoveBlockingRules(denyPaths, logTag)...)
	return rules
}

func generateMacOSBaseProfile(logTag string, enableWeakerNetworkIsolation bool) []string {
	lines := []string{
		`(version 1)`,
		fmt.Sprintf(`(deny default (with message %q))`, logTag),
		``,
		`; LogTag: ` + logTag,
		``,
		`; Essential permissions - based on Chrome sandbox policy`,
		`; Process permissions`,
		`(allow process-exec)`,
		`(allow process-fork)`,
		`(allow process-info* (target same-sandbox))`,
		`(allow signal (target same-sandbox))`,
		`(allow mach-priv-task-port (target same-sandbox))`,
		``,
		`; User preferences`,
		`(allow user-preference-read)`,
		``,
		`; Mach IPC - specific services only (no wildcard)`,
		`(allow mach-lookup`,
		`  (global-name "com.apple.audio.systemsoundserver")`,
		`  (global-name "com.apple.distributed_notifications@Uv3")`,
		`  (global-name "com.apple.FontObjectsServer")`,
		`  (global-name "com.apple.fonts")`,
		`  (global-name "com.apple.logd")`,
		`  (global-name "com.apple.lsd.mapdb")`,
		`  (global-name "com.apple.PowerManagement.control")`,
		`  (global-name "com.apple.system.logger")`,
		`  (global-name "com.apple.system.notification_center")`,
		`  (global-name "com.apple.system.opendirectoryd.libinfo")`,
		`  (global-name "com.apple.system.opendirectoryd.membership")`,
		`  (global-name "com.apple.bsd.dirhelper")`,
		`  (global-name "com.apple.securityd.xpc")`,
		`  (global-name "com.apple.coreservices.launchservicesd")`,
		`)`,
		``,
	}

	if enableWeakerNetworkIsolation {
		lines = append(lines,
			`; trustd.agent - needed for Go TLS certificate verification (weaker network isolation)`,
			`(allow mach-lookup (global-name "com.apple.trustd.agent"))`,
		)
	}

	lines = append(lines, ``)

	lines = append(lines,
		`; POSIX IPC - shared memory`,
		`(allow ipc-posix-shm)`,
		``,
		`; POSIX IPC - semaphores for Python multiprocessing`,
		`(allow ipc-posix-sem)`,
		``,
		`; IOKit - specific operations only`,
		`(allow iokit-open`,
		`  (iokit-registry-entry-class "IOSurfaceRootUserClient")`,
		`  (iokit-registry-entry-class "RootDomainUserClient")`,
		`  (iokit-user-client-class "IOSurfaceSendRight")`,
		`)`,
		``,
		`; IOKit properties`,
		`(allow iokit-get-properties)`,
		``,
		`; Specific safe system-sockets, doesn't allow network access`,
		`(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))`,
		``,
		`; sysctl - specific sysctls only`,
		`(allow sysctl-read`,
		`  (sysctl-name "hw.activecpu")`,
		`  (sysctl-name "hw.busfrequency_compat")`,
		`  (sysctl-name "hw.byteorder")`,
		`  (sysctl-name "hw.cacheconfig")`,
		`  (sysctl-name "hw.cachelinesize_compat")`,
		`  (sysctl-name "hw.cpufamily")`,
		`  (sysctl-name "hw.cpufrequency")`,
		`  (sysctl-name "hw.cpufrequency_compat")`,
		`  (sysctl-name "hw.cputype")`,
		`  (sysctl-name "hw.l1dcachesize_compat")`,
		`  (sysctl-name "hw.l1icachesize_compat")`,
		`  (sysctl-name "hw.l2cachesize_compat")`,
		`  (sysctl-name "hw.l3cachesize_compat")`,
		`  (sysctl-name "hw.logicalcpu")`,
		`  (sysctl-name "hw.logicalcpu_max")`,
		`  (sysctl-name "hw.machine")`,
		`  (sysctl-name "hw.memsize")`,
		`  (sysctl-name "hw.ncpu")`,
		`  (sysctl-name "hw.nperflevels")`,
		`  (sysctl-name "hw.packages")`,
		`  (sysctl-name "hw.pagesize_compat")`,
		`  (sysctl-name "hw.pagesize")`,
		`  (sysctl-name "hw.physicalcpu")`,
		`  (sysctl-name "hw.physicalcpu_max")`,
		`  (sysctl-name "hw.tbfrequency_compat")`,
		`  (sysctl-name "hw.vectorunit")`,
		`  (sysctl-name "kern.argmax")`,
		`  (sysctl-name "kern.bootargs")`,
		`  (sysctl-name "kern.hostname")`,
		`  (sysctl-name "kern.maxfiles")`,
		`  (sysctl-name "kern.maxfilesperproc")`,
		`  (sysctl-name "kern.maxproc")`,
		`  (sysctl-name "kern.ngroups")`,
		`  (sysctl-name "kern.osproductversion")`,
		`  (sysctl-name "kern.osrelease")`,
		`  (sysctl-name "kern.ostype")`,
		`  (sysctl-name "kern.osvariant_status")`,
		`  (sysctl-name "kern.osversion")`,
		`  (sysctl-name "kern.secure_kernel")`,
		`  (sysctl-name "kern.tcsm_available")`,
		`  (sysctl-name "kern.tcsm_enable")`,
		`  (sysctl-name "kern.usrstack64")`,
		`  (sysctl-name "kern.version")`,
		`  (sysctl-name "kern.willshutdown")`,
		`  (sysctl-name "machdep.cpu.brand_string")`,
		`  (sysctl-name "machdep.ptrauth_enabled")`,
		`  (sysctl-name "security.mac.lockdown_mode_state")`,
		`  (sysctl-name "sysctl.proc_cputype")`,
		`  (sysctl-name "vm.loadavg")`,
		`  (sysctl-name-prefix "hw.optional.arm")`,
		`  (sysctl-name-prefix "hw.optional.arm.")`,
		`  (sysctl-name-prefix "hw.optional.armv8_")`,
		`  (sysctl-name-prefix "hw.perflevel")`,
		`  (sysctl-name-prefix "kern.proc.all")`,
		`  (sysctl-name-prefix "kern.proc.pgrp.")`,
		`  (sysctl-name-prefix "kern.proc.pid.")`,
		`  (sysctl-name-prefix "machdep.cpu.")`,
		`  (sysctl-name-prefix "net.routetable.")`,
		`)`,
		``,
		`; V8 thread calculations`,
		`(allow sysctl-write`,
		`  (sysctl-name "kern.tcsm_enable")`,
		`)`,
		``,
		`; Distributed notifications`,
		`(allow distributed-notification-post)`,
		``,
		`; Specific mach-lookup permissions for security operations`,
		`(allow mach-lookup (global-name "com.apple.SecurityServer"))`,
		``,
		`; File I/O on device files`,
		`(allow file-ioctl (literal "/dev/null"))`,
		`(allow file-ioctl (literal "/dev/zero"))`,
		`(allow file-ioctl (literal "/dev/random"))`,
		`(allow file-ioctl (literal "/dev/urandom"))`,
		`(allow file-ioctl (literal "/dev/dtracehelper"))`,
		`(allow file-ioctl (literal "/dev/tty"))`,
		``,
		`(allow file-ioctl file-read-data file-write-data`,
		`  (require-all`,
		`    (literal "/dev/null")`,
		`    (vnode-type CHARACTER-DEVICE)`,
		`  )`,
		`)`,
		``,
	)

	return lines
}

func WrapCommandWithSandboxMacOS(params MacOSSandboxParams) (string, error) {
	hasReadRestrictions := params.ReadConfig != nil && len(params.ReadConfig.DenyOnly) > 0
	hasWriteRestrictions := params.WriteConfig != nil
	if !params.NeedsNetworkRestriction && !hasReadRestrictions && !hasWriteRestrictions {
		return params.Command, nil
	}

	shellName := params.BinShell
	if shellName == "" {
		shellName = "bash"
	}
	shellPath := Which(shellName)
	if shellPath == "" {
		return "", fmt.Errorf("shell %q not found in PATH", shellName)
	}

	logTag := generateMacOSSandboxLogTag(params.Command)
	profile := generateMacOSSandboxProfile(params, logTag)

	proxyEnv := GenerateProxyEnvVars(params.HTTPProxyPort, params.SOCKSProxyPort)
	args := []string{"env"}
	args = append(args, proxyEnv...)
	args = append(args, "sandbox-exec", "-p", profile, shellPath, "-c", params.Command)

	return quoteShellArgs(args...), nil
}

func generateMacOSSandboxProfile(params MacOSSandboxParams, logTag string) string {
	lines := generateMacOSBaseProfile(logTag, params.EnableWeakerNetworkIsolation)

	lines = append(lines, "; Network")
	if !params.NeedsNetworkRestriction {
		lines = append(lines, "(allow network*)")
	} else {
		if params.AllowLocalBinding {
			lines = append(lines,
				"(allow network-bind (local ip \"*:*\"))",
				"(allow network-inbound (local ip \"*:*\"))",
				"(allow network-outbound (local ip \"*:*\"))",
			)
		}

		if params.AllowAllUnixSockets {
			lines = append(lines,
				"(allow system-socket (socket-domain AF_UNIX))",
				"(allow network-bind (local unix-socket (path-regex #\"^/\")))",
				"(allow network-outbound (remote unix-socket (path-regex #\"^/\")))",
			)
		} else if len(params.AllowUnixSockets) > 0 {
			lines = append(lines, "(allow system-socket (socket-domain AF_UNIX))")
			for _, p := range params.AllowUnixSockets {
				norm := NormalizePathForSandbox(p)
				lines = append(lines,
					fmt.Sprintf("(allow network-bind (local unix-socket (subpath %q)))", norm),
					fmt.Sprintf("(allow network-outbound (remote unix-socket (subpath %q)))", norm),
				)
			}
		}

		if params.HTTPProxyPort != 0 {
			lines = append(lines,
				fmt.Sprintf("(allow network-bind (local ip \"localhost:%d\"))", params.HTTPProxyPort),
				fmt.Sprintf("(allow network-inbound (local ip \"localhost:%d\"))", params.HTTPProxyPort),
				fmt.Sprintf("(allow network-outbound (remote ip \"localhost:%d\"))", params.HTTPProxyPort),
			)
		}
		if params.SOCKSProxyPort != 0 {
			lines = append(lines,
				fmt.Sprintf("(allow network-bind (local ip \"localhost:%d\"))", params.SOCKSProxyPort),
				fmt.Sprintf("(allow network-inbound (local ip \"localhost:%d\"))", params.SOCKSProxyPort),
				fmt.Sprintf("(allow network-outbound (remote ip \"localhost:%d\"))", params.SOCKSProxyPort),
			)
		}
	}

	lines = append(lines, "", "; File read")
	lines = append(lines, generateMacOSReadRules(params.ReadConfig, logTag)...)

	lines = append(lines, "", "; File write")
	lines = append(lines, generateMacOSWriteRules(params.WriteConfig, logTag, params.AllowGitConfig)...)

	if params.AllowPty {
		lines = append(lines,
			"",
			"; Pseudo-terminal (pty) support",
			"(allow pseudo-tty)",
			"(allow file-ioctl",
			"  (literal \"/dev/ptmx\")",
			"  (regex #\"^/dev/ttys\")",
			")",
			"(allow file-read* file-write*",
			"  (literal \"/dev/ptmx\")",
			"  (regex #\"^/dev/ttys\")",
			")",
		)
	}

	return strings.Join(lines, "\n")
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
