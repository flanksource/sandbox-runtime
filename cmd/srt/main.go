package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/flanksource/sandbox-runtime/internal/srt"
)

type options struct {
	debug       bool
	settings    string
	commandMode string
	controlFD   int
	hasControl  bool
	help        bool
	presets     []string
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if len(os.Args) > 1 && os.Args[1] == "test-sandbox" {
		os.Exit(runTestSandbox(os.Args[2:]))
	}

	if len(os.Args) > 1 && os.Args[1] == "profile" {
		os.Exit(runProfile(os.Args[2:]))
	}

	opts, commandArgs, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if opts.help {
		printHelp()
		return
	}

	if opts.debug {
		_ = os.Setenv("SRT_DEBUG", "1")
	}

	var runtimeConfig *srt.SandboxRuntimeConfig

	if opts.settings != "" {
		srt.Debugf("Loading config from: %s", opts.settings)
		runtimeConfig, err = srt.LoadConfig(opts.settings)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
	} else {
		cwd, _ := os.Getwd()
		runtimeConfig, err = srt.LoadProfiles(cwd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: loading profiles: %v\n", err)
		}
		if runtimeConfig == nil {
			runtimeConfig, err = srt.LoadConfig(defaultConfigPath())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			}
		}
	}

	if len(opts.presets) > 0 {
		presetConfig, err := srt.ResolveProfile(&srt.Profile{Allow: opts.presets})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving presets: %v\n", err)
			os.Exit(1)
		}
		if runtimeConfig != nil {
			runtimeConfig.MergeFrom(presetConfig)
		} else {
			runtimeConfig = presetConfig
		}
	}

	if runtimeConfig == nil {
		cfg := srt.DefaultConfig()
		runtimeConfig = &cfg
		srt.Debugf("No valid config found, using default config")
	}

	if data, err := json.MarshalIndent(runtimeConfig, "", "  "); err == nil {
		srt.Debugf("Resolved config:\n%s", string(data))
	}

	if err := srt.SandboxManager.Initialize(ctx, *runtimeConfig, nil); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if opts.hasControl {
		startControlFDReader(opts.controlFD)
	}

	command := ""
	if opts.commandMode != "" {
		command = opts.commandMode
		srt.Debugf("Command string mode (-c): %s", command)
	} else if len(commandArgs) > 0 {
		command = strings.Join(commandArgs, " ")
		srt.Debugf("Original command: %s", command)
	} else {
		fmt.Fprintln(os.Stderr, "Error: No command specified. Use -c <command> or provide command arguments.")
		os.Exit(1)
	}

	sandboxedCommand, err := srt.SandboxManager.WrapWithSandbox(ctx, command, "", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if err := runCommand(sandboxedCommand); err != nil {
		if exitCode, ok := exitCodeFromError(err); ok {
			srt.SandboxManager.CleanupAfterCommand()
			os.Exit(exitCode)
		}
		fmt.Fprintln(os.Stderr, "Failed to execute command:", err)
		os.Exit(1)
	}

	srt.SandboxManager.CleanupAfterCommand()
}

func runCommand(command string) error {
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	return cmd.Wait()
}

func exitCodeFromError(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return 0, false
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
		if ws.Signaled() {
			sig := ws.Signal()
			if sig == syscall.SIGINT || sig == syscall.SIGTERM {
				return 0, true
			}
			return 1, true
		}
		if ws.Exited() {
			return ws.ExitStatus(), true
		}
	}
	return 1, true
}

func parseArgs(args []string) (options, []string, error) {
	opts := options{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-h", "--help":
			opts.help = true
			return opts, nil, nil
		case "-d", "--debug":
			opts.debug = true
		case "-s", "--settings":
			i++
			if i >= len(args) {
				return opts, nil, fmt.Errorf("missing value for %s", a)
			}
			opts.settings = args[i]
		case "-c":
			i++
			if i >= len(args) {
				return opts, nil, fmt.Errorf("missing value for -c")
			}
			opts.commandMode = args[i]
		case "-p", "--preset":
			i++
			if i >= len(args) {
				return opts, nil, fmt.Errorf("missing value for %s", a)
			}
			opts.presets = append(opts.presets, args[i])
		case "--control-fd":
			i++
			if i >= len(args) {
				return opts, nil, fmt.Errorf("missing value for --control-fd")
			}
			fd := 0
			if _, err := fmt.Sscanf(args[i], "%d", &fd); err != nil {
				return opts, nil, fmt.Errorf("invalid --control-fd value: %s", args[i])
			}
			opts.controlFD = fd
			opts.hasControl = true
		case "--":
			return opts, args[i+1:], nil
		default:
			return opts, args[i:], nil
		}
	}
	return opts, nil, nil
}

func startControlFDReader(fd int) {
	f := os.NewFile(uintptr(fd), fmt.Sprintf("control-fd-%d", fd))
	if f == nil {
		srt.Debugf("Failed to open control fd %d", fd)
		return
	}
	go func() {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			cfg, err := srt.LoadConfigFromString(line)
			if err != nil {
				srt.Debugf("Invalid config on control fd (ignored): %s (%v)", line, err)
				continue
			}
			if cfg == nil {
				continue
			}
			if err := srt.SandboxManager.UpdateConfig(*cfg); err != nil {
				srt.Debugf("Failed to update config from control fd: %v", err)
				continue
			}
			srt.Debugf("Config updated from control fd")
		}
		if err := scanner.Err(); err != nil {
			srt.Debugf("Control fd error: %v", err)
		}
	}()
}

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".srt-settings.json"
	}
	return filepath.Join(home, ".srt-settings.json")
}

func printHelp() {
	fmt.Print(`srt - Run commands in a sandbox with network and filesystem restrictions

Usage:
  srt [options] [command ...]
  srt -c <command>

Subcommands:
  profile <subcommand>              Manage sandbox profiles and presets
  test-sandbox <fixture-paths...>   Run fixture-based sandbox tests

Options:
  -d, --debug                enable debug logging
  -s, --settings <path>      path to config file (default: ~/.srt-settings.json)
  -c <command>               run command string directly
  -p, --preset <name>        enable a preset (repeatable, e.g. -p golang -p git)
  --control-fd <fd>          read config updates from fd (JSON lines)
  -h, --help                 show help

Profile commands:
  srt profile list           list available presets
  srt profile show <name>    show expanded preset (network, fs, env, passthroughEnv)
  srt profile resolve        show final merged config for cwd (.sandbox.yaml)
  srt profile init           detect project type, suggest .sandbox.yaml

Environment:
  Sandboxed commands receive a clean environment. Host env vars are injected in
  three layers (later layers override):
    1. Default passthrough: TERM, HOME, USER, SHELL, PATH, LANG, EDITOR, XDG_*, etc.
    2. Preset/profile passthroughEnv: e.g. golang passes GOPATH, GOMODCACHE, GOROOT
    3. Explicit env: key=value pairs from presets or .sandbox.yaml override all

Presets:
  golang, npm, nextjs, playwright, python, rust, docker, git, ssh, aws, gcp, azure, homebrew, ide, shell

Full .sandbox.yaml reference:

  # ─── Presets ──────────────────────────────────────────────────────
  # Include built-in presets by name. Each adds network domains,
  # filesystem paths, env vars, and passthroughEnv for its ecosystem.
  allow:
    - golang
    - git

  # ─── Network ─────────────────────────────────────────────────────
  network:
    allowedDomains:                    # domains the sandbox can reach
      - custom-registry.example.com
      - "*.internal.corp"              # wildcard subdomains
    deniedDomains:                     # explicitly blocked (checked first)
      - evil.example.com
    allowUnixSockets:                  # specific unix sockets to allow
      - /var/run/docker.sock
    allowAllUnixSockets: false         # allow ALL unix sockets
    allowLocalBinding: false           # bind to localhost ports
    # httpProxyPort: 8080              # use external HTTP proxy
    # socksProxyPort: 1080             # use external SOCKS proxy
    # mitmProxy:                       # route domains through MITM socket
    #   socketPath: /tmp/mitmproxy.sock
    #   domains: ["api.example.com"]

  # ─── Filesystem ──────────────────────────────────────────────────
  filesystem:
    allowWrite:                        # writable paths (~ and $ENV supported)
      - .                              # current working directory
      - /tmp
      - $HOME/.cache
    denyRead:                          # block reading these paths
      - $HOME/.ssh
      - $HOME/.aws/credentials
    denyWrite:                         # block writing within allowWrite
      - .env
      - "**/.env.local"
    allowGitConfig: false              # allow .git/config access

  # ─── Environment ─────────────────────────────────────────────────
  env:                                 # explicit key=value (overrides passthrough)
    GONOSUMCHECK: "*"
    NODE_TLS_REJECT_UNAUTHORIZED: "0"
  passthroughEnv:                      # host env var names to forward if set
    - MY_CUSTOM_TOKEN
    - DATABASE_URL

  # ─── Violation Handling ──────────────────────────────────────────
  ignoreViolations:                    # suppress violation logs per command
    curl: [network]
    git: [network, filesystem]

  # ─── Runtime Behavior ───────────────────────────────────────────
  allowPty: false                      # pseudo-terminal allocation
  enableWeakerNestedSandbox: false     # needed for docker-in-sandbox
  enableWeakerNetworkIsolation: false  # macOS: allow trustd.agent for Go TLS
`)
}
