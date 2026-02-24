package main

import (
	"bufio"
	"context"
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
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

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

	configPath := opts.settings
	if configPath == "" {
		configPath = defaultConfigPath()
	}

	runtimeConfig, err := srt.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}
	if runtimeConfig == nil {
		cfg := srt.DefaultConfig()
		runtimeConfig = &cfg
		srt.Debugf("No valid config found at %s, using default config", configPath)
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
	fmt.Println("srt - Run commands in a sandbox with network and filesystem restrictions")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  srt [options] [command ...]")
	fmt.Println("  srt -c <command>")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -d, --debug                enable debug logging")
	fmt.Println("  -s, --settings <path>      path to config file (default: ~/.srt-settings.json)")
	fmt.Println("  -c <command>               run command string directly")
	fmt.Println("  --control-fd <fd>          read config updates from fd (JSON lines)")
	fmt.Println("  -h, --help                 show help")
}
