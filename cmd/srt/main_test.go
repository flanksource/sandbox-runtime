package main

import (
	"errors"
	"os/exec"
	"testing"
)

func TestParseArgs_CommandMode(t *testing.T) {
	opts, cmd, err := parseArgs([]string{"-d", "-s", "/tmp/cfg.json", "-c", "echo hello"})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if !opts.debug {
		t.Fatalf("expected debug=true")
	}
	if opts.settings != "/tmp/cfg.json" {
		t.Fatalf("unexpected settings path: %q", opts.settings)
	}
	if opts.commandMode != "echo hello" {
		t.Fatalf("unexpected commandMode: %q", opts.commandMode)
	}
	if len(cmd) != 0 {
		t.Fatalf("expected no positional command args, got: %#v", cmd)
	}
}

func TestParseArgs_DefaultMode(t *testing.T) {
	opts, cmd, err := parseArgs([]string{"echo", "hello", "world"})
	if err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	if opts.commandMode != "" {
		t.Fatalf("expected empty commandMode")
	}
	if len(cmd) != 3 || cmd[0] != "echo" || cmd[2] != "world" {
		t.Fatalf("unexpected positional args: %#v", cmd)
	}
}

func TestParseArgs_Errors(t *testing.T) {
	_, _, err := parseArgs([]string{"-s"})
	if err == nil {
		t.Fatalf("expected error for missing -s value")
	}

	_, _, err = parseArgs([]string{"--control-fd", "not-a-number"})
	if err == nil {
		t.Fatalf("expected error for invalid --control-fd value")
	}
}

func TestRunCommand(t *testing.T) {
	if err := runCommand("echo hello >/dev/null"); err != nil {
		t.Fatalf("runCommand failed: %v", err)
	}

	err := runCommand("exit 7")
	if err == nil {
		t.Fatalf("expected non-zero command to fail")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if code, ok := exitCodeFromError(err); !ok || code != 7 {
		t.Fatalf("expected exit code 7, got code=%d ok=%v", code, ok)
	}
}
