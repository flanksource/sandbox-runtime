package srt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const ripgrepTimeout = 10 * time.Second

func ripGrepCtx(parent context.Context, args []string, target string, config *RipgrepConfig) ([]string, error) {
	command := "rg"
	commandArgs := []string{}
	if config != nil {
		if strings.TrimSpace(config.Command) != "" {
			command = config.Command
		}
		if len(config.Args) > 0 {
			commandArgs = append(commandArgs, config.Args...)
		}
	}

	fullArgs := make([]string, 0, len(commandArgs)+len(args)+1)
	fullArgs = append(fullArgs, commandArgs...)
	fullArgs = append(fullArgs, args...)
	fullArgs = append(fullArgs, target)

	ctx, cancel := context.WithTimeout(parent, ripgrepTimeout)
	defer cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, command, fullArgs...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		return splitNonEmptyLines(stdout.String()), nil
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("ripgrep timed out after %s", ripgrepTimeout)
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() == 1 {
			return []string{}, nil
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("ripgrep failed with exit code %d: %s", exitErr.ExitCode(), msg)
	}

	return nil, fmt.Errorf("failed to execute ripgrep: %w", err)
}

func splitNonEmptyLines(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
