package srt

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

var macOSLogSessionSuffix = fmt.Sprintf("_%s_SBX", randomHex(5))

var (
	macOSCommandExtractRegex = regexp.MustCompile(`CMD64_(.+?)_END`)
	macOSSandboxExtractRegex = regexp.MustCompile(`Sandbox:\s+(.+)$`)
)

func generateMacOSSandboxLogTag(command string) string {
	return fmt.Sprintf("CMD64_%s_END%s", EncodeSandboxedCommand(command), macOSLogSessionSuffix)
}

type macOSSandboxLogMonitor struct {
	cmd      *exec.Cmd
	done     chan struct{}
	stopOnce sync.Once
}

func startMacOSSandboxLogMonitor(callback func(SandboxViolationEvent), ignore map[string][]string) *macOSSandboxLogMonitor {
	if callback == nil {
		return nil
	}

	predicate := fmt.Sprintf("(eventMessage ENDSWITH %q)", macOSLogSessionSuffix)
	cmd := exec.Command("log", "stream", "--predicate", predicate, "--style", "compact")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		Debugf("[Sandbox Monitor] failed to get log stream stdout: %v", err)
		return nil
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		Debugf("[Sandbox Monitor] failed to get log stream stderr: %v", err)
		return nil
	}
	if err := cmd.Start(); err != nil {
		Debugf("[Sandbox Monitor] failed to start log stream: %v", err)
		return nil
	}

	monitor := &macOSSandboxLogMonitor{cmd: cmd, done: make(chan struct{})}

	go monitor.consumeLog(stdout, callback, ignore)
	go monitor.consumeStderr(stderr)
	go func() {
		err := cmd.Wait()
		if err != nil {
			Debugf("[Sandbox Monitor] log stream exited with error: %v", err)
		}
		close(monitor.done)
	}()

	return monitor
}

func (m *macOSSandboxLogMonitor) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		if m.cmd == nil || m.cmd.Process == nil {
			return
		}
		_ = m.cmd.Process.Signal(os.Interrupt)
		select {
		case <-m.done:
		case <-time.After(2 * time.Second):
			_ = m.cmd.Process.Kill()
			select {
			case <-m.done:
			case <-time.After(1 * time.Second):
			}
		}
	})
}

func (m *macOSSandboxLogMonitor) consumeLog(r io.Reader, callback func(SandboxViolationEvent), ignore map[string][]string) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	pendingCommandLine := ""
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		hasSandboxDeny := strings.Contains(line, "Sandbox:") && strings.Contains(line, "deny")
		hasCommandTag := macOSCommandExtractRegex.MatchString(trimmed)

		if hasCommandTag && !hasSandboxDeny {
			pendingCommandLine = trimmed
			continue
		}

		chunk := line
		if hasSandboxDeny && pendingCommandLine != "" {
			chunk = pendingCommandLine + "\n" + line
		}

		event := parseMacOSSandboxViolationChunk(chunk, ignore)
		if event == nil {
			continue
		}
		callback(*event)
		pendingCommandLine = ""
	}

	if err := scanner.Err(); err != nil {
		Debugf("[Sandbox Monitor] error reading log stream: %v", err)
	}
}

func (m *macOSSandboxLogMonitor) consumeStderr(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 8*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		Debugf("[Sandbox Monitor] log stream stderr: %s", line)
	}
}

func parseMacOSSandboxViolationChunk(chunk string, ignore map[string][]string) *SandboxViolationEvent {
	lines := strings.Split(chunk, "\n")
	violationLine := ""
	commandLine := ""

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if violationLine == "" && strings.Contains(line, "Sandbox:") && strings.Contains(line, "deny") {
			violationLine = line
		}
		if commandLine == "" && strings.HasPrefix(trimmed, "CMD64_") {
			commandLine = trimmed
		}
	}
	if commandLine == "" {
		for _, line := range lines {
			if macOSCommandExtractRegex.MatchString(line) {
				commandLine = line
				break
			}
		}
	}

	if violationLine == "" {
		return nil
	}

	sandboxMatch := macOSSandboxExtractRegex.FindStringSubmatch(violationLine)
	if len(sandboxMatch) < 2 {
		return nil
	}
	violationDetails := sandboxMatch[1]

	if isNoisyMacOSViolation(violationDetails) {
		return nil
	}

	encodedCommand := ""
	if matches := macOSCommandExtractRegex.FindStringSubmatch(commandLine); len(matches) > 1 {
		encodedCommand = matches[1]
	} else if matches := macOSCommandExtractRegex.FindStringSubmatch(violationLine); len(matches) > 1 {
		encodedCommand = matches[1]
	}

	command := ""
	if encodedCommand != "" {
		decodedCommand, err := DecodeSandboxedCommand(encodedCommand)
		if err == nil {
			command = decodedCommand
		}
	}

	if shouldIgnoreMacOSViolation(ignore, command, violationDetails) {
		return nil
	}

	return &SandboxViolationEvent{
		Line:           violationDetails,
		Command:        command,
		EncodedCommand: encodedCommand,
		Timestamp:      time.Now(),
	}
}

func isNoisyMacOSViolation(details string) bool {
	return strings.Contains(details, "mDNSResponder") ||
		strings.Contains(details, "mach-lookup com.apple.diagnosticd") ||
		strings.Contains(details, "mach-lookup com.apple.analyticsd")
}

func shouldIgnoreMacOSViolation(ignore map[string][]string, command string, details string) bool {
	if len(ignore) == 0 || command == "" {
		return false
	}

	if wildcardPaths := ignore["*"]; len(wildcardPaths) > 0 {
		for _, matchPath := range wildcardPaths {
			if matchPath != "" && strings.Contains(details, matchPath) {
				return true
			}
		}
	}

	for commandPattern, paths := range ignore {
		if commandPattern == "*" {
			continue
		}
		if !strings.Contains(command, commandPattern) {
			continue
		}
		for _, matchPath := range paths {
			if matchPath != "" && strings.Contains(details, matchPath) {
				return true
			}
		}
	}

	return false
}
