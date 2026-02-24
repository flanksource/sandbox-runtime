package srt

import (
	"fmt"
	"testing"
)

func TestParseMacOSSandboxViolationChunk_Basic(t *testing.T) {
	command := "echo hello"
	encoded := EncodeSandboxedCommand(command)
	chunk := fmt.Sprintf("CMD64_%s_END%s\n2026-01-01 Sandbox: bash(123) deny file-read-data /etc/passwd", encoded, macOSLogSessionSuffix)

	event := parseMacOSSandboxViolationChunk(chunk, nil)
	if event == nil {
		t.Fatalf("expected violation event")
	}
	if event.Command != command {
		t.Fatalf("expected command %q, got %q", command, event.Command)
	}
	if event.EncodedCommand != encoded {
		t.Fatalf("expected encoded command %q, got %q", encoded, event.EncodedCommand)
	}
	if event.Line == "" {
		t.Fatalf("expected non-empty violation line")
	}
}

func TestParseMacOSSandboxViolationChunk_IgnoresWildcard(t *testing.T) {
	command := "echo hello"
	encoded := EncodeSandboxedCommand(command)
	chunk := fmt.Sprintf("CMD64_%s_END%s\n2026-01-01 Sandbox: bash(123) deny file-read-data /etc/passwd", encoded, macOSLogSessionSuffix)

	event := parseMacOSSandboxViolationChunk(chunk, map[string][]string{
		"*": {"/etc/passwd"},
	})
	if event != nil {
		t.Fatalf("expected violation to be ignored by wildcard rule, got %+v", event)
	}
}

func TestParseMacOSSandboxViolationChunk_IgnoresCommandSpecificRule(t *testing.T) {
	command := "git push origin main"
	encoded := EncodeSandboxedCommand(command)
	chunk := fmt.Sprintf("CMD64_%s_END%s\n2026-01-01 Sandbox: bash(123) deny file-read-data /etc/passwd", encoded, macOSLogSessionSuffix)

	event := parseMacOSSandboxViolationChunk(chunk, map[string][]string{
		"git push": {"/etc/passwd"},
	})
	if event != nil {
		t.Fatalf("expected violation to be ignored by command-specific rule, got %+v", event)
	}
}

func TestParseMacOSSandboxViolationChunk_DoesNotIgnoreWhenCommandMissing(t *testing.T) {
	chunk := "2026-01-01 Sandbox: bash(123) deny file-read-data /etc/passwd"
	event := parseMacOSSandboxViolationChunk(chunk, map[string][]string{
		"*": {"/etc/passwd"},
	})
	if event == nil {
		t.Fatalf("expected violation event when command is missing")
	}
	if event.Command != "" {
		t.Fatalf("expected empty command when command tag missing, got %q", event.Command)
	}
}

func TestParseMacOSSandboxViolationChunk_FiltersNoisyViolations(t *testing.T) {
	chunk := "2026-01-01 Sandbox: mDNSResponder deny mach-lookup com.apple.analyticsd"
	event := parseMacOSSandboxViolationChunk(chunk, nil)
	if event != nil {
		t.Fatalf("expected noisy violation to be filtered")
	}
}
