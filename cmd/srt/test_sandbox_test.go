package main

import (
	"os"
	"testing"
)

func TestRunTestSandbox_MissingGavel(t *testing.T) {
	originalPath := os.Getenv("PATH")
	t.Setenv("PATH", "/nonexistent")
	defer os.Setenv("PATH", originalPath)

	code := runTestSandbox([]string{"some-fixture.md"})
	if code != 1 {
		t.Fatalf("expected exit code 1 when gavel is missing, got %d", code)
	}
}
