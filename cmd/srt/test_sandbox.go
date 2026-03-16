package main

import (
	"fmt"
	"os"
	"os/exec"
)

func runTestSandbox(args []string) int {
	if _, err := exec.LookPath("gavel"); err != nil {
		fmt.Fprintln(os.Stderr, "Error: gavel not found on PATH (install from https://github.com/flanksource/gavel)")
		return 1
	}

	cmd := exec.Command("gavel", append([]string{"fixtures"}, args...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if code, ok := exitCodeFromError(err); ok {
			return code
		}
		return 1
	}
	return 0
}
