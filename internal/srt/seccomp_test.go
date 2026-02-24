package srt

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSeccompArtifactResolution(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	arch := runtime.GOARCH
	bpf := GetPreGeneratedBPFPath("")
	apply := GetApplySeccompBinaryPath("")

	if arch == "amd64" || arch == "arm64" {
		if bpf == "" {
			t.Fatalf("expected pre-generated bpf path on %s", arch)
		}
		if apply == "" {
			t.Fatalf("expected apply-seccomp path on %s", arch)
		}
		if !strings.Contains(filepath.ToSlash(bpf), "third_party/seccomp") {
			t.Fatalf("expected bpf path to be in third_party/seccomp, got: %s", bpf)
		}
		if !strings.HasSuffix(bpf, "unix-block.bpf") {
			t.Fatalf("expected unix-block.bpf suffix, got: %s", bpf)
		}
	} else {
		if bpf != "" || apply != "" {
			t.Fatalf("expected no seccomp artifacts on unsupported arch %s, got bpf=%q apply=%q", arch, bpf, apply)
		}
	}
}

func TestCheckLinuxDependenciesShape(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	deps := CheckLinuxDependencies(nil)
	if deps.Errors == nil {
		t.Fatalf("expected non-nil Errors slice")
	}
	if deps.Warnings == nil {
		t.Fatalf("expected non-nil Warnings slice")
	}
}
