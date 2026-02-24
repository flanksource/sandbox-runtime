package sandbox

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/flanksource/sandbox-runtime/internal/srt"
)

type fakeManager struct {
	initCfg   srt.SandboxRuntimeConfig
	initAsk   srt.SandboxAskCallback
	initErr   error
	wrapIn    string
	wrapOut   string
	wrapErr   error
	resetErr  error
	resetCall int
}

func (f *fakeManager) Initialize(_ context.Context, runtimeConfig srt.SandboxRuntimeConfig, sandboxAskCallback srt.SandboxAskCallback) error {
	f.initCfg = runtimeConfig
	f.initAsk = sandboxAskCallback
	return f.initErr
}

func (f *fakeManager) WrapWithSandbox(_ context.Context, command, _ string, _ *srt.SandboxRuntimeConfig) (string, error) {
	f.wrapIn = command
	if f.wrapErr != nil {
		return "", f.wrapErr
	}
	return f.wrapOut, nil
}

func (f *fakeManager) Reset(_ context.Context) error {
	f.resetCall++
	return f.resetErr
}

func TestConfigToInternal_MapsAdvancedFields(t *testing.T) {
	httpPort := 19001
	socksPort := 19002
	cfg := Config{
		AllowedDomains: []string{"example.com"},
		DeniedDomains:  []string{"blocked.com"},
		AllowUnixSockets: []string{
			"/var/run/docker.sock",
		},
		AllowAllUnixSockets: true,
		AllowLocalBinding:   true,
		HTTPProxyPort:       &httpPort,
		SocksProxyPort:      &socksPort,
		MitmProxy: &MitmProxyConfig{
			SocketPath: "/tmp/mitm.sock",
			Domains:    []string{"*.corp.local"},
		},
		AllowWrite:                   []string{"/tmp/project"},
		DenyWrite:                    []string{"/tmp/project/secrets"},
		DenyRead:                     []string{"/etc/shadow"},
		AllowGitConfig:               true,
		IgnoreViolations:             map[string][]string{"macos": []string{"line-1"}},
		EnableWeakerNestedSandbox:    true,
		EnableWeakerNetworkIsolation: true,
		AllowPty:                     true,
		MandatoryDenySearchDepth:     4,
		Ripgrep:                      &RipgrepConfig{Command: "rg", Args: []string{"--hidden"}},
		Seccomp:                      &SeccompConfig{BPFPath: "/opt/seccomp.bpf", ApplyPath: "/opt/apply-seccomp"},
	}

	internal := cfg.toInternal()

	if !reflect.DeepEqual(internal.Network.AllowedDomains, []string{"example.com"}) {
		t.Fatalf("allowed domains mismatch: %#v", internal.Network.AllowedDomains)
	}
	if !reflect.DeepEqual(internal.Network.AllowUnixSockets, []string{"/var/run/docker.sock"}) {
		t.Fatalf("allowUnixSockets mismatch: %#v", internal.Network.AllowUnixSockets)
	}
	if internal.Network.HTTPProxyPort == nil || *internal.Network.HTTPProxyPort != httpPort {
		t.Fatalf("httpProxyPort mismatch: %#v", internal.Network.HTTPProxyPort)
	}
	if internal.Network.MitmProxy == nil || internal.Network.MitmProxy.SocketPath != "/tmp/mitm.sock" {
		t.Fatalf("mitm mapping mismatch: %#v", internal.Network.MitmProxy)
	}
	if !internal.Filesystem.AllowGitConfig {
		t.Fatalf("expected allowGitConfig=true")
	}
	if internal.MandatoryDenySearchDepth != 4 {
		t.Fatalf("mandatory deny depth mismatch: %d", internal.MandatoryDenySearchDepth)
	}
	if internal.Ripgrep == nil || internal.Ripgrep.Command != "rg" {
		t.Fatalf("ripgrep mapping mismatch: %#v", internal.Ripgrep)
	}
	if internal.Seccomp == nil || internal.Seccomp.ApplyPath != "/opt/apply-seccomp" {
		t.Fatalf("seccomp mapping mismatch: %#v", internal.Seccomp)
	}
	if !internal.EnableWeakerNestedSandbox || !internal.EnableWeakerNetworkIsolation || !internal.AllowPty {
		t.Fatalf("runtime toggles not mapped correctly: %+v", internal)
	}
}

func TestNewCommandClose_UsesManagerAndAskCallback(t *testing.T) {
	fm := &fakeManager{wrapOut: "echo wrapped"}
	orig := newManager
	newManager = func() manager { return fm }
	defer func() { newManager = orig }()

	hit := false
	ctx := context.Background()
	sb, err := New(ctx, Config{AllowedDomains: []string{"example.com"}}, WithAskCallback(func(params AskParams) bool {
		hit = true
		return params.Host == "dynamic.example.com" && params.Port == 443
	}))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if fm.initAsk == nil {
		t.Fatalf("expected ask callback to be passed to manager")
	}
	if !fm.initAsk(srt.NetworkHostPattern{Host: "dynamic.example.com", Port: 443}) {
		t.Fatalf("expected callback result to be true")
	}
	if !hit {
		t.Fatalf("expected sdk callback to run")
	}

	cmd, err := sb.Command(ctx, "echo hi")
	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}
	if fm.wrapIn != "echo hi" {
		t.Fatalf("expected wrap input command recorded, got %q", fm.wrapIn)
	}
	if got := cmd.Args; len(got) != 3 || got[0] != "sh" || got[1] != "-c" || got[2] != "echo wrapped" {
		t.Fatalf("unexpected cmd args: %#v", got)
	}

	if err := sb.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if fm.resetCall != 1 {
		t.Fatalf("expected one reset call, got %d", fm.resetCall)
	}
}

func TestNewAndCommandErrorPaths(t *testing.T) {
	orig := newManager
	defer func() { newManager = orig }()

	ctx := context.Background()
	newManager = func() manager { return &fakeManager{initErr: errors.New("init failed")} }
	if _, err := New(ctx, Config{}); err == nil {
		t.Fatalf("expected New error when initialize fails")
	}

	fm := &fakeManager{wrapErr: errors.New("wrap failed")}
	newManager = func() manager { return fm }
	sb, err := New(ctx, Config{})
	if err != nil {
		t.Fatalf("unexpected New error: %v", err)
	}
	if _, err := sb.Command(ctx, "echo hi"); err == nil {
		t.Fatalf("expected Command error when wrapping fails")
	}
}
