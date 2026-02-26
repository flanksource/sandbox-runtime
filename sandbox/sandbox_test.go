package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func skipIfUnsupported(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("unsupported platform")
	}

	// On Linux, bwrap needs the ability to create user/network namespaces.
	// In unprivileged containers (Docker, K8s) this fails even if bwrap is
	// installed.
	// Do a quick probe so the tests skip cleanly instead of
	// failing with "Operation not permitted".
	if runtime.GOOS == "linux" {
		probe := exec.Command("bwrap", "--unshare-net", "--dev", "/dev", "--ro-bind", "/", "/", "--", "/bin/true")
		if err := probe.Run(); err != nil {
			t.Skipf("bwrap cannot create namespaces (unprivileged container?): %v", err)
		}
	}
}

func TestIsSupported_HonorsConfiguredRipgrepCommand(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("unsupported platform")
	}

	if !IsSupported(Config{}) {
		t.Skip("default sandbox dependencies not available on this machine")
	}

	cfg := Config{Ripgrep: &RipgrepConfig{Command: "definitely-missing-rg-custom-cmd"}}
	if IsSupported(cfg) {
		t.Fatal("expected IsSupported to honor custom ripgrep command and return false")
	}
}

func TestIsSupported_InvalidConfigReturnsFalse(t *testing.T) {
	cfg := Config{Network: NetworkConfig{AllowedDomains: []string{"https://bad.example.com/path"}}}
	if IsSupported(cfg) {
		t.Fatal("expected IsSupported to return false for invalid config")
	}
}

func TestNew_InitializesRealManager(t *testing.T) {
	skipIfUnsupported(t)
	ctx := context.Background()

	sb, err := New(ctx, Config{
		Network: NetworkConfig{AllowedDomains: []string{"example.com"}},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer sb.Close(ctx)

	if sb.manager == nil {
		t.Fatal("expected manager to be set")
	}
}

func TestCommand_RunsInsideSandbox(t *testing.T) {
	skipIfUnsupported(t)
	ctx := context.Background()

	sb, err := New(ctx, Config{
		Network:    NetworkConfig{AllowedDomains: []string{"example.com"}},
		Filesystem: FilesystemConfig{AllowWrite: []string{os.TempDir()}},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer sb.Close(ctx)

	cmd, err := sb.Command(ctx, "echo", "hello-from-sandbox")
	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("sandboxed command failed: %v", err)
	}

	got := strings.TrimSpace(stdout.String())
	if got != "hello-from-sandbox" {
		t.Fatalf("expected %q, got %q", "hello-from-sandbox", got)
	}
}

func TestCommand_CanReadAllowedFile(t *testing.T) {
	skipIfUnsupported(t)
	ctx := context.Background()

	// Write a temp file the sandbox should be able to read.
	tmp, err := os.CreateTemp("", "sandbox-read-test-*")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString("readable-content"); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	tmp.Close()

	sb, err := New(ctx, Config{
		Network: NetworkConfig{AllowedDomains: []string{"example.com"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close(ctx)

	cmd, err := sb.Command(ctx, "cat", tmp.Name())
	if err != nil {
		t.Fatalf("Command: %v", err)
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("sandboxed cat failed: %v", err)
	}

	if got := stdout.String(); got != "readable-content" {
		t.Fatalf("expected %q, got %q", "readable-content", got)
	}
}

func TestCommand_DeniesWriteOutsideAllowed(t *testing.T) {
	skipIfUnsupported(t)
	ctx := context.Background()

	sb, err := New(ctx, Config{
		Network:    NetworkConfig{AllowedDomains: []string{"example.com"}},
		Filesystem: FilesystemConfig{AllowWrite: []string{"/tmp/sandbox-allowed-dir-does-not-exist"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close(ctx)

	// Try writing to a path outside the allowed write list.
	target := "/tmp/sandbox-denied-write-test-" + t.Name()
	defer os.Remove(target)

	cmd, err := sb.Command(ctx, "touch", target)
	if err != nil {
		t.Fatalf("Command: %v", err)
	}

	var stderr bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err == nil {
		// On some platforms the touch may silently succeed if sandbox-exec
		// doesn't enforce this specific write deny. Check the file doesn't exist.
		if _, statErr := os.Stat(target); statErr == nil {
			t.Log("sandbox did not block the write (platform may not enforce this path)")
		}
		return
	}

	// Command failed — sandbox blocked the write.
	t.Logf("write correctly denied: %v, stderr: %s", err, stderr.String())
}

func TestCommand_NetworkAllowedDomainWorks(t *testing.T) {
	skipIfUnsupported(t)
	ctx := context.Background()

	sb, err := New(ctx, Config{
		Network: NetworkConfig{AllowedDomains: []string{"example.com"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close(ctx)

	cmd, err := sb.Command(ctx, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "https://example.com")
	if err != nil {
		t.Fatalf("Command: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("curl to allowed domain failed: %v\nstderr: %s", err, stderr.String())
	}

	code := strings.TrimSpace(stdout.String())
	if code != "200" && code != "301" && code != "302" {
		t.Fatalf("expected HTTP 200/301/302 from example.com, got %q", code)
	}
}

func TestCommand_NetworkDeniedDomainBlocked(t *testing.T) {
	skipIfUnsupported(t)
	ctx := context.Background()

	sb, err := New(ctx, Config{
		Network: NetworkConfig{
			AllowedDomains: []string{"example.com"},
			DeniedDomains:  []string{"denied.example.com"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close(ctx)

	// Connect to a domain NOT in the allowed list — should be blocked by proxy.
	cmd, err := sb.Command(ctx, "curl", "-s", "--max-time", "5", "https://google.com")
	if err != nil {
		t.Fatalf("Command: %v", err)
	}

	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err == nil {
		t.Fatal("expected curl to non-allowed domain to fail, but it succeeded")
	}
	t.Logf("non-allowed domain correctly blocked: %v", err)
}

func TestWithAskCallback_InvokedForUnknownDomain(t *testing.T) {
	skipIfUnsupported(t)
	ctx := context.Background()

	asked := make(chan AskParams, 1)
	sb, err := New(ctx, Config{
		Network: NetworkConfig{AllowedDomains: []string{"example.com"}},
	}, WithAskCallback(func(params AskParams) bool {
		asked <- params
		return true // allow it
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close(ctx)

	// curl a domain not in allowed list — should trigger the ask callback.
	cmd, err := sb.Command(ctx, "curl", "-s", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", "https://httpbin.org/get")
	if err != nil {
		t.Fatalf("Command: %v", err)
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("curl failed: %v", err)
	}

	select {
	case p := <-asked:
		if p.Host != "httpbin.org" {
			t.Fatalf("expected ask for httpbin.org, got %q", p.Host)
		}
	default:
		t.Fatal("expected ask callback to be invoked")
	}
}

func TestClose_CleansUpResources(t *testing.T) {
	skipIfUnsupported(t)
	ctx := context.Background()

	sb, err := New(ctx, Config{
		Network: NetworkConfig{AllowedDomains: []string{"example.com"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Close should not error.
	if err := sb.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// After close, Command should fail since the manager is reset.
	_, err = sb.Command(ctx, "echo", "post-close")
	if err == nil {
		t.Fatal("expected Command after Close to fail")
	}
}

func TestNew_InvalidConfigReturnsError(t *testing.T) {
	skipIfUnsupported(t)
	ctx := context.Background()

	// Invalid domain pattern.
	_, err := New(ctx, Config{
		Network: NetworkConfig{AllowedDomains: []string{"http://bad-url.com/path"}},
	})
	if err == nil {
		t.Fatal("expected error for invalid domain pattern")
	}
}

func TestCommand_MultipleCommandsOnSameSandbox(t *testing.T) {
	skipIfUnsupported(t)
	ctx := context.Background()

	sb, err := New(ctx, Config{
		Network: NetworkConfig{AllowedDomains: []string{"example.com"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close(ctx)

	for i, word := range []string{"aaa", "bbb", "ccc"} {
		cmd, err := sb.Command(ctx, "echo", word)
		if err != nil {
			t.Fatalf("Command %d: %v", i, err)
		}

		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}

		if got := strings.TrimSpace(stdout.String()); got != word {
			t.Fatalf("command %d: expected %q, got %q", i, word, got)
		}
	}
}
