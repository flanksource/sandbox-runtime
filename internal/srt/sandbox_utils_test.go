package srt

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestGlobToRegex_BasicPatterns(t *testing.T) {
	tests := []struct {
		pattern string
		match   string
		want    bool
	}{
		{pattern: "*.ts", match: "foo.ts", want: true},
		{pattern: "*.ts", match: "foo/bar.ts", want: false},
		{pattern: "src/**/*.ts", match: "src/a/b/c.ts", want: true},
		{pattern: "src/**/*.ts", match: "lib/a.ts", want: false},
	}

	for _, tt := range tests {
		r, err := regexp.Compile(GlobToRegex(tt.pattern))
		if err != nil {
			t.Fatalf("invalid regex for pattern %q: %v", tt.pattern, err)
		}
		got := r.MatchString(tt.match)
		if got != tt.want {
			t.Fatalf("pattern=%q match=%q got=%v want=%v", tt.pattern, tt.match, got, tt.want)
		}
	}
}

func TestGlobToRegex_EscapesBackslashes(t *testing.T) {
	r, err := regexp.Compile(GlobToRegex(`foo\bar*.txt`))
	if err != nil {
		t.Fatalf("invalid regex: %v", err)
	}
	if !r.MatchString(`foo\bar1.txt`) {
		t.Fatalf("expected backslash-containing path to match")
	}
}

func TestGlobToRegex_TreatsUnclosedBracketLiterally(t *testing.T) {
	r, err := regexp.Compile(GlobToRegex("file[abc"))
	if err != nil {
		t.Fatalf("invalid regex for unclosed bracket pattern: %v", err)
	}
	if !r.MatchString("file[abc") {
		t.Fatalf("expected literal match for unclosed bracket pattern")
	}
	if r.MatchString("filea") {
		t.Fatalf("did not expect character-class semantics for unclosed bracket pattern")
	}
}

func TestIsSymlinkOutsideBoundary(t *testing.T) {
	if IsSymlinkOutsideBoundary("/tmp/claude", "/private/tmp/claude") {
		t.Fatalf("expected /tmp -> /private/tmp canonical alias to be allowed")
	}
	if !IsSymlinkOutsideBoundary("/tmp/claude/sub", "/tmp") {
		t.Fatalf("expected ancestor resolution to be rejected")
	}
	if !IsSymlinkOutsideBoundary("/tmp/claude", "/Users/example") {
		t.Fatalf("expected unrelated resolution to be rejected")
	}
}

func TestNormalizePathForSandbox_DoesNotResolveBroadeningSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on windows")
	}

	tmp := t.TempDir()
	linkPath := filepath.Join(tmp, "broad")
	if err := os.Symlink("/", linkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	got := NormalizePathForSandbox(linkPath)
	if got != filepath.Clean(linkPath) {
		t.Fatalf("expected broadening symlink path to remain unresolved, got %q", got)
	}
}

func TestNormalizePathForSandbox_GlobKeepsBroadeningSymlinkPrefix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on windows")
	}

	tmp := t.TempDir()
	linkPath := filepath.Join(tmp, "broad")
	if err := os.Symlink("/", linkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	pattern := filepath.Join(linkPath, "*.env")
	got := NormalizePathForSandbox(pattern)
	if !strings.HasPrefix(got, filepath.Clean(linkPath)) {
		t.Fatalf("expected normalized glob to keep original prefix %q, got %q", linkPath, got)
	}
}

func TestExpandGlobPattern(t *testing.T) {
	tmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(tmp, "nested"))
	mustMkdirAll(t, filepath.Join(tmp, "nested", "deep"))
	mustWriteFile(t, filepath.Join(tmp, "root.env"), "x")
	mustWriteFile(t, filepath.Join(tmp, "nested", "one.env"), "x")
	mustWriteFile(t, filepath.Join(tmp, "nested", "deep", "two.env"), "x")
	mustWriteFile(t, filepath.Join(tmp, "nested", "deep", "other.txt"), "x")

	rootOnly := ExpandGlobPattern(filepath.Join(tmp, "*.env"))
	wantRoot := NormalizePathForSandbox(filepath.Join(tmp, "root.env"))
	if len(rootOnly) != 1 || NormalizePathForSandbox(rootOnly[0]) != wantRoot {
		t.Fatalf("expected only root env file, got %#v", rootOnly)
	}

	recursive := ExpandGlobPattern(filepath.Join(tmp, "**", "*.env"))
	mustHave := []string{
		filepath.Join(tmp, "root.env"),
		filepath.Join(tmp, "nested", "one.env"),
		filepath.Join(tmp, "nested", "deep", "two.env"),
	}
	for _, want := range mustHave {
		wantNorm := NormalizePathForSandbox(want)
		found := false
		for _, got := range recursive {
			if NormalizePathForSandbox(got) == wantNorm {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected %q in recursive glob expansion, got %#v", want, recursive)
		}
	}
}

func TestGenerateProxyEnvVars(t *testing.T) {
	env := GenerateProxyEnvVars(3128, 1080)
	joined := strings.Join(env, "\n")
	mustContain := []string{
		"SANDBOX_RUNTIME=1",
		"HTTP_PROXY=http://localhost:3128",
		"HTTPS_PROXY=http://localhost:3128",
		"ALL_PROXY=socks5h://localhost:1080",
		"NO_PROXY=",
	}
	for _, m := range mustContain {
		if !strings.Contains(joined, m) {
			t.Fatalf("expected env vars to contain %q, got:\n%s", m, joined)
		}
	}
}

func TestEncodeDecodeSandboxedCommand(t *testing.T) {
	cmd := "echo hello world"
	encoded := EncodeSandboxedCommand(cmd)
	decoded, err := DecodeSandboxedCommand(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded != cmd {
		t.Fatalf("decoded command mismatch: got=%q want=%q", decoded, cmd)
	}
}
