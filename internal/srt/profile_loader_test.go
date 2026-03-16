package srt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProfileFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte(`
allow: [golang, npm]
network:
  allowedDomains:
    - extra.example.com
`), 0644)

	p, err := LoadProfileFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Allow) != 2 || p.Allow[0] != "golang" || p.Allow[1] != "npm" {
		t.Errorf("Allow = %v, want [golang npm]", p.Allow)
	}
	if len(p.Network.AllowedDomains) != 1 || p.Network.AllowedDomains[0] != "extra.example.com" {
		t.Errorf("AllowedDomains = %v, want [extra.example.com]", p.Network.AllowedDomains)
	}
}

func TestLoadProfileFromFile_NotFound(t *testing.T) {
	_, err := LoadProfileFromFile("/nonexistent/file.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadProfiles_LayerMerge(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	gitRoot := t.TempDir()
	os.MkdirAll(filepath.Join(gitRoot, ".git"), 0755)

	subDir := filepath.Join(gitRoot, "sub")
	os.MkdirAll(subDir, 0755)

	os.WriteFile(filepath.Join(home, ".sandbox.yaml"), []byte(`
allow: [git]
`), 0644)

	os.WriteFile(filepath.Join(gitRoot, ".sandbox.yaml"), []byte(`
allow: [golang]
`), 0644)

	os.WriteFile(filepath.Join(subDir, ".sandbox.yaml"), []byte(`
network:
  allowedDomains:
    - custom.example.com
`), 0644)

	cfg, err := LoadProfiles(subDir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	hasDomain := func(d string) bool {
		for _, dom := range cfg.Network.AllowedDomains {
			if dom == d {
				return true
			}
		}
		return false
	}

	if !hasDomain("github.com") {
		t.Error("missing github.com from git preset (home layer)")
	}
	if !hasDomain("proxy.golang.org") {
		t.Error("missing proxy.golang.org from golang preset (git-root layer)")
	}
	if !hasDomain("custom.example.com") {
		t.Error("missing custom.example.com from subdir layer")
	}
}

func TestLoadProfiles_NoFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	cfg, err := LoadProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Error("expected nil config when no .sandbox.yaml files exist")
	}
}

func TestFindGitRoot(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	sub := filepath.Join(dir, "a", "b")
	os.MkdirAll(sub, 0755)

	got := FindGitRoot(sub)
	if got != dir {
		t.Errorf("FindGitRoot(%s) = %q, want %q", sub, got, dir)
	}
}

func TestFindGitRoot_NoGit(t *testing.T) {
	dir := t.TempDir()
	got := FindGitRoot(dir)
	if got != "" {
		t.Errorf("FindGitRoot(%s) = %q, want empty", dir, got)
	}
}

func TestGetPreset(t *testing.T) {
	for _, name := range ListPresets() {
		t.Run(name, func(t *testing.T) {
			p, err := GetPreset(name)
			if err != nil {
				t.Fatal(err)
			}
			if p == nil {
				t.Error("expected non-nil profile")
			}
		})
	}
}

func TestListPresets(t *testing.T) {
	names := ListPresets()
	if len(names) < 10 {
		t.Errorf("expected at least 10 presets, got %d: %v", len(names), names)
	}
	expected := []string{"aws", "azure", "docker", "gcp", "git", "golang", "homebrew", "ide", "npm", "python", "rust", "shell", "ssh"}
	for _, e := range expected {
		found := false
		for _, n := range names {
			if n == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing preset: %s", e)
		}
	}
}

func TestLoadConfigFromYAML(t *testing.T) {
	cfg, err := LoadConfigFromYAML(`
allow: [golang]
network:
  allowedDomains:
    - extra.test.com
`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	hasDomain := func(d string) bool {
		for _, dom := range cfg.Network.AllowedDomains {
			if dom == d {
				return true
			}
		}
		return false
	}
	if !hasDomain("proxy.golang.org") {
		t.Error("missing proxy.golang.org")
	}
	if !hasDomain("extra.test.com") {
		t.Error("missing extra.test.com")
	}
}

func TestLoadConfigFromYAML_Empty(t *testing.T) {
	cfg, err := LoadConfigFromYAML("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Error("expected nil for empty content")
	}
}

func TestExpandEnvInProfile(t *testing.T) {
	t.Setenv("TEST_VAR", "/expanded")
	p := &Profile{
		Filesystem: &FilesystemConfig{
			AllowWrite: []string{"$TEST_VAR/sub"},
		},
	}
	expandEnvInProfile(p)
	if p.Filesystem.AllowWrite[0] != "/expanded/sub" {
		t.Errorf("got %q, want /expanded/sub", p.Filesystem.AllowWrite[0])
	}
}

func TestExpandEnvInProfile_EnvMapValues(t *testing.T) {
	t.Setenv("MY_CERT", "/etc/ssl/cert.pem")
	p := &Profile{
		Env: map[string]string{
			"SSL_CERT_FILE": "$MY_CERT",
			"STATIC_KEY":    "no-expansion",
		},
	}
	expandEnvInProfile(p)
	if p.Env["SSL_CERT_FILE"] != "/etc/ssl/cert.pem" {
		t.Errorf("SSL_CERT_FILE = %q, want /etc/ssl/cert.pem", p.Env["SSL_CERT_FILE"])
	}
	if p.Env["STATIC_KEY"] != "no-expansion" {
		t.Errorf("STATIC_KEY = %q, want no-expansion", p.Env["STATIC_KEY"])
	}
}
