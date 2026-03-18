package srt

import (
	"testing"
)

func TestMergeProfiles_UnionSlices(t *testing.T) {
	a := &Profile{
		Network: &NetworkConfig{
			AllowedDomains: []string{"a.com", "b.com"},
		},
		Filesystem: &FilesystemConfig{
			AllowWrite: []string{"/tmp"},
		},
	}
	b := &Profile{
		Network: &NetworkConfig{
			AllowedDomains: []string{"b.com", "c.com"},
		},
		Filesystem: &FilesystemConfig{
			AllowWrite: []string{"/tmp", "/home"},
		},
	}
	merged := MergeProfiles(a, b)

	wantDomains := []string{"a.com", "b.com", "c.com"}
	if len(merged.Network.AllowedDomains) != len(wantDomains) {
		t.Fatalf("got %v, want %v", merged.Network.AllowedDomains, wantDomains)
	}
	for i, d := range wantDomains {
		if merged.Network.AllowedDomains[i] != d {
			t.Errorf("domain[%d] = %q, want %q", i, merged.Network.AllowedDomains[i], d)
		}
	}

	wantPaths := []string{"/tmp", "/home"}
	if len(merged.Filesystem.AllowWrite) != len(wantPaths) {
		t.Fatalf("got %v, want %v", merged.Filesystem.AllowWrite, wantPaths)
	}
}

func TestMergeProfiles_BoolOR(t *testing.T) {
	a := &Profile{AllowPty: false, EnableWeakerNestedSandbox: true}
	b := &Profile{AllowPty: true, EnableWeakerNestedSandbox: false}
	merged := MergeProfiles(a, b)

	if !merged.AllowPty {
		t.Error("AllowPty should be true (OR)")
	}
	if !merged.EnableWeakerNestedSandbox {
		t.Error("EnableWeakerNestedSandbox should be true (OR)")
	}
}

func TestMergeProfiles_NilHandling(t *testing.T) {
	a := &Profile{
		Network: &NetworkConfig{AllowedDomains: []string{"a.com"}},
	}
	merged := MergeProfiles(nil, a, nil)
	if len(merged.Network.AllowedDomains) != 1 || merged.Network.AllowedDomains[0] != "a.com" {
		t.Errorf("got %v, want [a.com]", merged.Network.AllowedDomains)
	}
}

func TestMergeProfiles_IgnoreViolations(t *testing.T) {
	a := &Profile{
		IgnoreViolations: map[string][]string{"curl": {"net"}},
	}
	b := &Profile{
		IgnoreViolations: map[string][]string{"curl": {"fs", "net"}, "wget": {"net"}},
	}
	merged := MergeProfiles(a, b)

	if len(merged.IgnoreViolations["curl"]) != 2 {
		t.Errorf("curl violations = %v, want [net fs]", merged.IgnoreViolations["curl"])
	}
	if len(merged.IgnoreViolations["wget"]) != 1 {
		t.Errorf("wget violations = %v, want [net]", merged.IgnoreViolations["wget"])
	}
}

func TestResolveProfile_PresetExpansion(t *testing.T) {
	p := &Profile{
		Allow: []string{"golang"},
		Network: &NetworkConfig{
			AllowedDomains: []string{"custom.example.com"},
		},
	}
	cfg, err := ResolveProfile(p)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, d := range cfg.Network.AllowedDomains {
		if d == "proxy.golang.org" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected proxy.golang.org in domains, got %v", cfg.Network.AllowedDomains)
	}

	found = false
	for _, d := range cfg.Network.AllowedDomains {
		if d == "custom.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected custom.example.com in domains, got %v", cfg.Network.AllowedDomains)
	}
}

func TestResolveProfile_UnknownPreset(t *testing.T) {
	p := &Profile{Allow: []string{"nonexistent"}}
	_, err := ResolveProfile(p)
	if err == nil {
		t.Error("expected error for unknown preset")
	}
}

func TestResolveProfile_MultiplePresets(t *testing.T) {
	p := &Profile{Allow: []string{"golang", "npm"}}
	cfg, err := ResolveProfile(p)
	if err != nil {
		t.Fatal(err)
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
	if !hasDomain("registry.npmjs.org") {
		t.Error("missing registry.npmjs.org")
	}
}

func TestMergeProfiles_EnvLastWriterWins(t *testing.T) {
	a := &Profile{
		Env: map[string]string{"KEY1": "a", "SHARED": "from-a"},
	}
	b := &Profile{
		Env: map[string]string{"KEY2": "b", "SHARED": "from-b"},
	}
	merged := MergeProfiles(a, b)

	if merged.Env["KEY1"] != "a" {
		t.Errorf("KEY1 = %q, want %q", merged.Env["KEY1"], "a")
	}
	if merged.Env["KEY2"] != "b" {
		t.Errorf("KEY2 = %q, want %q", merged.Env["KEY2"], "b")
	}
	if merged.Env["SHARED"] != "from-b" {
		t.Errorf("SHARED = %q, want %q (last-writer-wins)", merged.Env["SHARED"], "from-b")
	}
}

func TestMergeProfiles_EnvNilHandling(t *testing.T) {
	a := &Profile{Env: map[string]string{"X": "1"}}
	b := &Profile{}
	merged := MergeProfiles(a, b)
	if merged.Env["X"] != "1" {
		t.Errorf("Env[X] = %q, want %q", merged.Env["X"], "1")
	}

	merged2 := MergeProfiles(b, a)
	if merged2.Env["X"] != "1" {
		t.Errorf("Env[X] = %q, want %q", merged2.Env["X"], "1")
	}
}

func TestResolveProfile_EnvFromPreset(t *testing.T) {
	p := &Profile{Allow: []string{"golang"}}
	cfg, err := ResolveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Env == nil {
		t.Fatal("expected non-nil Env from golang preset")
	}
	if cfg.Env["GONOSUMCHECK"] != "*" {
		t.Errorf("GONOSUMCHECK = %q, want %q", cfg.Env["GONOSUMCHECK"], "*")
	}
}

func TestMergeProfiles_PassthroughEnvDedup(t *testing.T) {
	a := &Profile{PassthroughEnv: []string{"GOPATH", "HOME"}}
	b := &Profile{PassthroughEnv: []string{"HOME", "CARGO_HOME"}}
	merged := MergeProfiles(a, b)

	want := []string{"GOPATH", "HOME", "CARGO_HOME"}
	if len(merged.PassthroughEnv) != len(want) {
		t.Fatalf("got %v, want %v", merged.PassthroughEnv, want)
	}
	for i, v := range want {
		if merged.PassthroughEnv[i] != v {
			t.Errorf("PassthroughEnv[%d] = %q, want %q", i, merged.PassthroughEnv[i], v)
		}
	}
}

func TestResolveProfile_PassthroughFromPreset(t *testing.T) {
	p := &Profile{Allow: []string{"golang"}}
	cfg, err := ResolveProfile(p)
	if err != nil {
		t.Fatal(err)
	}

	has := func(name string) bool {
		for _, v := range cfg.PassthroughEnv {
			if v == name {
				return true
			}
		}
		return false
	}
	if !has("GOPATH") {
		t.Errorf("expected GOPATH in PassthroughEnv, got %v", cfg.PassthroughEnv)
	}
	if !has("GOMODCACHE") {
		t.Errorf("expected GOMODCACHE in PassthroughEnv, got %v", cfg.PassthroughEnv)
	}
}

func TestMergeStringSlicesDedup(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want []string
	}{
		{"both empty", nil, nil, nil},
		{"a empty", nil, []string{"x"}, []string{"x"}},
		{"b empty", []string{"x"}, nil, []string{"x"}},
		{"no overlap", []string{"a"}, []string{"b"}, []string{"a", "b"}},
		{"full overlap", []string{"a", "b"}, []string{"a", "b"}, []string{"a", "b"}},
		{"partial overlap", []string{"a", "b"}, []string{"b", "c"}, []string{"a", "b", "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeStringSlicesDedup(tt.a, tt.b)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
