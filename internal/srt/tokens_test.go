package srt

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMergeTokensConfig_NilHandling(t *testing.T) {
	aws := &TokensConfig{AWS: &AWSTokenConfig{Region: "us-east-1"}}

	if got := MergeTokensConfig(nil, nil); got != nil {
		t.Errorf("nil+nil = %v, want nil", got)
	}
	if got := MergeTokensConfig(aws, nil); got != aws {
		t.Error("base+nil should return base")
	}
	if got := MergeTokensConfig(nil, aws); got != aws {
		t.Error("nil+other should return other")
	}
}

func TestMergeTokensConfig_OverrideProvider(t *testing.T) {
	base := &TokensConfig{
		AWS:    &AWSTokenConfig{Region: "us-east-1"},
		GitHub: &GitHubTokenConfig{},
	}
	other := &TokensConfig{
		AWS: &AWSTokenConfig{Region: "eu-west-1", Profile: "prod"},
	}
	merged := MergeTokensConfig(base, other)

	if merged.AWS.Region != "eu-west-1" || merged.AWS.Profile != "prod" {
		t.Errorf("AWS = %+v, want region=eu-west-1 profile=prod", merged.AWS)
	}
	if merged.GitHub == nil {
		t.Error("GitHub should be preserved from base")
	}
}

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "file.txt")

	if err := atomicWriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("got %q, want %q", string(data), "hello")
	}

	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp file should not exist after atomic write")
	}
}

func TestTokenManager_AcquireNilConfig(t *testing.T) {
	tm := NewTokenManager(t.TempDir())
	defer tm.Cleanup()

	results, err := tm.Acquire(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0", len(results))
	}
}

func TestAcquireGitHubToken_FromEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test123")
	t.Setenv("GH_TOKEN", "")

	result, err := acquireGitHubToken(context.Background(), GitHubTokenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Provider != "github" {
		t.Errorf("provider = %q, want %q", result.Provider, "github")
	}
	if result.EnvVars["GITHUB_TOKEN"] != "ghp_test123" {
		t.Errorf("GITHUB_TOKEN = %q, want %q", result.EnvVars["GITHUB_TOKEN"], "ghp_test123")
	}
}

func TestAcquireGitHubToken_FallsBackToGHToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "gho_fallback")

	result, err := acquireGitHubToken(context.Background(), GitHubTokenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if result.EnvVars["GITHUB_TOKEN"] != "gho_fallback" {
		t.Errorf("GITHUB_TOKEN = %q, want %q", result.EnvVars["GITHUB_TOKEN"], "gho_fallback")
	}
}

func TestAcquireAzureToken(t *testing.T) {
	result, err := acquireAzureToken(context.Background(), AzureTokenConfig{
		ClientID:     "client-123",
		ClientSecret: "secret-456",
		TenantID:     "tenant-789",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Provider != "azure" {
		t.Errorf("provider = %q, want %q", result.Provider, "azure")
	}
	if result.EnvVars["AZURE_CLIENT_ID"] != "client-123" {
		t.Errorf("AZURE_CLIENT_ID = %q", result.EnvVars["AZURE_CLIENT_ID"])
	}
	if result.EnvVars["AZURE_CLIENT_SECRET"] != "secret-456" {
		t.Errorf("AZURE_CLIENT_SECRET = %q", result.EnvVars["AZURE_CLIENT_SECRET"])
	}
	if result.EnvVars["AZURE_TENANT_ID"] != "tenant-789" {
		t.Errorf("AZURE_TENANT_ID = %q", result.EnvVars["AZURE_TENANT_ID"])
	}
}

func TestAcquireAzureToken_MissingRequired(t *testing.T) {
	_, err := acquireAzureToken(context.Background(), AzureTokenConfig{ClientID: "x"})
	if err == nil {
		t.Error("expected error for missing tenantID")
	}
}

func TestTokenManager_Cleanup(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "creds")
	os.MkdirAll(subDir, 0o700)
	os.WriteFile(filepath.Join(subDir, "test"), []byte("x"), 0o600)

	tm := NewTokenManager(subDir)
	tm.Cleanup()

	if _, err := os.Stat(subDir); !os.IsNotExist(err) {
		t.Error("credential directory should be removed after cleanup")
	}
}

func TestTokenManager_FullFlow(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_flow_test")

	tm := NewTokenManager(t.TempDir())
	defer tm.Cleanup()

	config := &TokensConfig{
		GitHub: &GitHubTokenConfig{},
		Azure: &AzureTokenConfig{
			ClientID: "c", ClientSecret: "s", TenantID: "t",
		},
	}

	results, err := tm.Acquire(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	providers := map[string]bool{}
	for _, r := range results {
		providers[r.Provider] = true
	}
	if !providers["github"] {
		t.Error("missing github provider")
	}
	if !providers["azure"] {
		t.Error("missing azure provider")
	}
}

func TestProfileTokensMerge(t *testing.T) {
	a := &Profile{
		Tokens: &TokensConfig{
			GitHub: &GitHubTokenConfig{},
			AWS:    &AWSTokenConfig{Region: "us-east-1"},
		},
	}
	b := &Profile{
		Tokens: &TokensConfig{
			AWS: &AWSTokenConfig{Region: "eu-west-1", Profile: "prod"},
		},
	}

	merged := MergeProfiles(a, b)
	if merged.Tokens == nil {
		t.Fatal("Tokens should not be nil")
	}
	if merged.Tokens.GitHub == nil {
		t.Error("GitHub should be preserved from first profile")
	}
	if merged.Tokens.AWS.Region != "eu-west-1" {
		t.Errorf("AWS region = %q, want eu-west-1", merged.Tokens.AWS.Region)
	}
}

func TestConfigTokensMerge(t *testing.T) {
	base := SandboxRuntimeConfig{
		Tokens: &TokensConfig{
			GitHub: &GitHubTokenConfig{},
		},
	}
	other := SandboxRuntimeConfig{
		Tokens: &TokensConfig{
			AWS: &AWSTokenConfig{Region: "us-east-1"},
		},
	}

	base.MergeFrom(&other)
	if base.Tokens.GitHub == nil {
		t.Error("GitHub should be preserved after merge")
	}
	if base.Tokens.AWS == nil || base.Tokens.AWS.Region != "us-east-1" {
		t.Error("AWS should be merged in")
	}
}
