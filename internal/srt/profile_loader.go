package srt

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/flanksource/commons/logger"
	"github.com/flanksource/sandbox-runtime/internal/srt/presets"
	"gopkg.in/yaml.v3"
)

func GetPreset(name string) (*Profile, error) {
	data, err := presets.Get(name)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid preset %q: %w", name, err)
	}
	expandEnvInProfile(&p)
	return &p, nil
}

func ListPresets() []string {
	return presets.List()
}

func LoadProfileFromFile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid profile %s: %w", path, err)
	}
	expandEnvInProfile(&p)
	return &p, nil
}

func LoadProfiles(cwd string) (*SandboxRuntimeConfig, error) {
	var layers []*Profile
	var loadedFiles []string

	home, err := os.UserHomeDir()
	if err == nil {
		path := filepath.Join(home, ".sandbox.yaml")
		if p, err := LoadProfileFromFile(path); err == nil {
			layers = append(layers, p)
			loadedFiles = append(loadedFiles, path)
		}
	}

	gitRoot := FindGitRoot(cwd)
	if gitRoot != "" {
		path := filepath.Join(gitRoot, ".sandbox.yaml")
		if p, err := LoadProfileFromFile(path); err == nil {
			layers = append(layers, p)
			loadedFiles = append(loadedFiles, path)
		}
	}

	if cwd != gitRoot && cwd != home {
		path := filepath.Join(cwd, ".sandbox.yaml")
		if p, err := LoadProfileFromFile(path); err == nil {
			layers = append(layers, p)
			loadedFiles = append(loadedFiles, path)
		}
	}

	if len(layers) == 0 {
		return nil, nil
	}

	for _, f := range loadedFiles {
		logger.Tracef("Loaded profile: %s", f)
	}

	merged := MergeProfiles(layers...)
	return ResolveProfile(merged)
}

func FindGitRoot(from string) string {
	dir := from
	for {
		if info, err := os.Stat(filepath.Join(dir, ".git")); err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func expandEnvInProfile(p *Profile) {
	if p.Network != nil {
		expandSlice(p.Network.AllowedDomains)
		expandSlice(p.Network.DeniedDomains)
		expandSlice(p.Network.AllowUnixSockets)
		p.Network.AllowedDomains = filterEmptyStrings(p.Network.AllowedDomains)
		p.Network.DeniedDomains = filterEmptyStrings(p.Network.DeniedDomains)
		p.Network.AllowUnixSockets = filterEmptyStrings(p.Network.AllowUnixSockets)
	}
	if p.Filesystem != nil {
		expandSlice(p.Filesystem.DenyRead)
		expandSlice(p.Filesystem.AllowWrite)
		expandSlice(p.Filesystem.DenyWrite)
		p.Filesystem.DenyRead = filterEmptyStrings(p.Filesystem.DenyRead)
		p.Filesystem.AllowWrite = filterEmptyStrings(p.Filesystem.AllowWrite)
		p.Filesystem.DenyWrite = filterEmptyStrings(p.Filesystem.DenyWrite)
	}
	for k, v := range p.Env {
		if strings.Contains(v, "$") {
			p.Env[k] = os.ExpandEnv(v)
		}
	}
}

func expandSlice(s []string) {
	for i, v := range s {
		if strings.Contains(v, "$") {
			s[i] = os.ExpandEnv(v)
		}
	}
}

func filterEmptyStrings(s []string) []string {
	var result []string
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			result = append(result, v)
		}
	}
	return result
}

func LoadConfigFromYAML(content string) (*SandboxRuntimeConfig, error) {
	if strings.TrimSpace(content) == "" {
		return nil, nil
	}
	var p Profile
	if err := yaml.Unmarshal([]byte(content), &p); err != nil {
		return nil, err
	}
	expandEnvInProfile(&p)
	return ResolveProfile(&p)
}
