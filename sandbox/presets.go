package sandbox

import "github.com/flanksource/sandbox-runtime/internal/srt"

// GetPreset loads a named built-in preset (e.g. "golang", "npm", "docker").
func GetPreset(name string) (*Profile, error) {
	return srt.GetPreset(name)
}

// ListPresets returns the names of all available built-in presets.
func ListPresets() []string {
	return srt.ListPresets()
}

// LoadProfileFromFile parses a .sandbox.yaml file into a Profile.
func LoadProfileFromFile(path string) (*Profile, error) {
	return srt.LoadProfileFromFile(path)
}

// LoadProfiles discovers and merges .sandbox.yaml files from
// home directory, git root, and cwd, then resolves preset references.
func LoadProfiles(cwd string) (*Config, error) {
	return srt.LoadProfiles(cwd)
}

// MergeProfiles combines multiple profiles, deduplicating slices.
func MergeProfiles(profiles ...*Profile) *Profile {
	return srt.MergeProfiles(profiles...)
}

// ResolveProfile expands preset references and returns a resolved Config.
func ResolveProfile(p *Profile) (*Config, error) {
	return srt.ResolveProfile(p)
}
