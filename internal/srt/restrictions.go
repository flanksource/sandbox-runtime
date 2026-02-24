package srt

type FsReadRestrictionConfig struct {
	DenyOnly []string
}

type FsWriteRestrictionConfig struct {
	AllowOnly       []string
	DenyWithinAllow []string
}

type NetworkRestrictionConfig struct {
	AllowedHosts []string
	DeniedHosts  []string
}

type NetworkHostPattern struct {
	Host string
	Port int
}

type SandboxAskCallback func(params NetworkHostPattern) bool
