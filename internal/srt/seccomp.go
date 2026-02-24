package srt

import (
	"os"
	"path/filepath"
	"runtime"
)

func vendorArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		return ""
	}
}

func GetPreGeneratedBPFPath(explicitPath string) string {
	return findSeccompArtifact("unix-block.bpf", explicitPath)
}

func GetApplySeccompBinaryPath(explicitPath string) string {
	return findSeccompArtifact("apply-seccomp", explicitPath)
}

func findSeccompArtifact(fileName, explicitPath string) string {
	if explicitPath != "" {
		if fileExists(explicitPath) {
			return explicitPath
		}
		return ""
	}

	arch := vendorArch()
	if arch == "" {
		return ""
	}

	candidates := seccompCandidates(arch, fileName)
	for _, p := range candidates {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

func seccompCandidates(arch, fileName string) []string {
	paths := make([]string, 0, 8)
	wd, _ := os.Getwd()
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)

	rel := filepath.Join("third_party", "seccomp", arch, fileName)
	paths = append(paths,
		filepath.Join(wd, rel),
		filepath.Join(wd, "..", rel),
		filepath.Join(wd, "..", "..", rel),
		filepath.Join(wd, "..", "..", "..", rel),
		filepath.Join(wd, "..", "..", "..", "..", rel),
		filepath.Join(exeDir, rel),
		filepath.Join(exeDir, "..", rel),
		filepath.Join(exeDir, "..", "..", rel),
		filepath.Join(exeDir, "..", "..", "..", rel),
	)

	return uniqueExistingCandidates(paths)
}

func uniqueExistingCandidates(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		clean := filepath.Clean(p)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	return out
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !st.IsDir()
}
