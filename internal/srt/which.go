package srt

import "os/exec"

func Which(bin string) string {
	path, err := exec.LookPath(bin)
	if err != nil {
		return ""
	}
	return path
}
