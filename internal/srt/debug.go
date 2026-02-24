package srt

import (
	"fmt"
	"os"
)

func Debugf(format string, args ...any) {
	if os.Getenv("SRT_DEBUG") == "" {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "[SandboxDebug] "+format+"\n", args...)
}
