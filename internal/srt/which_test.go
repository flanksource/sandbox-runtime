package srt

import "testing"

func TestWhich(t *testing.T) {
	if p := Which("sh"); p == "" {
		t.Fatalf("expected to find sh")
	}
	if p := Which("this-command-definitely-does-not-exist-12345"); p != "" {
		t.Fatalf("expected missing command to return empty path, got %q", p)
	}
}
