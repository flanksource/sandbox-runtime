package srt

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestGenerateMacOSSandboxProfile_DenyDefaultBaseline(t *testing.T) {
	logTag := "TEST_LOG_TAG"
	profile := generateMacOSSandboxProfile(MacOSSandboxParams{
		NeedsNetworkRestriction: false,
		ReadConfig:              nil,
		WriteConfig:             nil,
	}, logTag)

	denyDefault := fmt.Sprintf("(deny default (with message %q))", logTag)
	if !strings.Contains(profile, denyDefault) {
		t.Fatalf("expected deny-default profile baseline, missing: %s", denyDefault)
	}
	if strings.Contains(profile, "(allow default)") {
		t.Fatalf("profile must not use allow default baseline")
	}

	required := []string{
		"(allow process-exec)",
		"(allow process-fork)",
		"(allow user-preference-read)",
		"(allow network*)",
		"(allow file-read*)",
		"(allow file-write*)",
	}
	for _, rule := range required {
		if !strings.Contains(profile, rule) {
			t.Fatalf("expected profile to include %q", rule)
		}
	}
}

func TestGenerateMacOSSandboxProfile_MoveBlockingRulesForReadAndWriteDeny(t *testing.T) {
	logTag := "MOVE_BLOCK_TAG"
	readDeny := "/tmp/srt-move-read-target"
	writeDeny := "/tmp/srt-move-write-target"
	globDeny := "/tmp/srt-move-glob/**/*.env"

	profile := generateMacOSSandboxProfile(MacOSSandboxParams{
		NeedsNetworkRestriction: true,
		ReadConfig: &FsReadRestrictionConfig{
			DenyOnly: []string{readDeny, globDeny},
		},
		WriteConfig: &FsWriteRestrictionConfig{
			AllowOnly:       []string{"/tmp"},
			DenyWithinAllow: []string{writeDeny},
		},
	}, logTag)

	checks := []string{
		fmt.Sprintf("(deny file-write-unlink\n  (subpath %q)\n  (with message %q))", readDeny, logTag),
		fmt.Sprintf("(deny file-write-unlink\n  (subpath %q)\n  (with message %q))", writeDeny, logTag),
		fmt.Sprintf("(deny file-write-unlink\n  (literal %q)\n  (with message %q))", "/tmp", logTag),
		"(deny file-write-unlink\n  " + fmt.Sprintf("(regex %q)", GlobToRegex(globDeny)),
	}

	for _, check := range checks {
		if !strings.Contains(profile, check) {
			t.Fatalf("expected move-blocking rule snippet not found: %s", check)
		}
	}
}

func TestGetAncestorDirectories(t *testing.T) {
	got := getAncestorDirectories("/private/tmp/test/file.txt")
	want := []string{"/private/tmp/test", "/private/tmp", "/private"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected ancestors\n got: %#v\nwant: %#v", got, want)
	}
}

func TestGenerateMoveBlockingRules_GlobIncludesAncestorLiterals(t *testing.T) {
	rules := strings.Join(generateMoveBlockingRules([]string{"/tmp/a/**/*.env"}, "LOG_TAG"), "\n")
	if !strings.Contains(rules, `(literal "/tmp/a")`) {
		t.Fatalf("expected glob move blocking rules to include base dir literal")
	}
	if !strings.Contains(rules, `(literal "/tmp")`) {
		t.Fatalf("expected glob move blocking rules to include ancestor literal")
	}
}

func TestGenerateMacOSBaseProfile_EnableWeakerNetworkIsolationToggle(t *testing.T) {
	without := strings.Join(generateMacOSBaseProfile("TAG", false), "\n")
	if strings.Contains(without, "com.apple.trustd.agent") {
		t.Fatalf("trustd.agent should not be present when weaker network isolation is disabled")
	}
	if !strings.Contains(without, ")\n\n\n; POSIX IPC - shared memory") {
		t.Fatalf("expected formatting parity blank line before POSIX block when weaker isolation is disabled")
	}

	with := strings.Join(generateMacOSBaseProfile("TAG", true), "\n")
	if !strings.Contains(with, "com.apple.trustd.agent") {
		t.Fatalf("trustd.agent should be present when weaker network isolation is enabled")
	}
}

func TestGenerateMacOSWriteRules_NilConfigAllowsAllWrites(t *testing.T) {
	rules := generateMacOSWriteRules(nil, "TAG", false)
	if len(rules) != 1 || rules[0] != "(allow file-write*)" {
		t.Fatalf("expected nil write config to allow file-write*, got: %#v", rules)
	}
}

func TestGenerateMacOSWriteRules_AddsTmpdirParentAllowRules(t *testing.T) {
	t.Setenv("TMPDIR", "/var/folders/ab/cdefghijk/T/")
	rules := strings.Join(generateMacOSWriteRules(&FsWriteRestrictionConfig{AllowOnly: []string{"/tmp"}}, "TAG", false), "\n")

	if !strings.Contains(rules, "/var/folders/ab/cdefghijk") && !strings.Contains(rules, "/private/var/folders/ab/cdefghijk") {
		t.Fatalf("expected TMPDIR parent allow rule in generated write rules, got:\n%s", rules)
	}
}

func TestGetTmpdirParentIfMacOSPattern(t *testing.T) {
	t.Setenv("TMPDIR", "/var/folders/ab/cdefghijk/T/")
	got := getTmpdirParentIfMacOSPattern()
	want := []string{"/var/folders/ab/cdefghijk", "/private/var/folders/ab/cdefghijk"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected TMPDIR parents\n got: %#v\nwant: %#v", got, want)
	}

	t.Setenv("TMPDIR", "/tmp/not-macos-layout")
	got = getTmpdirParentIfMacOSPattern()
	if len(got) != 0 {
		t.Fatalf("expected no TMPDIR parent allow entries for non-matching TMPDIR, got: %#v", got)
	}
}

func TestGenerateMacOSSandboxProfile_AllowPtyExpandedRules(t *testing.T) {
	profile := generateMacOSSandboxProfile(MacOSSandboxParams{
		NeedsNetworkRestriction: true,
		ReadConfig:              &FsReadRestrictionConfig{DenyOnly: []string{}},
		WriteConfig:             &FsWriteRestrictionConfig{AllowOnly: []string{"/tmp"}},
		AllowPty:                true,
	}, "TAG")

	checks := []string{
		"(allow pseudo-tty)",
		"(literal \"/dev/ptmx\")",
		"(regex #\"^/dev/ttys\")",
	}
	for _, check := range checks {
		if !strings.Contains(profile, check) {
			t.Fatalf("expected PTY rule %q in profile", check)
		}
	}
}

func TestGenerateMacOSBaseProfile_ContainsExpectedAllowlistEntries(t *testing.T) {
	profile := strings.Join(generateMacOSBaseProfile("TAG", false), "\n")
	checks := []string{
		"(allow iokit-open",
		`(sysctl-name "kern.osrelease")`,
		`(global-name "com.apple.system.logger")`,
	}
	for _, check := range checks {
		if !strings.Contains(profile, check) {
			t.Fatalf("expected base profile to include %q", check)
		}
	}
}
