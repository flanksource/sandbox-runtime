package srt

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLinuxGetMandatoryDenyPaths_ScansNestedDangerousPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	if Which("rg") == "" {
		t.Skip("ripgrep (rg) not available")
	}

	tmp := t.TempDir()
	restore := chdirForTest(t, tmp)
	defer restore()

	mustMkdirAll(t, filepath.Join("sub", ".vscode"))
	mustWriteFile(t, filepath.Join("sub", ".vscode", "settings.json"), "{}")

	mustMkdirAll(t, filepath.Join("sub", ".claude", "commands"))
	mustWriteFile(t, filepath.Join("sub", ".claude", "commands", "test.md"), "# test")

	mustWriteFile(t, filepath.Join("sub", ".bashrc"), "export TEST=1")

	mustMkdirAll(t, filepath.Join("subrepo", ".git", "hooks"))
	mustWriteFile(t, filepath.Join("subrepo", ".git", "hooks", "pre-commit"), "#!/bin/sh")
	mustWriteFile(t, filepath.Join("subrepo", ".git", "config"), "[core]")

	denyPaths := linuxGetMandatoryDenyPaths(context.Background(), nil, 5, false)

	expectContainsPath(t, denyPaths, filepath.Join(tmp, "sub", ".vscode"))
	expectContainsPath(t, denyPaths, filepath.Join(tmp, "sub", ".claude", "commands"))
	expectContainsPath(t, denyPaths, filepath.Join(tmp, "sub", ".bashrc"))
	expectContainsPath(t, denyPaths, filepath.Join(tmp, "subrepo", ".git", "hooks"))
	expectContainsPath(t, denyPaths, filepath.Join(tmp, "subrepo", ".git", "config"))
}

func TestLinuxGetMandatoryDenyPaths_AllowGitConfigToggle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	if Which("rg") == "" {
		t.Skip("ripgrep (rg) not available")
	}

	tmp := t.TempDir()
	restore := chdirForTest(t, tmp)
	defer restore()

	mustMkdirAll(t, filepath.Join(".git", "hooks"))
	mustWriteFile(t, filepath.Join(".git", "hooks", "pre-commit"), "#!/bin/sh")
	mustWriteFile(t, filepath.Join(".git", "config"), "[core]")

	mustMkdirAll(t, filepath.Join("nested", ".git", "hooks"))
	mustWriteFile(t, filepath.Join("nested", ".git", "hooks", "pre-push"), "#!/bin/sh")
	mustWriteFile(t, filepath.Join("nested", ".git", "config"), "[core]")

	denyWithGitConfigBlocked := linuxGetMandatoryDenyPaths(context.Background(), nil, 5, false)
	denyWithGitConfigAllowed := linuxGetMandatoryDenyPaths(context.Background(), nil, 5, true)

	rootGitConfig := filepath.Join(tmp, ".git", "config")
	nestedGitConfig := filepath.Join(tmp, "nested", ".git", "config")
	rootHooks := filepath.Join(tmp, ".git", "hooks")
	nestedHooks := filepath.Join(tmp, "nested", ".git", "hooks")

	expectContainsPath(t, denyWithGitConfigBlocked, rootGitConfig)
	expectContainsPath(t, denyWithGitConfigBlocked, nestedGitConfig)
	expectContainsPath(t, denyWithGitConfigBlocked, rootHooks)
	expectContainsPath(t, denyWithGitConfigBlocked, nestedHooks)

	expectNotContainsPath(t, denyWithGitConfigAllowed, rootGitConfig)
	expectNotContainsPath(t, denyWithGitConfigAllowed, nestedGitConfig)
	expectContainsPath(t, denyWithGitConfigAllowed, rootHooks)
	expectContainsPath(t, denyWithGitConfigAllowed, nestedHooks)
}

func TestGenerateFilesystemArgsLinux_IncludesMandatoryDenyPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	tmp := t.TempDir()
	restore := chdirForTest(t, tmp)
	defer restore()

	mustWriteFile(t, ".bashrc", "export SAFE=1")

	args := generateFilesystemArgsLinux(context.Background(),
		nil,
		&FsWriteRestrictionConfig{AllowOnly: []string{"."}, DenyWithinAllow: []string{}},
		nil,
		0,
		false,
	)

	deniedPath := NormalizePathForSandbox(".bashrc")
	if !containsArgTriplet(args, "--ro-bind", deniedPath, deniedPath) {
		t.Fatalf("expected mandatory deny path %q to be mounted read-only, args: %#v", deniedPath, args)
	}
}

func TestLinuxGetMandatoryDenyPaths_RespectsSearchDepth(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	if Which("rg") == "" {
		t.Skip("ripgrep (rg) not available")
	}

	tmp := t.TempDir()
	restore := chdirForTest(t, tmp)
	defer restore()

	deepDangerousFile := filepath.Join("a", "b", "c", "d", ".bashrc")
	mustMkdirAll(t, filepath.Dir(deepDangerousFile))
	mustWriteFile(t, deepDangerousFile, "export TEST=1")

	lowDepth := linuxGetMandatoryDenyPaths(context.Background(), nil, 2, false)
	highDepth := linuxGetMandatoryDenyPaths(context.Background(), nil, 8, false)

	deepDangerousAbs := filepath.Join(tmp, deepDangerousFile)
	expectNotContainsPath(t, lowDepth, deepDangerousAbs)
	expectContainsPath(t, highDepth, deepDangerousAbs)
}

func chdirForTest(t *testing.T, dir string) func() {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("failed to chdir to %s: %v", dir, err)
	}
	return func() {
		_ = os.Chdir(cwd)
	}
}

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("failed to mkdir %s: %v", dir, err)
	}
}

func mustWriteFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func expectContainsPath(t *testing.T, paths []string, want string) {
	t.Helper()
	want = filepath.Clean(want)
	for _, p := range paths {
		if filepath.Clean(p) == want {
			return
		}
	}
	t.Fatalf("expected path %q in deny paths, got: %#v", want, paths)
}

func expectNotContainsPath(t *testing.T, paths []string, want string) {
	t.Helper()
	want = filepath.Clean(want)
	for _, p := range paths {
		if filepath.Clean(p) == want {
			t.Fatalf("did not expect path %q in deny paths, got: %#v", want, paths)
		}
	}
}

func containsArgTriplet(args []string, first, second, third string) bool {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == first && args[i+1] == second && args[i+2] == third {
			return true
		}
	}
	return false
}

func resetBwrapTrackingForTest() {
	bwrapCleanupMu.Lock()
	bwrapMountPoints = map[string]struct{}{}
	bwrapSyntheticSources = map[string]struct{}{}
	bwrapCleanupMu.Unlock()
}

func bwrapTrackingCountsForTest() (mountPoints int, syntheticSources int) {
	bwrapCleanupMu.Lock()
	defer bwrapCleanupMu.Unlock()
	return len(bwrapMountPoints), len(bwrapSyntheticSources)
}

func isBwrapSyntheticSourceTrackedForTest(path string) bool {
	bwrapCleanupMu.Lock()
	defer bwrapCleanupMu.Unlock()
	_, ok := bwrapSyntheticSources[path]
	return ok
}

// ---------------------------------------------------------------------------
// hasFileAncestor
// ---------------------------------------------------------------------------

func TestHasFileAncestor_ReturnsTrueWhenParentIsFile(t *testing.T) {
	tmp := t.TempDir()
	// Create a regular file where a directory would normally be expected.
	filePath := filepath.Join(tmp, ".git")
	mustWriteFile(t, filePath, "gitdir: /somewhere/else")

	// .git is a file, so .git/hooks can never be created.
	target := filepath.Join(tmp, ".git", "hooks")
	if !hasFileAncestor(target) {
		t.Fatalf("expected hasFileAncestor(%q) = true", target)
	}
}

func TestHasFileAncestor_ReturnsFalseWhenAllDirs(t *testing.T) {
	tmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(tmp, "a", "b"))

	target := filepath.Join(tmp, "a", "b", "c")
	if hasFileAncestor(target) {
		t.Fatalf("expected hasFileAncestor(%q) = false", target)
	}
}

func TestHasFileAncestor_ReturnsFalseForFullyNonExistent(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "does", "not", "exist")
	if hasFileAncestor(target) {
		t.Fatalf("expected hasFileAncestor(%q) = false", target)
	}
}

// ---------------------------------------------------------------------------
// findFirstNonExistentComponent
// ---------------------------------------------------------------------------

func TestFindFirstNonExistentComponent_ReturnsFirstMissing(t *testing.T) {
	tmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(tmp, "existing"))
	target := filepath.Join(tmp, "existing", "missing", "deep")

	got := findFirstNonExistentComponent(target)
	want := filepath.Join(tmp, "existing", "missing")
	if got != want {
		t.Fatalf("findFirstNonExistentComponent(%q) = %q, want %q", target, got, want)
	}
}

func TestFindFirstNonExistentComponent_ReturnsLeafWhenOnlyLeafMissing(t *testing.T) {
	tmp := t.TempDir()
	mustMkdirAll(t, filepath.Join(tmp, "parent"))
	target := filepath.Join(tmp, "parent", "leaf")

	got := findFirstNonExistentComponent(target)
	if got != target {
		t.Fatalf("findFirstNonExistentComponent(%q) = %q, want target itself", target, got)
	}
}

// ---------------------------------------------------------------------------
// Non-existent deny path protection in generateFilesystemArgsLinux
// ---------------------------------------------------------------------------

func TestGenerateFilesystemArgsLinux_BlocksNonExistentDenyPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	tmp := t.TempDir()
	restore := chdirForTest(t, tmp)
	defer restore()

	// Create an allowed write directory.
	mustMkdirAll(t, "project")

	// The deny path does NOT exist yet — the protection should still mount
	// something to block its creation.
	nonExistentDeny := filepath.Join(tmp, "project", ".bashrc")

	args := generateFilesystemArgsLinux(context.Background(),
		nil,
		&FsWriteRestrictionConfig{
			AllowOnly:       []string{filepath.Join(tmp, "project")},
			DenyWithinAllow: []string{nonExistentDeny},
		},
		nil,
		0,
		false,
	)

	// We expect --ro-bind /dev/null <nonExistentDeny> because .bashrc is the
	// leaf (first non-existent component == the deny path itself).
	if !containsArgTriplet(args, "--ro-bind", "/dev/null", nonExistentDeny) {
		t.Fatalf("expected --ro-bind /dev/null %s in args: %v", nonExistentDeny, args)
	}
}

func TestGenerateFilesystemArgsLinux_BlocksNonExistentDenyPathsIntermediate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	tmp := t.TempDir()
	restore := chdirForTest(t, tmp)
	defer restore()

	mustMkdirAll(t, "project")

	// Deny path whose parent also does not exist yet.
	deepDeny := filepath.Join(tmp, "project", ".claude", "settings.json")

	args := generateFilesystemArgsLinux(context.Background(),
		nil,
		&FsWriteRestrictionConfig{
			AllowOnly:       []string{filepath.Join(tmp, "project")},
			DenyWithinAllow: []string{deepDeny},
		},
		nil,
		0,
		false,
	)

	// The first non-existent component is ".claude" (an intermediate dir).
	// We expect an empty-dir bind (not /dev/null).
	firstMissing := filepath.Join(tmp, "project", ".claude")
	found := false
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--ro-bind" && args[i+2] == firstMissing {
			// The source should NOT be /dev/null (it should be a temp empty dir).
			if args[i+1] == "/dev/null" {
				t.Fatalf("expected empty-dir bind for intermediate component, got /dev/null")
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected --ro-bind <empty-dir> %s in args: %v", firstMissing, args)
	}
}

func TestGenerateFilesystemArgsLinux_TracksIntermediateSyntheticSourceForCleanup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	resetBwrapTrackingForTest()
	t.Cleanup(resetBwrapTrackingForTest)

	tmp := t.TempDir()
	restore := chdirForTest(t, tmp)
	defer restore()

	mustMkdirAll(t, "project")

	deepDeny := filepath.Join(tmp, "project", ".claude", "settings.json")
	args := generateFilesystemArgsLinux(context.Background(),
		nil,
		&FsWriteRestrictionConfig{
			AllowOnly:       []string{filepath.Join(tmp, "project")},
			DenyWithinAllow: []string{deepDeny},
		},
		nil,
		0,
		false,
	)

	firstMissing := filepath.Join(tmp, "project", ".claude")
	syntheticSource := ""
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--ro-bind" && args[i+2] == firstMissing && args[i+1] != "/dev/null" {
			syntheticSource = args[i+1]
			break
		}
	}
	if syntheticSource == "" {
		t.Fatalf("expected synthetic source mount for %s, args: %v", firstMissing, args)
	}
	if !isBwrapSyntheticSourceTrackedForTest(syntheticSource) {
		t.Fatalf("expected synthetic source %s to be tracked", syntheticSource)
	}
	if !fileExistsOrDir(syntheticSource) {
		t.Fatalf("expected synthetic source %s to exist on disk", syntheticSource)
	}

	CleanupBwrapMountPoints()

	if fileExistsOrDir(syntheticSource) {
		t.Fatalf("expected synthetic source %s to be removed during cleanup", syntheticSource)
	}
}

func TestGenerateFilesystemArgsLinux_SkipsNonExistentDenyWithFileAncestor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	tmp := t.TempDir()
	restore := chdirForTest(t, tmp)
	defer restore()

	mustMkdirAll(t, "worktree")
	// Simulate a git worktree: .git is a regular file, not a directory.
	mustWriteFile(t, filepath.Join("worktree", ".git"), "gitdir: /somewhere")

	denyPath := filepath.Join(tmp, "worktree", ".git", "hooks")

	args := generateFilesystemArgsLinux(context.Background(),
		nil,
		&FsWriteRestrictionConfig{
			AllowOnly:       []string{filepath.Join(tmp, "worktree")},
			DenyWithinAllow: []string{denyPath},
		},
		nil,
		0,
		false,
	)

	// Because .git is a file the deny path can never be created — no bind
	// should be generated for it.
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--ro-bind" && args[i+2] == denyPath {
			t.Fatalf("did not expect bind for deny path %s under file ancestor, args: %v", denyPath, args)
		}
	}
}

func TestGenerateFilesystemArgsLinux_SkipsNonExistentDenyOutsideAllowed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	tmp := t.TempDir()
	restore := chdirForTest(t, tmp)
	defer restore()

	mustMkdirAll(t, "project")
	mustMkdirAll(t, "other")

	// Deny path is under /tmp/.../other which is NOT in the allowed list.
	denyPath := filepath.Join(tmp, "other", ".bashrc")

	args := generateFilesystemArgsLinux(context.Background(),
		nil,
		&FsWriteRestrictionConfig{
			AllowOnly:       []string{filepath.Join(tmp, "project")},
			DenyWithinAllow: []string{denyPath},
		},
		nil,
		0,
		false,
	)

	// Already protected by the root --ro-bind / /, so no extra bind expected.
	for i := 0; i+2 < len(args); i++ {
		if args[i+2] == denyPath {
			t.Fatalf("did not expect bind for deny path outside allowed paths, args: %v", args)
		}
	}
}

func TestFindSymlinkInPath_ReturnsSymlinkWithinAllowedPath(t *testing.T) {
	tmp := t.TempDir()
	projectDir := filepath.Join(tmp, "project")
	decoyDir := filepath.Join(projectDir, "decoy")
	mustMkdirAll(t, decoyDir)

	symlinkPath := filepath.Join(projectDir, ".claude")
	if err := os.Symlink(decoyDir, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink %s -> %s: %v", symlinkPath, decoyDir, err)
	}

	target := filepath.Join(projectDir, ".claude", "settings.json")
	got := findSymlinkInPath(target, []string{projectDir})
	if got != symlinkPath {
		t.Fatalf("expected symlink %q, got %q", symlinkPath, got)
	}
}

func TestGenerateFilesystemArgsLinux_BlocksSymlinkReplacementAttack(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}

	tmp := t.TempDir()
	restore := chdirForTest(t, tmp)
	defer restore()

	projectDir := filepath.Join(tmp, "project")
	decoyDir := filepath.Join(projectDir, "decoy")
	mustMkdirAll(t, decoyDir)

	symlinkPath := filepath.Join(projectDir, ".claude")
	if err := os.Symlink(decoyDir, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink %s -> %s: %v", symlinkPath, decoyDir, err)
	}

	denyPath := filepath.Join(projectDir, ".claude", "settings.json")
	args := generateFilesystemArgsLinux(context.Background(),
		nil,
		&FsWriteRestrictionConfig{
			AllowOnly:       []string{projectDir},
			DenyWithinAllow: []string{denyPath},
		},
		nil,
		0,
		false,
	)

	if !containsArgTriplet(args, "--ro-bind", "/dev/null", symlinkPath) {
		t.Fatalf("expected symlink protection bind for %s, args: %v", symlinkPath, args)
	}
}

// ---------------------------------------------------------------------------
// CleanupBwrapMountPoints
// ---------------------------------------------------------------------------

func TestCleanupBwrapMountPoints_RemovesEmptyFileAndDir(t *testing.T) {
	resetBwrapTrackingForTest()
	t.Cleanup(resetBwrapTrackingForTest)

	tmp := t.TempDir()

	emptyFile := filepath.Join(tmp, "empty-file")
	mustWriteFile(t, emptyFile, "")

	emptyDir := filepath.Join(tmp, "empty-dir")
	mustMkdirAll(t, emptyDir)

	syntheticSource := filepath.Join(tmp, "synthetic-source")
	mustMkdirAll(t, syntheticSource)

	trackBwrapMountPoint(emptyFile)
	trackBwrapMountPoint(emptyDir)
	trackBwrapSyntheticSource(syntheticSource)

	CleanupBwrapMountPoints()

	if fileExistsOrDir(emptyFile) {
		t.Fatalf("expected empty file %s to be removed", emptyFile)
	}
	if fileExistsOrDir(emptyDir) {
		t.Fatalf("expected empty dir %s to be removed", emptyDir)
	}
	if fileExistsOrDir(syntheticSource) {
		t.Fatalf("expected synthetic source dir %s to be removed", syntheticSource)
	}
	mountCount, sourceCount := bwrapTrackingCountsForTest()
	if mountCount != 0 || sourceCount != 0 {
		t.Fatalf("expected tracking sets to be cleared, mountPoints=%d syntheticSources=%d", mountCount, sourceCount)
	}
}

func TestCleanupBwrapMountPoints_LeavesNonEmptyAlone(t *testing.T) {
	resetBwrapTrackingForTest()
	t.Cleanup(resetBwrapTrackingForTest)

	tmp := t.TempDir()

	nonEmptyFile := filepath.Join(tmp, "has-content")
	mustWriteFile(t, nonEmptyFile, "real data")

	nonEmptyDir := filepath.Join(tmp, "has-child")
	mustMkdirAll(t, nonEmptyDir)
	mustWriteFile(t, filepath.Join(nonEmptyDir, "child.txt"), "x")

	nonEmptySyntheticSource := filepath.Join(tmp, "synthetic-has-child")
	mustMkdirAll(t, nonEmptySyntheticSource)
	mustWriteFile(t, filepath.Join(nonEmptySyntheticSource, "child.txt"), "x")

	trackBwrapMountPoint(nonEmptyFile)
	trackBwrapMountPoint(nonEmptyDir)
	trackBwrapSyntheticSource(nonEmptySyntheticSource)

	CleanupBwrapMountPoints()

	if !fileExistsOrDir(nonEmptyFile) {
		t.Fatalf("non-empty file %s should not have been removed", nonEmptyFile)
	}
	if !fileExistsOrDir(nonEmptyDir) {
		t.Fatalf("non-empty dir %s should not have been removed", nonEmptyDir)
	}
	if !fileExistsOrDir(nonEmptySyntheticSource) {
		t.Fatalf("non-empty synthetic source dir %s should not have been removed", nonEmptySyntheticSource)
	}
}

func TestManagerCleanupAfterCommand_CleansTrackedBwrapArtifacts(t *testing.T) {
	resetBwrapTrackingForTest()
	t.Cleanup(resetBwrapTrackingForTest)

	tmp := t.TempDir()
	emptyFile := filepath.Join(tmp, "empty-file")
	mustWriteFile(t, emptyFile, "")
	trackBwrapMountPoint(emptyFile)

	m := NewManager()
	m.CleanupAfterCommand()

	if fileExistsOrDir(emptyFile) {
		t.Fatalf("expected manager command cleanup to remove %s", emptyFile)
	}
}

func TestManagerReset_CleansTrackedBwrapArtifacts(t *testing.T) {
	resetBwrapTrackingForTest()
	t.Cleanup(resetBwrapTrackingForTest)

	tmp := t.TempDir()
	emptyDir := filepath.Join(tmp, "empty-dir")
	mustMkdirAll(t, emptyDir)
	trackBwrapMountPoint(emptyDir)

	m := NewManager()
	if err := m.Reset(context.Background()); err != nil {
		t.Fatalf("reset failed: %v", err)
	}

	if fileExistsOrDir(emptyDir) {
		t.Fatalf("expected manager reset cleanup to remove %s", emptyDir)
	}
}
