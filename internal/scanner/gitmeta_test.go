package scanner

import (
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestCollectGitMetadataFallsBackToCIEnv(t *testing.T) {
	t.Setenv("GITHUB_SHA", "deadbeefcafebabe")
	t.Setenv("GITHUB_HEAD_REF", "refs/heads/feature-x")

	dir := t.TempDir()
	// Force Git metadata lookup to fail so this test always exercises the env fallback.
	t.Setenv("GIT_DIR", filepath.Join(dir, "missing-git-dir"))
	e := &Engine{}
	meta := api.ScanMetadata{}
	e.collectGitMetadata(dir, &meta)
	if meta.GitCommit != "deadbeefcafebabe" {
		t.Fatalf("commit=%q", meta.GitCommit)
	}
	if meta.GitBranch != "feature-x" {
		t.Fatalf("branch=%q", meta.GitBranch)
	}
}

func TestFirstEnv(t *testing.T) {
	t.Setenv("CI_COMMIT_SHA", "abc123")
	if got := firstEnv("MISSING", "CI_COMMIT_SHA"); got != "abc123" {
		t.Fatalf("got %q", got)
	}
}
