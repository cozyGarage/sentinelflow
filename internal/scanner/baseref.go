package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/baseline"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// filterBaselineRef drops findings that already exist at ref, so only findings
// introduced since ref remain. Unlike --diff-base it matches by fingerprint, so
// a pre-existing finding that moved to another line is still recognised.
func (e *Engine) filterBaselineRef(ctx context.Context, targetPath string, result *api.ScanResult) error {
	baseFindings, err := e.scanAtRef(ctx, targetPath, e.BaselineRef)
	if err != nil {
		return fmt.Errorf("baseline ref %s: %w", e.BaselineRef, err)
	}

	bl := &baseline.File{Version: baseline.VersionV2}
	for _, f := range baseFindings {
		bl.Findings = append(bl.Findings, baseline.Entry{Fingerprint: fingerprint.Of(f)})
	}
	before := result.Findings
	result.Findings = baseline.Filter(before, bl)
	suppressed := len(before) - len(result.Findings)

	if result.Baseline == nil {
		result.Baseline = &api.BaselineSummary{Total: len(before)}
	}
	result.Baseline.Enabled = true
	result.Baseline.Suppressed += suppressed
	result.Baseline.New = len(result.Findings)
	return nil
}

// scanAtRef checks ref out into a temporary worktree and scans the same
// relative path there with the same scanners.
func (e *Engine) scanAtRef(ctx context.Context, targetPath, ref string) ([]api.Finding, error) {
	top, err := runGit(ctx, targetPath, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	// show-toplevel resolves symlinks; resolve targetPath too so Rel stays inside the repo.
	real, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(top, real)
	if err != nil {
		return nil, err
	}

	tmp, err := os.MkdirTemp("", "sentinelflow-baseref-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	wt := filepath.Join(tmp, "wt")
	if _, err := runGit(ctx, top, "worktree", "add", "--detach", "--quiet", wt, ref); err != nil {
		return nil, err
	}
	// Background context: clean up even when the scan deadline has passed.
	defer func() { _, _ = runGit(context.Background(), top, "worktree", "remove", "--force", wt) }()

	cfg := *e.config
	cfg.Baseline.Enabled = false
	cfg.DiffBase = ""
	sub := &Engine{config: &cfg, scanners: e.scanners}
	res, err := sub.Scan(ctx, filepath.Join(wt, rel))
	if err != nil {
		return nil, err
	}
	return res.Findings, nil
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
