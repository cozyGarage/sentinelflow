package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cozygarage/sentinelflow/internal/baseline"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// filterBaselineRef drops findings that already exist at ref, so only findings
// introduced since ref remain. Unlike --diff-base it matches by fingerprint, so
// a pre-existing finding that moved to another line is still recognised.
func (e *Engine) filterBaselineRef(ctx context.Context, targetPath string, result *api.ScanResult) error {
	if err := e.validateBaselineRuns(result.ScannerRuns, "head"); err != nil {
		return fmt.Errorf("head scan incomplete: %w", err)
	}
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

func (e *Engine) validateBaselineRuns(runs []api.ScannerRun, side string) error {
	if len(runs) != len(e.scanners) {
		return fmt.Errorf("%s scanner set incomplete: got %d outcomes, want %d", side, len(runs), len(e.scanners))
	}
	for i, scanner := range e.scanners {
		if runs[i].Scanner != scanner.Name() {
			return fmt.Errorf("%s scanner set mismatch at %d: got %q, want %q", side, i, runs[i].Scanner, scanner.Name())
		}
		if runs[i].Error != "" {
			return fmt.Errorf("%s scanner %s failed: %s", side, runs[i].Scanner, runs[i].Error)
		}
	}
	return nil
}

func validateComparableScanners(head, base []Scanner) error {
	if len(head) != len(base) {
		return fmt.Errorf("scanner set changed: head has %d scanners, base has %d", len(head), len(base))
	}
	for i := range head {
		if head[i].Name() != base[i].Name() {
			return fmt.Errorf("scanner set changed at %d: head has %q, base has %q", i, head[i].Name(), base[i].Name())
		}
	}
	return nil
}

// scanAtRef checks ref out into a temporary worktree and scans the same
// relative path there with the same scanners.
func (e *Engine) scanAtRef(ctx context.Context, targetPath, ref string) (findings []api.Finding, err error) {
	top, err := e.runGit(ctx, targetPath, "rev-parse", "--show-toplevel")
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
	wt := filepath.Join(tmp, "wt")
	if _, err := e.runGit(ctx, top, "worktree", "add", "--detach", "--quiet", wt, ref); err != nil {
		if removeErr := os.RemoveAll(tmp); removeErr != nil {
			return nil, errors.Join(err, fmt.Errorf("remove temporary directory %s: %w", tmp, removeErr))
		}
		return nil, err
	}
	worktreeAdded := true
	keepTemp := false
	defer func() {
		if worktreeAdded {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, cleanupErr := e.runGit(cleanupCtx, top, "worktree", "remove", "--force", wt)
			cancel()
			if cleanupErr != nil {
				keepTemp = true
				err = errors.Join(err, fmt.Errorf("remove temporary worktree %s: %w", wt, cleanupErr))
			}
		}
		if !keepTemp {
			if removeErr := os.RemoveAll(tmp); removeErr != nil {
				err = errors.Join(err, fmt.Errorf("remove temporary worktree directory %s: %w", tmp, removeErr))
			}
		}
	}()

	cfg := *e.config
	cfg.Baseline.Enabled = false
	cfg.DiffBase = ""
	baseScanners := e.scanners
	if e.scannerFactory != nil {
		baseScanners = e.scannerFactory(&cfg)
	}
	if err := validateComparableScanners(e.scanners, baseScanners); err != nil {
		return nil, err
	}
	sub := &Engine{config: &cfg, scanners: baseScanners}
	res, err := sub.Scan(ctx, filepath.Join(wt, rel))
	if err != nil {
		if res != nil {
			return res.Findings, err
		}
		return nil, err
	}
	if res == nil {
		return nil, errors.New("base scan returned no result")
	}
	if err := e.validateBaselineRuns(res.ScannerRuns, "base"); err != nil {
		return res.Findings, err
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
