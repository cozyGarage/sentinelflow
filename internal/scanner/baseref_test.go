package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestSC079_BaselineRefFingerprintOmitsTemporaryCheckoutPrefix(t *testing.T) {
	root := filepath.Join(t.TempDir(), "checkout", "nested")
	file := filepath.Join(root, "src", "main.go")
	finding := api.Finding{RuleID: "rule", Location: api.Location{File: file, Snippet: "vulnerable()"}, Fingerprint: "stale-path-bound-fingerprint"}
	got := findingsForPathComparison([]api.Finding{finding}, root)
	if got[0].Location.File != "src/main.go" {
		t.Fatalf("path=%q, want relative path", got[0].Location.File)
	}
	if got[0].Fingerprint == finding.Fingerprint || got[0].Fingerprint != fingerprint.Of(got[0]) {
		t.Fatalf("fingerprint was not recomputed: %+v", got[0])
	}
	otherRoot := filepath.Join(t.TempDir(), "different-checkout", "nested")
	other := finding
	other.Location.File = filepath.Join(otherRoot, "src", "main.go")
	other = findingsForPathComparison([]api.Finding{other}, otherRoot)[0]
	if got[0].Fingerprint != other.Fingerprint {
		t.Fatal("temporary checkout prefixes must not change finding identity")
	}
}

func TestSC051_BaselineRefRejectsHeadOrBaseScannerFailures(t *testing.T) {
	for _, failOnBase := range []bool{false, true} {
		name := "head failure"
		if failOnBase {
			name = "base failure"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			git := func(args ...string) {
				t.Helper()
				cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.email=t@t", "-c", "user.name=t"}, args...)...)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "finding.txt"), []byte("present\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if failOnBase {
				if err := os.WriteFile(filepath.Join(root, "base-fails"), []byte("yes"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			git("init", "-q")
			git("add", ".")
			git("commit", "-q", "-m", "baseline")
			if failOnBase {
				if err := os.Remove(filepath.Join(root, "base-fails")); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(root, "base-fails"), []byte("yes"), 0644); err != nil {
				t.Fatal(err)
			}

			engine := NewEngine(config.Default())
			engine.scanners = []Scanner{&baselineFailureScanner{failWhenMarker: true}}
			engine.scannerFactory = nil
			engine.BaselineRef = "HEAD"
			result, err := engine.Scan(context.Background(), root)
			if err == nil {
				t.Fatal("incomplete head/base scan must reject the delta")
			}
			if result == nil || len(result.Findings) != 1 || result.Findings[0].RuleID != "test.rule" {
				t.Fatalf("head evidence must survive comparison failure: result=%+v", result)
			}
		})
	}
}

func TestSC051_ScannerRunErrorCoexistsWithNilEngineError(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "base-fails"), []byte("yes"), 0644); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(config.Default())
	engine.scanners = []Scanner{&baselineFailureScanner{failWhenMarker: true}}
	engine.scannerFactory = nil
	result, err := engine.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("scanner outcome errors are recorded separately from engine errors: %v", err)
	}
	if result == nil || len(result.Findings) != 1 || len(result.ScannerRuns) != 1 || result.ScannerRuns[0].Error == "" {
		t.Fatalf("expected retained finding and scanner run error: %+v", result)
	}
}

func TestSC052_RejectsMissingOrFailedScannerOutcome(t *testing.T) {
	engine := &Engine{scanners: []Scanner{&baselineFailureScanner{}}}
	for _, tc := range []struct {
		name string
		runs []api.ScannerRun
	}{
		{name: "missing", runs: nil},
		{name: "failed", runs: []api.ScannerRun{{Scanner: "test-scanner", Error: "injected"}}},
		{name: "wrong scanner", runs: []api.ScannerRun{{Scanner: "other"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := engine.validateBaselineRuns(tc.runs, "base"); err == nil {
				t.Fatal("incomplete or incomparable base outcomes must fail validation")
			}
		})
	}
}

func TestSC053_BaselineRefUsesFreshComparableScannerInstances(t *testing.T) {
	root := initBaselineRepo(t)
	cfg := config.Default()
	var constructed int
	factory := func(*config.Config) []Scanner {
		constructed++
		return []Scanner{&oneShotBaselineScanner{}}
	}
	engine := &Engine{config: cfg, scanners: factory(cfg), scannerFactory: factory, BaselineRef: "HEAD"}
	result, err := engine.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if constructed != 2 {
		t.Fatalf("want distinct head and base scanner instances; factory called %d times", constructed)
	}
	if len(result.Findings) != 0 || result.Baseline == nil || result.Baseline.Suppressed != 1 {
		t.Fatalf("comparable completed baseline should suppress the old finding: %+v", result)
	}
}

func TestSC053_RejectsScannerSetMismatch(t *testing.T) {
	if err := validateComparableScanners([]Scanner{&oneShotBaselineScanner{}}, nil); err == nil {
		t.Fatal("different scanner sets must not be compared")
	}
}

func TestSC054_BaselineRefCleanupFailureIsVisible(t *testing.T) {
	root := initBaselineRepo(t)
	engine := NewEngine(config.Default())
	engine.scanners = []Scanner{&oneShotBaselineScanner{}}
	engine.scannerFactory = nil
	engine.BaselineRef = "HEAD"
	var worktree string
	engine.gitRunner = func(ctx context.Context, dir string, args ...string) (string, error) {
		if len(args) >= 3 && args[0] == "worktree" && args[1] == "add" {
			worktree = args[len(args)-2]
		}
		if len(args) >= 3 && args[0] == "worktree" && args[1] == "remove" {
			return "", errors.New("injected cleanup failure")
		}
		return runGit(ctx, dir, args...)
	}
	result, err := engine.Scan(context.Background(), root)
	if err == nil || !strings.Contains(err.Error(), "injected cleanup failure") {
		t.Fatalf("cleanup failure must be visible, got result=%+v err=%v", result, err)
	}
	if worktree == "" {
		t.Fatal("test did not observe temporary worktree path")
	}
	// Remove the deliberately leaked registration so the fixture leaves no git state behind.
	if _, cleanupErr := runGit(context.Background(), root, "worktree", "remove", "--force", worktree); cleanupErr != nil {
		t.Fatalf("test cleanup: %v", cleanupErr)
	}
	if cleanupErr := os.RemoveAll(filepath.Dir(worktree)); cleanupErr != nil {
		t.Fatalf("remove deliberately retained temporary directory: %v", cleanupErr)
	}
}

func TestSC054_WorktreeAddFailureCleansPartialRegistration(t *testing.T) {
	root := initBaselineRepo(t)
	engine := NewEngine(config.Default())
	engine.BaselineRef = "HEAD"
	var worktree string
	engine.gitRunner = func(ctx context.Context, dir string, args ...string) (string, error) {
		if len(args) >= 3 && args[0] == "worktree" && args[1] == "add" {
			worktree = args[len(args)-2]
			if _, err := runGit(ctx, dir, args...); err != nil {
				return "", err
			}
			// Simulate a timeout/error reported after Git has registered the
			// worktree, which is the state the early-error cleanup must handle.
			return "", context.DeadlineExceeded
		}
		return runGit(ctx, dir, args...)
	}
	_, err := engine.scanAtRef(context.Background(), root, "HEAD")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want injected worktree-add failure, got %v", err)
	}
	if worktree == "" {
		t.Fatal("test did not observe temporary worktree path")
	}
	worktrees, gitErr := runGit(context.Background(), root, "worktree", "list")
	if gitErr != nil {
		t.Fatal(gitErr)
	}
	if lines := strings.Split(strings.TrimSpace(worktrees), "\n"); len(lines) != 1 {
		t.Fatalf("partial worktree registration was not removed:\n%s", worktrees)
	}
	if _, statErr := os.Stat(filepath.Dir(worktree)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("temporary worktree directory remains: %v", statErr)
	}
}

func initBaselineRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "finding.txt"), []byte("finding\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", root, "init", "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	for _, args := range [][]string{{"add", "."}, {"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base"}} {
		cmd = exec.Command("git", append([]string{"-C", root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return root
}

type oneShotBaselineScanner struct{ calls int }

func (s *oneShotBaselineScanner) Name() string         { return "test-scanner" }
func (s *oneShotBaselineScanner) Supports(string) bool { return true }
func (s *oneShotBaselineScanner) Scan(_ context.Context, _ string, _ interface{}) (*types.ScannerResult, error) {
	s.calls++
	if s.calls > 1 {
		return nil, errors.New("scanner instance reused")
	}
	f := api.Finding{ID: "stable", Scanner: "test-scanner", RuleID: "test.rule", Title: "test", Location: api.Location{File: "finding.txt"}}
	return &types.ScannerResult{Findings: []api.Finding{f}, FilesCount: 1}, nil
}

type baselineFailureScanner struct{ failWhenMarker bool }

func (s *baselineFailureScanner) Name() string         { return "test-scanner" }
func (s *baselineFailureScanner) Supports(string) bool { return true }
func (s *baselineFailureScanner) Scan(_ context.Context, path string, _ interface{}) (*types.ScannerResult, error) {
	f := api.Finding{ID: "finding-1", Scanner: "test-scanner", RuleID: "test.rule", Title: "test", Location: api.Location{File: "finding.txt"}}
	_, markerErr := os.Stat(filepath.Join(path, "base-fails"))
	if (markerErr == nil) == s.failWhenMarker {
		return &types.ScannerResult{Findings: []api.Finding{f}, FilesCount: 1}, errors.New("injected scanner failure")
	}
	return &types.ScannerResult{Findings: []api.Finding{f}, FilesCount: 1}, nil
}

func TestBaselineRefReportsOnlyNewFindings(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.email=t@t", "-c", "user.name=t"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	git("init", "-q")
	write("old/Dockerfile", "FROM nginx:latest\n")
	git("add", ".")
	git("commit", "-q", "-m", "base")
	// Shift the old finding down a line, and add a new one.
	write("old/Dockerfile", "# comment\nFROM nginx:latest\n")
	write("new/Dockerfile", "FROM nginx:latest\n")

	cfg := config.Default()
	cfg.Scanners.IaC.Enabled = true
	cfg.Scanners.Secrets.Enabled = false
	cfg.Scanners.Dependencies.Enabled = false
	cfg.Scanners.SAST.Enabled = false
	cfg.Policies.Enabled = false

	full, err := NewEngine(cfg).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Findings) == 0 {
		t.Fatal("fixture should produce findings")
	}

	engine := NewEngine(cfg)
	engine.BaselineRef = "HEAD"
	beforeHead, err := runGit(context.Background(), root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	beforeStatus, err := runGit(context.Background(), root, "status", "--porcelain")
	if err != nil {
		t.Fatal(err)
	}
	beforeIndex, err := runGit(context.Background(), root, "diff", "--cached", "--binary")
	if err != nil {
		t.Fatal(err)
	}
	res, err := engine.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 || len(res.Findings) >= len(full.Findings) {
		t.Fatalf("want a strict subset of %d findings, got %d", len(full.Findings), len(res.Findings))
	}
	for _, f := range res.Findings {
		if filepath.ToSlash(f.Location.File) != "new/Dockerfile" {
			t.Errorf("pre-existing finding leaked through: %s %s", f.Location.File, f.RuleID)
		}
	}
	if res.Baseline == nil || res.Baseline.Suppressed != len(full.Findings)-len(res.Findings) {
		t.Fatalf("baseline summary wrong: %+v", res.Baseline)
	}
	var refSuppressed int
	for _, observation := range res.Suppressed {
		if observation.Source == "baseline-ref" && observation.Authority == "repository_ref" && observation.Fingerprint != "" {
			refSuppressed++
		}
	}
	if refSuppressed != res.Baseline.Suppressed {
		t.Fatalf("baseline-ref observations=%d summary=%+v", refSuppressed, res.Baseline)
	}
	out, _ := exec.Command("git", "-C", root, "worktree", "list").Output()
	if n := len(strings.Split(strings.TrimSpace(string(out)), "\n")); n != 1 {
		t.Fatalf("temporary worktree not removed:\n%s", out)
	}
	afterHead, err := runGit(context.Background(), root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	afterStatus, err := runGit(context.Background(), root, "status", "--porcelain")
	if err != nil {
		t.Fatal(err)
	}
	afterIndex, err := runGit(context.Background(), root, "diff", "--cached", "--binary")
	if err != nil {
		t.Fatal(err)
	}
	if beforeHead != afterHead || beforeStatus != afterStatus || beforeIndex != afterIndex {
		t.Fatalf("baseline comparison changed caller checkout: HEAD %q -> %q; status %q -> %q; index changed=%t", beforeHead, afterHead, beforeStatus, afterStatus, beforeIndex != afterIndex)
	}
}

func TestSC054_TimeoutCleansTemporaryWorktree(t *testing.T) {
	root := initBaselineRepo(t)
	engine := NewEngine(config.Default())
	started := make(chan struct{})
	engine.scanners = []Scanner{&blockingBaseScanner{started: started}}
	engine.scannerFactory = nil
	engine.BaselineRef = "HEAD"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startedAt := time.Now()
	result := make(chan error, 1)
	go func() {
		_, err := engine.Scan(ctx, root)
		result <- err
	}()
	select {
	case <-engine.scanners[0].(*blockingBaseScanner).started:
		cancel()
	case <-time.After(5 * time.Second):
		t.Fatal("base scanner did not start")
	}
	err := <-result
	if err == nil {
		t.Fatal("expired comparison must return an incomplete-comparison error")
	}
	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		t.Fatalf("cancelled comparison took %s; cleanup must remain bounded", elapsed)
	}
	out, gitErr := runGit(context.Background(), root, "worktree", "list")
	if gitErr != nil {
		t.Fatal(gitErr)
	}
	if n := len(strings.Split(strings.TrimSpace(out), "\n")); n != 1 {
		t.Fatalf("timed-out comparison leaked worktree registration:\n%s", out)
	}
}

func TestSC054_WorktreeAddFailurePreservesCallerCheckout(t *testing.T) {
	root := initBaselineRepo(t)
	engine := NewEngine(config.Default())
	engine.scanners = []Scanner{&oneShotBaselineScanner{}}
	engine.scannerFactory = nil
	engine.BaselineRef = "missing-ref"
	beforeHead, err := runGit(context.Background(), root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	beforeStatus, err := runGit(context.Background(), root, "status", "--porcelain")
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), root)
	if err == nil {
		t.Fatal("invalid baseline ref must fail comparison")
	}
	if result == nil || len(result.Findings) != 1 {
		t.Fatalf("head observation should remain available: %+v", result)
	}
	afterHead, err := runGit(context.Background(), root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	afterStatus, err := runGit(context.Background(), root, "status", "--porcelain")
	if err != nil {
		t.Fatal(err)
	}
	worktrees, err := runGit(context.Background(), root, "worktree", "list")
	if err != nil {
		t.Fatal(err)
	}
	if beforeHead != afterHead || beforeStatus != afterStatus || len(strings.Split(strings.TrimSpace(worktrees), "\n")) != 1 {
		t.Fatalf("failed worktree creation changed caller state: HEAD %q -> %q; status %q -> %q; worktrees:\n%s", beforeHead, afterHead, beforeStatus, afterStatus, worktrees)
	}
}

type blockingBaseScanner struct{ started chan struct{} }

func (*blockingBaseScanner) Name() string         { return "test-scanner" }
func (*blockingBaseScanner) Supports(string) bool { return true }
func (s *blockingBaseScanner) Scan(ctx context.Context, path string, _ interface{}) (*types.ScannerResult, error) {
	if strings.Contains(path, "sentinelflow-baseref-") {
		close(s.started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f := api.Finding{ID: "stable", Scanner: "test-scanner", RuleID: "test.rule", Title: "test", Location: api.Location{File: "finding.txt"}}
	return &types.ScannerResult{Findings: []api.Finding{f}, FilesCount: 1}, nil
}
