package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cozygarage/sentinelflow/internal/baseline"
	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/dependencies"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestEngineInitialization(t *testing.T) {
	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets:      config.SecretsConfig{Enabled: true},
			IaC:          config.IaCConfig{Enabled: true},
			Dependencies: config.DependenciesConfig{Enabled: true},
		},
		Policies: config.PoliciesConfig{
			Enabled: true,
		},
	}

	engine := NewEngine(cfg)

	if engine == nil {
		t.Fatal("Failed to create engine")
	}

	tmpDir := t.TempDir()
	result, err := engine.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("scan empty dir: %v", err)
	}
	// Should have 4 scanners (secrets, iac, dependencies, policy)
	if len(result.ScannerRuns) != 4 {
		t.Errorf("Expected 4 scanner runs, got %d", len(result.ScannerRuns))
	}
}

func TestScanNonExistentPath(t *testing.T) {
	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{Enabled: true},
		},
	}

	engine := NewEngine(cfg)
	_, err := engine.Scan(context.Background(), "/nonexistent/path")

	if err == nil {
		t.Error("Expected error for nonexistent path")
	}
}

func TestScanEmptyDirectory(t *testing.T) {
	// Create temporary empty directory
	tmpDir := t.TempDir()

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{Enabled: true},
		},
	}

	engine := NewEngine(cfg)
	result, err := engine.Scan(context.Background(), tmpDir)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	// Should have metadata
	if result.Metadata.TargetPath != tmpDir {
		t.Errorf("Expected target path %s, got %s", tmpDir, result.Metadata.TargetPath)
	}
}

func TestCollectFilesSkipsHidden(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some files
	os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(tmpDir, ".hidden"), []byte("secret"), 0644)

	// Create .git directory
	gitDir := filepath.Join(tmpDir, ".git")
	os.Mkdir(gitDir, 0755)
	os.WriteFile(filepath.Join(gitDir, "config"), []byte("git config"), 0644)

	cfg := &config.Config{}
	engine := NewEngine(cfg)

	files, _, err := engine.collectFiles(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Failed to collect files: %v", err)
	}

	// Should include test.go and .hidden but not .git/config
	foundGitFile := false
	foundTestFile := false

	for _, f := range files {
		if filepath.Base(f) == "config" {
			foundGitFile = true
		}
		if filepath.Base(f) == "test.go" {
			foundTestFile = true
		}
	}

	if foundGitFile {
		t.Error("Should not collect files from .git directory")
	}

	if !foundTestFile {
		t.Error("Should collect test.go")
	}
}

func TestExcludeFiltering(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "main_test.go"), []byte("package main"), 0644)

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Exclude: []string{"*_test.go"},
			Secrets: config.SecretsConfig{
				Enabled: true,
			},
		},
	}

	engine := NewEngine(cfg)
	result, err := engine.Scan(context.Background(), tmpDir)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Check that excluded files were skipped
	for _, finding := range result.Findings {
		if filepath.Base(finding.Location.File) == "main_test.go" {
			t.Error("Should not scan files matching exclude pattern")
		}
	}
}

type stubScanner struct {
	name     string
	findings []api.Finding
	err      error
	delay    time.Duration
}

func (s *stubScanner) Name() string              { return s.name }
func (s *stubScanner) Supports(path string) bool { return true }
func (s *stubScanner) Scan(ctx context.Context, path string, opts interface{}) (*types.ScannerResult, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &types.ScannerResult{Findings: s.findings, FilesCount: 1}, s.err
}

func TestEngineOrdersResultsIndependentOfScannerCompletion(t *testing.T) {
	tmpDir := t.TempDir()
	engine := NewEngine(&config.Config{})
	engine.scanners = []Scanner{
		&stubScanner{
			name:  "slow",
			delay: 20 * time.Millisecond,
			findings: []api.Finding{{
				ID: "LOW-1", Scanner: "slow", Severity: api.SeverityLow,
				Location: api.Location{File: "z.go", StartLine: 10},
			}},
		},
		&stubScanner{
			name: "fast",
			findings: []api.Finding{{
				ID: "HIGH-1", Scanner: "fast", Severity: api.SeverityHigh,
				Location: api.Location{File: "a.go", StartLine: 2},
			}},
		},
	}

	result, err := engine.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.ScannerRuns) != 2 || result.ScannerRuns[0].Scanner != "slow" || result.ScannerRuns[1].Scanner != "fast" {
		t.Fatalf("scanner runs should retain configured order, got %+v", result.ScannerRuns)
	}
	if len(result.Findings) != 2 || result.Findings[0].ID != "HIGH-1" || result.Findings[1].ID != "LOW-1" {
		t.Fatalf("findings should sort by severity regardless of completion order, got %+v", result.Findings)
	}
}

func TestSC044_RequiredReachabilityFailureIsRecordedWithPartialFinding(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "svc")
	if err := os.MkdirAll(moduleDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "go.mod"), []byte("module example.com/svc\n\ngo 1.22\n"), 0644); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(t.TempDir(), "govulncheck")
	script := `#!/bin/sh
cat <<'JSON'
{"config":{"protocol_version":"v1.0.0","scan_level":"symbol"}}
{"finding":{"osv":"GO-1","trace":[{"module":"m","version":"v1.2.3","package":"m/p","function":"F"}]}}
JSON
exit 2
`
	if err := os.WriteFile(tool, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	old := dependencies.GovulncheckBin
	dependencies.GovulncheckBin = tool
	t.Cleanup(func() { dependencies.GovulncheckBin = old })

	cfg := config.Default()
	cfg.Scanners.Dependencies.Reachability = "required"
	e := NewEngine(cfg)
	e.scanners = []Scanner{&stubScanner{name: "dependencies", findings: []api.Finding{{
		Scanner: "dependencies", RuleID: "GO-1", Severity: api.SeverityHigh,
		Location: api.Location{File: "svc/go.mod"}, Metadata: map[string]any{"ecosystem": "go", "package": "m", "version": "v1.2.3"},
	}}}}
	result, err := e.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("scanner outcome should be recorded in the result: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Reachable == nil || !*result.Findings[0].Reachable {
		t.Fatalf("partial positive evidence should survive: %+v", result.Findings)
	}
	if len(result.ScannerRuns) != 1 || !strings.Contains(result.ScannerRuns[0].Error, "reachability:") {
		t.Fatalf("required reachability failure must be visible in scanner outcome: %+v", result.ScannerRuns)
	}
	if result.ScannerRuns[0].Status != api.ScanStatusFailed || result.Status != api.ScanStatusFailed {
		t.Fatalf("required reachability failure must remain failed in status: aggregate=%s run=%s", result.Status, result.ScannerRuns[0].Status)
	}
}

func TestEnginePreservesFindingsOnScannerError(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{}
	engine := NewEngine(cfg)
	engine.scanners = []Scanner{
		&stubScanner{
			name: "partial",
			findings: []api.Finding{
				{ID: "F1", Title: "kept", Severity: api.SeverityHigh, Scanner: "partial"},
			},
			err: fmt.Errorf("partial failure"),
		},
	}

	result, err := engine.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "F1" {
		t.Fatalf("expected findings preserved on error, got %+v", result.Findings)
	}
	if len(result.ScannerRuns) != 1 || result.ScannerRuns[0].Error == "" {
		t.Fatalf("expected ScannerRun.Error set, got %+v", result.ScannerRuns)
	}
	if result.ScannerRuns[0].Status != api.ScanStatusPartial || result.Status != api.ScanStatusPartial {
		t.Fatalf("findings plus scanner failure should be partial: result=%s run=%s", result.Status, result.ScannerRuns[0].Status)
	}
}

func TestEngineCleanZeroFindingsAndNoConfiguredScannersHaveDifferentOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		scanners []Scanner
		want     api.ScanStatus
	}{
		{name: "clean empty result", scanners: []Scanner{&stubScanner{name: "secrets"}}, want: api.ScanStatusComplete},
		{name: "no scanner ran", scanners: []Scanner{}, want: api.ScanStatusSkipped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := NewEngine(&config.Config{})
			engine.scanners = tc.scanners
			result, err := engine.Scan(context.Background(), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != tc.want {
				t.Fatalf("status = %q, want %q", result.Status, tc.want)
			}
		})
	}
}

func TestEngineVEXFailureReturnsCollectedFindings(t *testing.T) {
	for _, stage := range []string{"vex", "diff", "baseline"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			cfg := &config.Config{}
			engine := NewEngine(cfg)
			switch stage {
			case "vex":
				bad := filepath.Join(root, "bad-vex.json")
				if err := os.WriteFile(bad, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
				cfg.VEX = []string{bad}
			case "diff":
				engine.DiffBase = "ref-that-does-not-exist"
			case "baseline":
				bad := filepath.Join(root, "bad-baseline.json")
				if err := os.WriteFile(bad, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
				cfg.Baseline.Enabled = true
				cfg.Baseline.File = bad
			}
			engine.scanners = []Scanner{&stubScanner{name: "secrets", findings: []api.Finding{{ID: "F1", Scanner: "secrets", Severity: api.SeverityHigh}}}}
			result, err := engine.Scan(context.Background(), root)
			if err == nil {
				t.Fatalf("invalid %s input should fail the scan", stage)
			}
			if result == nil || len(result.Findings) != 1 || result.Findings[0].ID != "F1" {
				t.Fatalf("%s failure should preserve collected finding evidence: result=%+v err=%v", stage, result, err)
			}
			if result.Status != api.ScanStatusFailed || result.ScannerRuns[len(result.ScannerRuns)-1].Scanner != "postprocess:"+stage {
				t.Fatalf("%s failure must be explicit in overall outcome: status=%q runs=%+v", stage, result.Status, result.ScannerRuns)
			}
		})
	}
}

func TestSC093_UnknownReachabilityAndIncompleteBaseRetainHeadRisk(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"finding.txt": "synthetic finding\n",
		"go.mod":      "module example.com/app\n\ngo 1.22\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	git := exec.Command("git", "-C", root, "init", "-q")
	if out, err := git.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	for _, args := range [][]string{{"add", "."}, {"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base"}} {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	govulncheck := filepath.Join(t.TempDir(), "govulncheck")
	script := "#!/bin/sh\n[ \"$1\" = \"-json\" ] && [ \"$2\" = \"-C\" ] && [ \"$4\" = \"./...\" ] || exit 90\nprintf '%s\\n' '{\"config\":{\"protocol_version\":\"v1.0.0\",\"scan_level\":\"symbol\"}}'\ncase \"$3\" in *sentinelflow-baseref-*) exit 2;; esac\n"
	if err := os.WriteFile(govulncheck, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	previous := dependencies.GovulncheckBin
	dependencies.GovulncheckBin = govulncheck
	t.Cleanup(func() { dependencies.GovulncheckBin = previous })
	cfg := config.Default()
	cfg.Scanners.Dependencies.Reachability = "required"
	finding := api.Finding{ID: "risk", Scanner: "dependencies", RuleID: "GO-UNKNOWN", Severity: api.SeverityHigh,
		Location: api.Location{File: "go.mod"}, Metadata: map[string]any{"ecosystem": "go", "package": "example.com/lib", "version": "v1.2.3"}}
	e := NewEngine(cfg)
	e.scanners = []Scanner{&stubScanner{name: "dependencies", findings: []api.Finding{finding}}}
	e.scannerFactory = nil
	e.BaselineRef = "HEAD"
	result, err := e.Scan(context.Background(), root)
	if err == nil {
		t.Fatal("failed base reachability must reject baseline subtraction")
	}
	if result == nil || len(result.Findings) != 1 || result.Findings[0].Reachable != nil {
		t.Fatalf("unknown head risk must survive incomplete base comparison: result=%+v", result)
	}
	if len(result.ScannerRuns) < 2 || result.ScannerRuns[len(result.ScannerRuns)-1].Scanner != "baseline-ref" {
		t.Fatalf("comparison failure must be represented: %+v", result.ScannerRuns)
	}
}

func TestSC098_EngineRedactsScannerDiagnostics(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{}
	e := NewEngine(cfg)
	e.scanners = []Scanner{&stubScanner{name: "fake", err: fmt.Errorf("tool failed api_key=SENTINELFLOW_SECRET_MARKER")}}
	result, err := e.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ScannerRuns) != 1 || strings.Contains(result.ScannerRuns[0].Error, "SENTINELFLOW_SECRET_MARKER") || !strings.Contains(result.ScannerRuns[0].Error, "REDACTED") {
		t.Fatalf("engine scanner diagnostic must be useful but redacted: %+v", result.ScannerRuns)
	}
}

func TestSC076_SuppressedObservationsRetainSafeProvenance(t *testing.T) {
	tmpDir := t.TempDir()
	suppressed := api.Finding{
		ID: "OLD", RuleID: "aws-access-key", Title: "old", Severity: api.SeverityCritical,
		Location: api.Location{File: "a.go", StartLine: 1},
	}
	kept := api.Finding{
		ID: "NEW", RuleID: "aws-access-key", Title: "new", Severity: api.SeverityHigh,
		Location: api.Location{File: "a.go", StartLine: 2},
	}
	blPath := filepath.Join(tmpDir, "baseline.yaml")
	if err := baseline.Save(blPath, baseline.Generate([]api.Finding{suppressed})); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Baseline: config.BaselineConfig{Enabled: true, File: blPath},
	}
	engine := NewEngine(cfg)
	engine.scanners = []Scanner{
		&stubScanner{name: "stub", findings: []api.Finding{suppressed, kept}},
	}

	result, err := engine.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "NEW" {
		t.Fatalf("gate findings = %+v, want only NEW", result.Findings)
	}
	if result.Baseline == nil || !result.Baseline.Enabled {
		t.Fatal("expected baseline summary when filtering is enabled")
	}
	if result.Baseline.Total != 2 || result.Baseline.Suppressed != 1 || result.Baseline.New != 1 {
		t.Fatalf("baseline summary = %+v", result.Baseline)
	}
	if result.Baseline.Total != result.Baseline.New+result.Baseline.Suppressed || result.Baseline.Total != len(result.Findings)+len(result.Suppressed) {
		t.Fatalf("retained observations and summary do not reconcile: summary=%+v findings=%d observations=%d", result.Baseline, len(result.Findings), len(result.Suppressed))
	}
	if result.Baseline.New != len(result.Findings) {
		t.Fatalf("new count %d must match findings the gate sees (%d)", result.Baseline.New, len(result.Findings))
	}
	if len(result.Suppressed) != 1 || result.Suppressed[0].Source != "baseline" || result.Suppressed[0].Authority != "repository" || result.Suppressed[0].Fingerprint == "" {
		t.Fatalf("baseline suppression must retain redacted identity and provenance: %+v", result.Suppressed)
	}
}

func TestSC080_SuppressionAuthorityIsExplicitlySelfAttested(t *testing.T) {
	const marker = "SENTINELFLOW_RAW_SECRET_MARKER"
	result := &api.ScanResult{}
	finding := api.Finding{RuleID: "secret-rule", Location: api.Location{File: "private/path.go", Snippet: marker}, ValueHash: fingerprint.ValueHash(marker)}
	appendSuppressed(result, []api.Finding{finding}, "inline", "matched inline ignore directive", "repository")
	if len(result.Suppressed) != 1 || result.Suppressed[0].Authority != "repository" || result.Suppressed[0].Fingerprint == "" {
		t.Fatalf("suppression provenance must be explicit and self-attested: %+v", result.Suppressed)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), marker) || strings.Contains(string(encoded), "private/path.go") {
		t.Fatalf("suppression record leaked value or path: %s", encoded)
	}
}

func TestSC076_InlineAndVEXSuppressionsRetainObservation(t *testing.T) {
	for _, source := range []string{"inline", "vex"} {
		t.Run(source, func(t *testing.T) {
			root := t.TempDir()
			finding := api.Finding{ID: "F1", RuleID: "CVE-2025-1", CVE: "CVE-2025-1", Location: api.Location{File: "app.go", StartLine: 2, Snippet: "bad()"}}
			cfg := &config.Config{}
			if source == "inline" {
				if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("// sentinelflow:ignore CVE-2025-1 -- accepted test exception\nbad()\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				path := filepath.Join(root, "vex.json")
				body := `{"statements":[{"vulnerability":{"name":"CVE-2025-1"},"status":"not_affected"}]}`
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				cfg.VEX = []string{"vex.json"}
				cfg.VEXAllowBroad = true
			}
			e := NewEngine(cfg)
			e.scanners = []Scanner{&stubScanner{name: "stub", findings: []api.Finding{finding}}}
			result, err := e.Scan(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) != 0 || len(result.Suppressed) != 1 || result.Suppressed[0].Source != source || result.Suppressed[0].Fingerprint != fingerprint.Of(finding) {
				t.Fatalf("suppression observation lost: findings=%+v suppressed=%+v", result.Findings, result.Suppressed)
			}
			if result.Baseline == nil || result.Baseline.Total != 1 || result.Baseline.Suppressed != 1 || result.Baseline.New != 0 {
				t.Fatalf("suppression summary did not reconcile: %+v", result.Baseline)
			}
		})
	}
}

func TestSC077_StrictIgnoreFailureRetainsFinding(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("bad() // sentinelflow:ignore rule\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{StrictIgnores: true}
	finding := api.Finding{RuleID: "rule", Location: api.Location{File: "app.go", StartLine: 1}}
	e := NewEngine(cfg)
	e.scanners = []Scanner{&stubScanner{name: "stub", findings: []api.Finding{finding}}}
	result, err := e.Scan(context.Background(), root)
	if err == nil || result == nil || len(result.Findings) != 1 || result.Findings[0].RuleID != "rule" {
		t.Fatalf("strict suppression failure must preserve the finding: result=%+v err=%v", result, err)
	}
	if result.Status != api.ScanStatusFailed {
		t.Fatalf("status=%q, want failed", result.Status)
	}
}

func TestEngineBaselineMissingFileStillSummarizes(t *testing.T) {
	tmpDir := t.TempDir()
	finding := api.Finding{
		ID: "F1", RuleID: "r", Title: "kept", Severity: api.SeverityHigh,
		Location: api.Location{File: "a.go", StartLine: 1},
	}
	cfg := &config.Config{
		Baseline: config.BaselineConfig{Enabled: true, File: filepath.Join(tmpDir, "missing.yaml")},
	}
	engine := NewEngine(cfg)
	engine.scanners = []Scanner{&stubScanner{name: "stub", findings: []api.Finding{finding}}}

	result, err := engine.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("missing baseline should keep findings, got %+v", result.Findings)
	}
	if result.Baseline == nil || result.Baseline.Suppressed != 0 || result.Baseline.New != 1 || result.Baseline.Total != 1 {
		t.Fatalf("baseline summary = %+v", result.Baseline)
	}
}

func TestSecretsAllowlistDoesNotHideIaCPaths(t *testing.T) {
	tmpDir := t.TempDir()
	tfDir := filepath.Join(tmpDir, "test", "infra")
	if err := os.MkdirAll(tfDir, 0755); err != nil {
		t.Fatal(err)
	}
	tf := `
resource "aws_s3_bucket" "public" {
  bucket = "example"
  acl    = "public-read"
}
`
	if err := os.WriteFile(filepath.Join(tfDir, "main.tf"), []byte(tf), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			// Secrets allowlist must NOT strip IaC from the shared walk.
			Exclude: nil,
			Secrets: config.SecretsConfig{
				Enabled:   false,
				Allowlist: []string{"test/**"},
			},
			IaC: config.IaCConfig{
				Enabled:    true,
				Severity:   "medium",
				Frameworks: []string{"terraform"},
			},
		},
	}

	engine := NewEngine(cfg)
	result, err := engine.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected IaC findings under test/** despite secrets allowlist")
	}
}

func TestCollectFilesRecordsOversized(t *testing.T) {
	tmpDir := t.TempDir()
	big := filepath.Join(tmpDir, "blob.bin")
	if err := os.WriteFile(big, make([]byte, 2048), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "ok.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Scanners.MaxFileSize = 512
	engine := NewEngine(cfg)
	files, skipped, err := engine.collectFiles(context.Background(), tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) == 0 {
		t.Fatal("expected oversized skip warning")
	}
	foundOK := false
	for _, f := range files {
		if filepath.Base(f) == "ok.go" {
			foundOK = true
		}
		if filepath.Base(f) == "blob.bin" {
			t.Fatal("oversized file should not be collected")
		}
	}
	if !foundOK {
		t.Fatal("expected ok.go to be collected")
	}
}

func TestPerfBudgetSmallTree(t *testing.T) {
	if testing.Short() {
		t.Skip("perf budget")
	}
	tmpDir := t.TempDir()
	for i := 0; i < 80; i++ {
		name := filepath.Join(tmpDir, fmt.Sprintf("f%02d.go", i))
		if err := os.WriteFile(name, []byte("package p\nfunc F() {}\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.Scanners.Dependencies.Enabled = false
	cfg.Policies.Enabled = false
	cfg.Scanners.IaC.Enabled = false
	cfg.Scanners.SAST.Enabled = false
	engine := NewEngine(cfg)
	start := time.Now()
	if _, err := engine.Scan(context.Background(), tmpDir); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("perf budget exceeded: scanned 80 files in %s (budget 5s)", d)
	}
}
