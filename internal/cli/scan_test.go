package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestShouldFailCaseInsensitive(t *testing.T) {
	cfg := &config.Config{
		FailOn: config.FailOnConfig{Severity: "HIGH"},
	}
	result := &api.ScanResult{
		Findings: []api.Finding{
			{Severity: api.SeverityHigh},
		},
	}
	if !shouldFail(result, cfg) {
		t.Fatal("expected HIGH threshold to match high findings")
	}
}

func TestSC091_BuiltCLIExitAndPartialReport(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../.."))
	bin := filepath.Join(t.TempDir(), "sentinelflow")
	build := exec.Command("go", "build", "-o", bin, "./cmd/sentinelflow")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}

	t.Run("clean exits zero", func(t *testing.T) {
		target := t.TempDir()
		assertCLIExit(t, bin, target, 0, "--secrets")
	})
	t.Run("pre-result engine error redacts sensitive target path", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "api_key=SENTINELFLOW_SECRET_MARKER")
		if err := os.MkdirAll(target, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, ".sentinelflow.yaml"), []byte("vex:\n  - missing-vex.json\n"), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "scan", target, "--secrets")
		cmd.Env = append(os.Environ(), "NO_COLOR=1")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != api.ExitTool {
			t.Fatalf("want tool exit %d, got %v\nstdout:\n%s\nstderr:\n%s", api.ExitTool, err, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), "SENTINELFLOW_SECRET_MARKER") || strings.Contains(stderr.String(), "SENTINELFLOW_SECRET_MARKER") {
			t.Fatalf("pre-result engine error leaked synthetic secret\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "load VEX") || !strings.Contains(stderr.String(), "REDACTED") {
			t.Fatalf("expected a useful redacted error reason, got stderr:\n%s", stderr.String())
		}
	})
	t.Run("threshold finding exits one", func(t *testing.T) {
		target := t.TempDir()
		if err := os.WriteFile(filepath.Join(target, "Dockerfile"), []byte("FROM nginx:latest\n"), 0600); err != nil {
			t.Fatal(err)
		}
		result := assertCLIExit(t, bin, target, 1, "--iac", "--fail-on", "info")
		if len(result.Findings) == 0 {
			t.Fatal("threshold report must contain its finding")
		}
	})
	t.Run("comparison error exits two and writes partial findings", func(t *testing.T) {
		target := t.TempDir()
		if err := os.WriteFile(filepath.Join(target, "Dockerfile"), []byte("FROM nginx:latest\n"), 0600); err != nil {
			t.Fatal(err)
		}
		git(t, target, "init", "-q")
		git(t, target, "-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
		git(t, target, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base")
		result := assertCLIExit(t, bin, target, 2, "--iac", "--baseline-ref", "missing-ref")
		if len(result.Findings) == 0 {
			t.Fatal("operational comparison failure must retain the head finding in the report")
		}
	})
	t.Run("incomplete baseline plus threshold finding keeps operational exit", func(t *testing.T) {
		target := t.TempDir()
		if err := os.WriteFile(filepath.Join(target, "Dockerfile"), []byte("FROM nginx:latest\n"), 0600); err != nil {
			t.Fatal(err)
		}
		git(t, target, "init", "-q")
		git(t, target, "-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
		git(t, target, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base")
		result := assertCLIExit(t, bin, target, 2, "--iac", "--fail-on", "info", "--baseline-ref", "missing-ref")
		if len(result.Findings) == 0 {
			t.Fatal("comparison failure must retain risk even when a finding gate also matches")
		}
	})
	t.Run("required external finding plus process failure exits two and writes report", func(t *testing.T) {
		target := t.TempDir()
		configText := "scanners:\n  secrets:\n    enabled: false\n  iac:\n    enabled: false\n  dependencies:\n    enabled: false\n  sast:\n    enabled: false\n  external:\n    gitleaks:\n      mode: required\n"
		if err := os.WriteFile(filepath.Join(target, ".sentinelflow.yaml"), []byte(configText), 0600); err != nil {
			t.Fatal(err)
		}
		fakeBin := t.TempDir()
		gitleaks := filepath.Join(fakeBin, "gitleaks")
		script := "#!/bin/sh\nprintf '%s' '[{\"RuleID\":\"test.secret\",\"Description\":\"synthetic secret\",\"File\":\"secret.txt\",\"StartLine\":1,\"Match\":\"SYNTHETIC\"}]'\nprintf '%s\\n' 'api_key=SENTINELFLOW_SECRET_MARKER' >&2\nexit 2\n"
		if err := os.WriteFile(gitleaks, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		extraEnv := []string{"PATH=" + fakeBin + string(os.PathListSeparator) + os.Getenv("PATH")}
		result := assertCLIExitEnv(t, bin, target, 2, extraEnv)
		if result == nil || len(result.Findings) != 1 || result.Findings[0].RuleID != "test.secret" {
			t.Fatalf("required tool failure must preserve parsed finding in report: %+v", result)
		}
		if len(result.ScannerRuns) == 0 || strings.Contains(result.ScannerRuns[len(result.ScannerRuns)-1].Error, "SENTINELFLOW_SECRET_MARKER") || !strings.Contains(result.ScannerRuns[len(result.ScannerRuns)-1].Error, "REDACTED") {
			t.Fatalf("scanner diagnostic must be redacted in public report: %+v", result.ScannerRuns)
		}
	})
	t.Run("deadline exits three", func(t *testing.T) {
		target := t.TempDir()
		assertCLIExit(t, bin, target, 3, "--secrets", "--timeout", "1ns")
	})
	t.Run("deadline with partial scanner result still writes report and exits three", func(t *testing.T) {
		target := t.TempDir()
		if err := os.WriteFile(filepath.Join(target, ".sentinelflow.yaml"), []byte("scan_timeout: 100ms\nscanners:\n  external:\n    gitleaks:\n      mode: required\n"), 0600); err != nil {
			t.Fatal(err)
		}
		fakeBin := t.TempDir()
		gitleaks := filepath.Join(fakeBin, "gitleaks")
		if err := os.WriteFile(gitleaks, []byte("#!/bin/sh\nprintf '[]'\nexec sleep 5\n"), 0700); err != nil {
			t.Fatal(err)
		}
		extraEnv := []string{"PATH=" + fakeBin + string(os.PathListSeparator) + os.Getenv("PATH")}
		result := assertCLIExitEnv(t, bin, target, 3, extraEnv)
		if result == nil {
			t.Fatal("deadline after scanner execution starts should still emit the partial result report")
		}
		if len(result.ScannerRuns) == 0 || result.ScannerRuns[len(result.ScannerRuns)-1].Error == "" {
			t.Fatalf("partial report should retain the timed-out scanner outcome: %+v", result.ScannerRuns)
		}
	})
}

func assertCLIExit(t *testing.T, bin, target string, want int, flags ...string) *api.ScanResult {
	t.Helper()
	return assertCLIExitEnv(t, bin, target, want, nil, flags...)
}

func assertCLIExitEnv(t *testing.T, bin, target string, want int, extraEnv []string, flags ...string) *api.ScanResult {
	t.Helper()
	reportPath := filepath.Join(t.TempDir(), "report.json")
	args := append([]string{"scan", target}, flags...)
	if !containsArg(args, "--output") {
		args = append(args, "--output", reportPath)
	}
	if !containsArg(args, "--format") {
		args = append(args, "--format", "json")
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Env = append(cmd.Env, "NO_COLOR=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	got := 0
	if err != nil {
		if !errors.As(err, &exitErr) {
			t.Fatalf("run CLI: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		}
		got = exitErr.ExitCode()
	}
	if got != want {
		t.Fatalf("exit=%d want=%d\nstdout:\n%s\nstderr:\n%s", got, want, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "SENTINELFLOW_SECRET_MARKER") || strings.Contains(stderr.String(), "SENTINELFLOW_SECRET_MARKER") {
		t.Fatalf("CLI leaked synthetic diagnostic marker\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	}
	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		if want == api.ExitTimeout {
			return nil
		}
		t.Fatalf("read report: %v\nstdout:\n%s\nstderr:\n%s", readErr, stdout.String(), stderr.String())
	}
	var result api.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode report: %v\n%s", err, data)
	}
	return &result
}

func containsArg(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestShouldFailChecksAllGates(t *testing.T) {
	cfg := &config.Config{
		FailOn: config.FailOnConfig{
			Severity:         "high",
			Secrets:          true,
			PolicyViolations: true,
		},
	}

	mediumOnly := &api.ScanResult{
		Findings: []api.Finding{
			{Type: api.FindingTypeMisconfiguration, Severity: api.SeverityMedium},
		},
	}
	if shouldFail(mediumOnly, cfg) {
		t.Error("medium-only findings should not fail on high severity threshold")
	}

	withSecret := &api.ScanResult{
		Findings: []api.Finding{
			{Type: api.FindingTypeSecret, Severity: api.SeverityLow},
		},
	}
	if !shouldFail(withSecret, cfg) {
		t.Error("expected fail when secrets gate is enabled")
	}

	withPolicy := &api.ScanResult{
		Findings: []api.Finding{
			{Type: api.FindingTypePolicyViolation, Severity: api.SeverityLow},
		},
	}
	if !shouldFail(withPolicy, cfg) {
		t.Error("expected fail when policy_violations gate is enabled")
	}
}

func TestApplyScanFlagsSelectiveDisablesPolicy(t *testing.T) {
	prevAll := scanAll
	prevSecrets := scanSecrets
	prevIaC := scanIaC
	prevDeps := scanDependencies
	prevSAST := scanSAST
	prevContainer := scanContainer
	prevLicense := scanLicense
	t.Cleanup(func() {
		scanAll = prevAll
		scanSecrets = prevSecrets
		scanIaC = prevIaC
		scanDependencies = prevDeps
		scanSAST = prevSAST
		scanContainer = prevContainer
		scanLicense = prevLicense
	})

	scanAll = false
	scanSecrets = true
	scanIaC = false
	scanDependencies = false
	scanSAST = false
	scanContainer = false
	scanLicense = false

	cfg := config.Default()
	if !cfg.Policies.Enabled {
		t.Fatal("precondition: defaults enable policy")
	}
	if err := applyScanFlags(cfg); err != nil {
		t.Fatalf("applyScanFlags: %v", err)
	}
	if !cfg.Scanners.Secrets.Enabled {
		t.Fatal("expected --secrets to enable secrets")
	}
	if cfg.Scanners.IaC.Enabled || cfg.Scanners.SAST.Enabled {
		t.Fatal("expected other scanners disabled")
	}
	if cfg.Policies.Enabled {
		t.Fatal("expected selective flags to disable policy scanner")
	}
}

func TestApplyScanFlagsAllPreservesOverrides(t *testing.T) {
	prevAll := scanAll
	prevFailOn := failOnSeverity
	prevBaseline := useBaseline
	prevImage := containerImage
	prevAI := scanAI
	t.Cleanup(func() {
		scanAll = prevAll
		failOnSeverity = prevFailOn
		useBaseline = prevBaseline
		containerImage = prevImage
		scanAI = prevAI
	})

	scanAll = true
	failOnSeverity = "low"
	useBaseline = true
	containerImage = "alpine:3.19"
	scanAI = false

	cfg := config.Default()
	cfg.Scanners.Secrets.Enabled = false
	cfg.Baseline.Enabled = false
	cfg.FailOn.Severity = "high"

	if err := applyScanFlags(cfg); err != nil {
		t.Fatalf("applyScanFlags: %v", err)
	}

	if !cfg.Scanners.Secrets.Enabled || !cfg.Scanners.SAST.Enabled {
		t.Fatal("expected --all to enable secrets/iac/deps/sast")
	}
	if cfg.Scanners.License.Enabled {
		t.Fatal("expected --all alone to leave license disabled (opt-in via --license)")
	}
	// --container-image still opts into container even when --all alone would not.
	if !cfg.Scanners.Container.Enabled {
		t.Fatal("expected --container-image to enable container with --all")
	}
	if cfg.FailOn.Severity != "low" {
		t.Fatalf("expected --fail-on to apply with --all, got %q", cfg.FailOn.Severity)
	}
	if !cfg.Baseline.Enabled {
		t.Fatal("expected --baseline to apply with --all")
	}
	if cfg.Scanners.Container.Image != "alpine:3.19" {
		t.Fatalf("expected container image override, got %q", cfg.Scanners.Container.Image)
	}
}

func TestApplyScanFlagsAllOptOutKeepsPolicy(t *testing.T) {
	prevAll := scanAll
	prevNoSecrets := noSecrets
	prevNoIaC := noIaC
	prevNoDeps := noDependencies
	prevNoSAST := noSAST
	t.Cleanup(func() {
		scanAll = prevAll
		noSecrets = prevNoSecrets
		noIaC = prevNoIaC
		noDependencies = prevNoDeps
		noSAST = prevNoSAST
	})

	scanAll = true
	noSecrets = true
	noIaC = false
	noDependencies = false
	noSAST = false

	cfg := config.Default()
	if !cfg.Policies.Enabled {
		t.Fatal("precondition: defaults enable policy")
	}
	if err := applyScanFlags(cfg); err != nil {
		t.Fatalf("applyScanFlags: %v", err)
	}
	if cfg.Scanners.Secrets.Enabled {
		t.Fatal("expected --no-secrets to disable secrets under --all")
	}
	if !cfg.Scanners.IaC.Enabled || !cfg.Scanners.Dependencies.Enabled || !cfg.Scanners.SAST.Enabled {
		t.Fatal("expected other --all scanners to stay enabled")
	}
	if !cfg.Policies.Enabled {
		t.Fatal("expected --all --no-secrets to leave policy enabled")
	}
}

func TestApplyScanFlagsNoOptOutIgnoredWithoutAll(t *testing.T) {
	prevAll := scanAll
	prevSecrets := scanSecrets
	prevIaC := scanIaC
	prevDeps := scanDependencies
	prevSAST := scanSAST
	prevContainer := scanContainer
	prevLicense := scanLicense
	prevNoSecrets := noSecrets
	t.Cleanup(func() {
		scanAll = prevAll
		scanSecrets = prevSecrets
		scanIaC = prevIaC
		scanDependencies = prevDeps
		scanSAST = prevSAST
		scanContainer = prevContainer
		scanLicense = prevLicense
		noSecrets = prevNoSecrets
	})

	scanAll = false
	scanSecrets = false
	scanIaC = false
	scanDependencies = false
	scanSAST = false
	scanContainer = false
	scanLicense = false
	noSecrets = true

	cfg := config.Default()
	cfg.Scanners.Secrets.Enabled = true
	if err := applyScanFlags(cfg); err != nil {
		t.Fatalf("applyScanFlags: %v", err)
	}
	if !cfg.Scanners.Secrets.Enabled {
		t.Fatal("expected --no-secrets without --all to leave secrets unchanged")
	}
	if !cfg.Policies.Enabled {
		t.Fatal("expected --no-secrets without --all to leave policy enabled")
	}
}

func TestApplyScanFlagsAllDoesNotEnableContainer(t *testing.T) {
	prevAll := scanAll
	prevImage := containerImage
	prevContainer := scanContainer
	t.Cleanup(func() {
		scanAll = prevAll
		containerImage = prevImage
		scanContainer = prevContainer
	})

	scanAll = true
	containerImage = ""
	scanContainer = false

	cfg := config.Default()
	cfg.Scanners.Container.Enabled = true // config default on; --all should clear it
	if err := applyScanFlags(cfg); err != nil {
		t.Fatalf("applyScanFlags: %v", err)
	}
	if cfg.Scanners.Container.Enabled {
		t.Fatal("expected --all alone to leave container disabled")
	}
}

func TestApplyScanFlagsAllWithContainerFlag(t *testing.T) {
	prevAll := scanAll
	prevImage := containerImage
	prevContainer := scanContainer
	t.Cleanup(func() {
		scanAll = prevAll
		containerImage = prevImage
		scanContainer = prevContainer
	})

	scanAll = true
	containerImage = ""
	scanContainer = true

	cfg := config.Default()
	cfg.Scanners.Container.Enabled = false
	if err := applyScanFlags(cfg); err != nil {
		t.Fatalf("applyScanFlags: %v", err)
	}
	if !cfg.Scanners.Container.Enabled {
		t.Fatal("expected --all --container to enable container")
	}
}

func TestApplyScanFlagsRejectsAI(t *testing.T) {
	prevAI := scanAI
	prevAll := scanAll
	t.Cleanup(func() {
		scanAI = prevAI
		scanAll = prevAll
	})

	scanAI = true
	scanAll = false
	err := applyScanFlags(config.Default())
	if err == nil || !strings.Contains(err.Error(), config.AINotAvailableMessage) {
		t.Fatalf("expected --ai rejection with shared message, got %v", err)
	}
}

func TestScannerErrorsFailsCI(t *testing.T) {
	result := &api.ScanResult{
		ScannerRuns: []api.ScannerRun{
			{Scanner: "dependencies", Error: "osv unavailable"},
		},
	}
	err := scannerErrors(result, config.Default())
	if err == nil {
		t.Fatal("expected scanner error to fail the scan")
	}
}

func TestScannerErrorsSoftDependencies(t *testing.T) {
	off := false
	cfg := config.Default()
	cfg.Scanners.Dependencies.FailOnError = &off
	result := &api.ScanResult{
		ScannerRuns: []api.ScannerRun{
			{Scanner: "dependencies", Error: "osv unavailable"},
			{Scanner: "secrets", Error: "boom"},
		},
	}
	err := scannerErrors(result, cfg)
	if err == nil {
		t.Fatal("expected secrets error to still fail")
	}
	if !strings.Contains(err.Error(), "secrets") {
		t.Fatalf("expected secrets in error, got %v", err)
	}
	if strings.Contains(err.Error(), "dependencies") {
		t.Fatalf("dependencies should be soft when fail_on_error=false, got %v", err)
	}

	result = &api.ScanResult{
		ScannerRuns: []api.ScannerRun{
			{Scanner: "dependencies", Error: "osv unavailable"},
		},
	}
	if err := scannerErrors(result, cfg); err != nil {
		t.Fatalf("expected soft deps error to be non-fatal, got %v", err)
	}
}

func TestValidatePolicyNameRejectsTraversal(t *testing.T) {
	for _, name := range []string{"../evil", "foo/bar", `foo\bar`, "bad name"} {
		if err := validatePolicyName(name); err == nil {
			t.Fatalf("expected rejection for %q", name)
		}
	}
	if err := validatePolicyName("require-https"); err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
}

func TestRemoveHookBlockPreservesOtherHooks(t *testing.T) {
	content := "#!/bin/sh\necho existing\n\n# >>> sentinelflow-pre-commit-hook\n# sentinelflow-pre-commit-hook\nexec sentinelflow scan\n# <<< sentinelflow-pre-commit-hook\n"
	updated, removed := removeHookBlock(content)
	if !removed {
		t.Fatal("expected block removal")
	}
	if !strings.Contains(updated, "echo existing") {
		t.Fatal("expected existing hook content to remain")
	}
	if strings.Contains(updated, "sentinelflow") {
		t.Fatal("expected SentinelFlow block to be removed")
	}
}

func TestShouldFailOnKEVRegardlessOfSeverity(t *testing.T) {
	result := &api.ScanResult{Findings: []api.Finding{{Severity: api.SeverityLow, KEV: true}}}
	if shouldFail(result, &config.Config{FailOn: config.FailOnConfig{Severity: "critical"}}) {
		t.Fatal("KEV gate is off: low finding must not fail a critical threshold")
	}
	if !shouldFail(result, &config.Config{FailOn: config.FailOnConfig{Severity: "critical", KEV: true}}) {
		t.Fatal("fail_on.kev must fail on a KEV finding of any severity")
	}
}

func TestShouldFailReachableOnly(t *testing.T) {
	no, yes := false, true
	result := &api.ScanResult{Findings: []api.Finding{
		{Severity: api.SeverityCritical, Reachable: &no},
		{Severity: api.SeverityLow, Reachable: &yes},
	}}
	cfg := &config.Config{FailOn: config.FailOnConfig{Severity: "high"}}
	if !shouldFail(result, cfg) {
		t.Fatal("without reachable_only the unreachable critical still gates")
	}
	cfg.FailOn.ReachableOnly = true
	if shouldFail(result, cfg) {
		t.Fatal("reachable_only must ignore the unreachable critical")
	}
	result.Findings = append(result.Findings, api.Finding{Severity: api.SeverityHigh}) // not analysed
	if !shouldFail(result, cfg) {
		t.Fatal("unanalysed findings must still gate")
	}
}

func TestSC044_ReachableOnlyFailsClosedForUnknown(t *testing.T) {
	no, yes := false, true
	cfg := &config.Config{FailOn: config.FailOnConfig{Severity: "critical", ReachableOnly: true}}
	for _, tc := range []struct {
		name      string
		reachable *bool
		wantFail  bool
	}{
		{name: "confirmed unreachable", reachable: &no, wantFail: false},
		{name: "confirmed reachable", reachable: &yes, wantFail: true},
		{name: "unknown", reachable: nil, wantFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := &api.ScanResult{Findings: []api.Finding{{Severity: api.SeverityCritical, Reachable: tc.reachable}}}
			if got := shouldFail(result, cfg); got != tc.wantFail {
				t.Fatalf("shouldFail() = %v, want %v", got, tc.wantFail)
			}
		})
	}
}

func TestSC044_RequiredReachabilityErrorIsNotSoftened(t *testing.T) {
	softDependencyErrors := false
	cfg := &config.Config{}
	cfg.Scanners.Dependencies.FailOnError = &softDependencyErrors
	cfg.Scanners.Dependencies.Reachability = "required"
	result := &api.ScanResult{ScannerRuns: []api.ScannerRun{{Scanner: "dependencies", Error: "reachability: govulncheck failed"}}}
	if err := scannerErrors(result, cfg); err == nil {
		t.Fatal("required reachability failure must remain an operational error when dependency transport errors are soft")
	}
}
