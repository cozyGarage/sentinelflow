package cli

import (
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
