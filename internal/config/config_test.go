package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateRejectsInvalidSeverity(t *testing.T) {
	cfg := Default()
	cfg.FailOn.Severity = "urgent"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid severity to fail validation")
	}
}

func TestValidateRejectsAIEnabled(t *testing.T) {
	cfg := Default()
	cfg.Scanners.AI.Enabled = true
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected AI enabled config to fail validation")
	}
	if err.Error() != AINotAvailableMessage {
		t.Fatalf("expected shared AI rejection message, got %v", err)
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("defaults should be valid: %v", err)
	}
}

func TestValidateNormalizesFailOnSeverity(t *testing.T) {
	cfg := Default()
	cfg.FailOn.Severity = "HIGH"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected HIGH to validate: %v", err)
	}
	if cfg.FailOn.Severity != "high" {
		t.Fatalf("expected normalized severity high, got %q", cfg.FailOn.Severity)
	}
}

func TestScanTimeoutDuration(t *testing.T) {
	cfg := Default()
	d, err := cfg.ScanTimeoutDuration()
	if err != nil || d != 10*time.Minute {
		t.Fatalf("default timeout: got %v %v", d, err)
	}
	cfg.ScanTimeout = "90s"
	d, err = cfg.ScanTimeoutDuration()
	if err != nil || d != 90*time.Second {
		t.Fatalf("90s timeout: got %v %v", d, err)
	}
	cfg.ScanTimeout = "nope"
	if _, err := cfg.ScanTimeoutDuration(); err == nil {
		t.Fatal("expected invalid timeout error")
	}
}

func TestDependenciesFailOnErrorDefault(t *testing.T) {
	cfg := Default()
	if !cfg.DependenciesFailOnError() {
		t.Fatal("default should fail on dependency errors")
	}
	off := false
	cfg.Scanners.Dependencies.FailOnError = &off
	if cfg.DependenciesFailOnError() {
		t.Fatal("expected fail_on_error=false to soft-skip")
	}
	on := true
	cfg.Scanners.Dependencies.FailOnError = &on
	if !cfg.DependenciesFailOnError() {
		t.Fatal("expected fail_on_error=true to stay strict")
	}
}

func TestValidateRejectsUnknownIaCFramework(t *testing.T) {
	cfg := Default()
	cfg.Scanners.IaC.Frameworks = []string{"terraform", "cloudformation"}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "cloudformation") {
		t.Fatalf("expected cloudformation rejection, got %v", err)
	}
}
