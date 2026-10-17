package config

import (
	"os"
	"path/filepath"
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

func TestSC082_OfflineFreshnessConfigDefaultsAndValidation(t *testing.T) {
	cfg := Default()
	if cfg.Scanners.Dependencies.OfflineRequireFresh {
		t.Fatal("strict offline freshness must remain opt-in")
	}
	if age, err := cfg.OfflineMaxAgeDuration(); err != nil || age != 720*time.Hour {
		t.Fatalf("default max age=%s err=%v, want 720h", age, err)
	}
	cfg.Scanners.Dependencies.OfflineMaxAge = "0s"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "must be > 0") {
		t.Fatalf("non-positive offline max age should fail validation, got %v", err)
	}
	cfg = Default()
	cfg.Scanners.Dependencies.OfflineMaxAge = "not-a-duration"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid scanners.dependencies.offline_max_age") {
		t.Fatalf("invalid offline max age should fail validation, got %v", err)
	}
	path := filepath.Join(t.TempDir(), ".sentinelflow.yaml")
	if err := os.WriteFile(path, []byte("scanners:\n  dependencies:\n    offline_require_fresh: true\n    offline_max_age: 48h\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Scanners.Dependencies.OfflineRequireFresh || cfg.Scanners.Dependencies.OfflineMaxAge != "48h" {
		t.Fatalf("offline freshness settings did not load: %+v", cfg.Scanners.Dependencies)
	}
}

func TestVEXBroadScopeRequiresExplicitConfig(t *testing.T) {
	cfg := Default()
	if cfg.VEXAllowBroad {
		t.Fatal("broad VEX scope must be opt-in")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".sentinelflow.yaml")
	if err := os.WriteFile(path, []byte("vex_allow_broad: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.VEXAllowBroad {
		t.Fatal("explicit vex_allow_broad must load")
	}
}

func TestStrictIgnoresLoadsOptInAndDefaultsOff(t *testing.T) {
	if Default().StrictIgnores {
		t.Fatal("strict inline ignore mode must remain opt-in")
	}
	path := filepath.Join(t.TempDir(), ".sentinelflow.yaml")
	if err := os.WriteFile(path, []byte("strict_ignores: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.StrictIgnores {
		t.Fatal("strict_ignores setting was not loaded")
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

func TestLoadFromDirPrefersTargetConfig(t *testing.T) {
	dir := t.TempDir()
	content := "version: \"1.0\"\nfail_on:\n  severity: critical\n"
	if err := os.WriteFile(filepath.Join(dir, ".sentinelflow.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn.Severity != "critical" {
		t.Fatalf("expected target config severity critical, got %q", cfg.FailOn.Severity)
	}
}

func TestConfigDirForTarget(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "main.go")
	if err := os.WriteFile(file, []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := ConfigDirForTarget(dir); got != filepath.Clean(dir) {
		t.Fatalf("dir target: got %q", got)
	}
	if got := ConfigDirForTarget(file); got != filepath.Clean(dir) {
		t.Fatalf("file target: got %q want %q", got, dir)
	}
}

func TestGitHistoryPrecedence(t *testing.T) {
	cases := []struct {
		name               string
		gitOn, secOn       bool
		gitDepth, secDepth int
		wantOn             bool
		wantDepth          int
	}{
		{"defaults", false, false, 50, 0, false, 50},
		{"canonical", true, false, 100, 0, true, 100},
		{"deprecated alias enables", false, true, 50, 0, true, 50},
		{"deprecated depth when git left default", false, true, 50, 7, true, 7},
		{"git depth wins when set", true, true, 20, 7, true, 20},
	}
	for _, tc := range cases {
		cfg := Default()
		cfg.Git.ScanHistory, cfg.Git.HistoryDepth = tc.gitOn, tc.gitDepth
		cfg.Scanners.Secrets.ScanGitHistory, cfg.Scanners.Secrets.MaxHistoryDepth = tc.secOn, tc.secDepth
		if on, depth := cfg.GitHistory(); on != tc.wantOn || depth != tc.wantDepth {
			t.Errorf("%s: got (%v, %d), want (%v, %d)", tc.name, on, depth, tc.wantOn, tc.wantDepth)
		}
	}
}
