package cli

import (
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func TestInitTemplateLoadsAndMatchesScanAll(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Cleanup(func() { initForce = false })

	rootCmd.SetArgs([]string{"init"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}
	cfg, err := config.LoadFromDir(dir)
	if err != nil {
		t.Fatalf("load generated config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("generated config invalid: %v", err)
	}
	if f := cfg.Reporting.Format; f != "" && f != "text" {
		t.Fatalf("init must not change default output format, got %q", cfg.Reporting.Format)
	}
	if !cfg.Scanners.SAST.Enabled {
		t.Fatal("init should enable SAST so local scans match the Action's scan-all default")
	}

	rootCmd.SetArgs([]string{"init"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("second init without --force should refuse to overwrite")
	}
	rootCmd.SetArgs([]string{"init", "--force"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init --force: %v", err)
	}
}
