package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

func resetArtifactFlags() {
	outputFile, failOnSeverity, scanTimeoutFlag, outputFormat = "", "", "", "text"
	rootCmd.PersistentFlags().Lookup("format").Changed = false
}

// The release workflow runs exactly this command; it must accept the flags and write -o.
func TestScanArtifactWritesReportWithGateFlags(t *testing.T) {
	t.Cleanup(resetArtifactFlags)
	dir := t.TempDir()
	target := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "nested", "artifact-scan.json")

	rootCmd.SetArgs([]string{"scan-artifact", target, "--fail-on", "critical", "--timeout", "1m", "-f", "json", "-o", out})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan-artifact: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("report not written: %v", err)
	}
}

func TestScanArtifactRejectsBadFlagsAsToolError(t *testing.T) {
	t.Cleanup(resetArtifactFlags)
	target := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--fail-on", "bogus"}, {"--timeout", "abc"}, {"-f", "xml"}} {
		resetArtifactFlags()
		rootCmd.SetArgs(append([]string{"scan-artifact", target}, args...))
		var exitErr *api.ExitError
		if err := rootCmd.Execute(); !errors.As(err, &exitErr) || exitErr.Code != api.ExitTool {
			t.Fatalf("%v: got %v, want exit %d", args, err, api.ExitTool)
		}
	}
}
