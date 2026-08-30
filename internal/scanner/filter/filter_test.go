package filter

import "testing"

func TestShouldSkipTestFilesOnlyViaAllowlist(t *testing.T) {
	if ShouldSkip("internal/scanner/sast/scanner_test.go", nil) {
		t.Error("empty allowlist/exclude must not hard-skip _test.go")
	}
	allowlist := []string{"**/*_test.go"}
	if !ShouldSkip("internal/scanner/sast/scanner_test.go", allowlist) {
		t.Error("expected glob allowlist to skip _test.go")
	}
}

func TestShouldSkipTestdata(t *testing.T) {
	if !ShouldSkip("internal/scanner/sast/testdata/vuln.go", nil) {
		t.Error("expected /testdata/ paths to be skipped")
	}
}

func TestShouldSkipAllowlistPath(t *testing.T) {
	allowlist := []string{"internal/scanner/sast/scanner.go"}
	if !ShouldSkip("internal/scanner/sast/scanner.go", allowlist) {
		t.Error("expected allowlisted path to be skipped")
	}
}

func TestShouldSkipGlobSuffix(t *testing.T) {
	allowlist := []string{"**/*_test.go"}
	if !ShouldSkip("internal/scanner/sast/scanner_test.go", allowlist) {
		t.Error("expected glob suffix match")
	}
}

func TestIsBundledSampleDirScoped(t *testing.T) {
	root := "/repo"
	if !IsBundledSampleDir(root, "/repo/test/fixtures") {
		t.Fatal("expected test/fixtures to be a bundled sample")
	}
	if !IsBundledSampleDir(root, "/repo/examples/demo-project") {
		t.Fatal("expected examples/demo-project to be a bundled sample")
	}
	if IsBundledSampleDir(root, "/repo/pkg/fixtures") {
		t.Fatal("arbitrary fixtures/ dir must not be skipped")
	}
	if IsBundledSampleDir(root, "/repo/demo-project") {
		t.Fatal("demo-project outside examples/ must not be skipped")
	}
	if IsBundledSampleDir("/repo/test/fixtures", "/repo/test/fixtures") {
		t.Fatal("scan root itself must not be skipped")
	}
}
