package sast

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func writeScanFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func findingRules(result *ScannerResult) map[string]int {
	counts := map[string]int{}
	for _, f := range result.Findings {
		counts[f.RuleID]++
	}
	return counts
}

func TestDetectSQLInjection(t *testing.T) {
	s := NewScanner(config.Default())
	tmpDir := t.TempDir()
	writeScanFile(t, tmpDir, "handler.go", `query := "SELECT * FROM users WHERE id = " + request.Params["id"]`)

	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if findingRules(result)["sqli-concat"] == 0 {
		t.Error("expected SQL injection finding")
	}
}

func TestDetectPathTraversal(t *testing.T) {
	s := NewScanner(config.Default())
	tmpDir := t.TempDir()
	writeScanFile(t, tmpDir, "file.go", `path := baseDir + "/../etc/passwd"`)

	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if findingRules(result)["path-traversal"] == 0 {
		t.Error("expected path traversal finding")
	}
}

func TestSupportsExtensions(t *testing.T) {
	s := NewScanner(config.Default())
	if !s.Supports("main.go") {
		t.Error("should support .go files")
	}
	if !s.Supports("app.py") {
		t.Error("should support .py files")
	}
	if s.Supports("image.png") {
		t.Error("should not support .png files")
	}
	if s.Supports("script.php") {
		t.Error("should not claim PHP until language-specific rules exist")
	}
}

func TestSQLFormatDoesNotMatchEnglishUpdate(t *testing.T) {
	s := NewScanner(config.Default())
	tmpDir := t.TempDir()
	writeScanFile(t, tmpDir, "msg.go", `
package main
func rem() string { return fmt.Sprintf("Update %s to version %s", pkg, ver) }
func bad() string { return fmt.Sprintf("SELECT * FROM users WHERE id=%s", id) }
`)

	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	counts := findingRules(result)
	if counts["sqli-format"] != 1 {
		t.Fatalf("expected exactly one sqli-format (real SQL), got %d findings: %+v", counts["sqli-format"], result.Findings)
	}
}

func TestEvalDoesNotMatchGoMethodEval(t *testing.T) {
	s := NewScanner(config.Default())
	tmpDir := t.TempDir()
	writeScanFile(t, tmpDir, "opa.go", `
package main
func run() { query.Eval(ctx, input) }
`)
	writeScanFile(t, tmpDir, "xss.js", `const x = eval(userInput)`)

	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	counts := findingRules(result)
	if counts["xss-eval"] != 1 {
		t.Fatalf("expected one xss-eval (JS only), got %d: %+v", counts["xss-eval"], result.Findings)
	}
}

func TestCmdInjectShellGrouping(t *testing.T) {
	s := NewScanner(config.Default())
	tmpDir := t.TempDir()
	writeScanFile(t, tmpDir, "safe.go", `
package main
var shell = "bash"
func ok() { exec.Command("ls", "-la") }
`)
	writeScanFile(t, tmpDir, "bad.go", `
package main
func bad() { exec.Command("bash", "-c", userCmd) }
`)

	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	counts := findingRules(result)
	if counts["cmd-inject-shell"] != 1 {
		t.Fatalf("expected one cmd-inject-shell, got %d: %+v", counts["cmd-inject-shell"], result.Findings)
	}
}

func TestSkipRulesAndSeverity(t *testing.T) {
	cfg := config.Default()
	cfg.Scanners.SAST.SkipRules = []string{"path-traversal"}
	cfg.Scanners.SAST.Severity = "critical"
	s := NewScanner(cfg)
	tmpDir := t.TempDir()
	writeScanFile(t, tmpDir, "mixed.go", `
package main
func a() { _ = "/../etc/passwd" }
func b() { exec.Command("sh", "-c", "echo "+user) }
`)

	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	counts := findingRules(result)
	if counts["path-traversal"] != 0 {
		t.Fatal("path-traversal should be skipped")
	}
	if counts["cmd-inject-exec"] == 0 {
		t.Fatal("expected critical cmd-inject-exec to remain")
	}
	for _, f := range result.Findings {
		if !api.MeetsMinimum(f.Severity, "critical") {
			t.Fatalf("finding below severity filter: %s %s", f.RuleID, f.Severity)
		}
	}
}

func TestFindingIDsIncludePathToken(t *testing.T) {
	s := NewScanner(config.Default())
	tmpDir := t.TempDir()
	writeScanFile(t, tmpDir, "a.go", `x := eval(y)`)
	writeScanFile(t, tmpDir, "b.go", `x := eval(y)`)

	result, err := s.Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	ids := map[string]bool{}
	for _, f := range result.Findings {
		if f.RuleID != "xss-eval" {
			continue
		}
		if ids[f.ID] {
			t.Fatalf("duplicate finding ID across files: %s", f.ID)
		}
		ids[f.ID] = true
		if !strings.Contains(f.ID, "xss-eval") || strings.Count(f.ID, "-") < 3 {
			t.Fatalf("expected path token in ID, got %s", f.ID)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 distinct xss-eval IDs, got %d", len(ids))
	}
}

func TestEmbeddedRulesLoad(t *testing.T) {
	rules := loadRules()
	if len(rules) < 10 {
		t.Fatalf("expected embedded rules, got %d", len(rules))
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.ID] {
			t.Fatalf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
		if r.Pattern == nil {
			t.Fatalf("rule %s missing pattern", r.ID)
		}
	}
}

func TestFixtureCorpus(t *testing.T) {
	s := NewScanner(config.Default())
	root := filepath.Join("testdata")
	if _, err := os.Stat(root); err != nil {
		t.Skip("fixtures not present")
	}
	result, err := s.Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("scan fixtures: %v", err)
	}
	want := map[string]bool{
		"sqli-concat": true, "sqli-format": true, "xss-eval": true,
		"path-traversal": true, "cmd-inject-shell": true, "cmd-inject-exec": true,
		"ssrf-http": true, "path-join-user": true,
	}
	got := findingRules(result)
	for id := range want {
		if got[id] == 0 {
			t.Errorf("fixture corpus missing rule %s (got %+v)", id, got)
		}
	}
	// Negative file should not add false English-Update / bare-bash hits beyond intentional ones.
	for _, f := range result.Findings {
		if f.Location.File == "clean.go" {
			t.Errorf("unexpected finding in clean.go: %s", f.RuleID)
		}
	}
}
