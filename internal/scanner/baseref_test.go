package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

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
	out, _ := exec.Command("git", "-C", root, "worktree", "list").Output()
	if n := len(strings.Split(strings.TrimSpace(string(out)), "\n")); n != 1 {
		t.Fatalf("temporary worktree not removed:\n%s", out)
	}
}
