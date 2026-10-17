package external

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestSC032_AdapterDoesNotTreatFindingsAsProcessSuccess(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-scanner")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s' '{\"results\":[{\"check_id\":\"test.rule\",\"path\":\"a.go\",\"extra\":{\"message\":\"hit\",\"severity\":\"ERROR\"},\"start\":{\"line\":1}}]}'\nexit 2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	a := &Adapter{name: "fake", bin: "fake-scanner", mode: "required", args: func(string) []string { return nil }, parse: parseSemgrep, requiresOutput: true}
	res, err := a.Scan(t.Context(), t.TempDir(), nil)
	if err == nil {
		t.Fatal("tool failure must be returned even when it emitted a finding")
	}
	if len(res.Findings) != 1 {
		t.Fatalf("preserve parsed findings alongside error, got %+v", res)
	}
}

func TestSC033_RequiredAdapterRejectsEmptyReport(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-scanner")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	a := &Adapter{name: "fake", bin: "fake-scanner", mode: "required", args: func(string) []string { return nil }, parse: parseSemgrep, requiresOutput: true}
	if _, err := a.Scan(t.Context(), t.TempDir(), nil); err == nil {
		t.Fatal("empty required report must fail")
	}
}

func TestSC033_RequiredAdapterRejectsMalformedOrTruncatedReport(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "malformed", body: "not-json"},
		{name: "truncated", body: "{\"results\":["},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "fake-scanner")
			script := "#!/bin/sh\ncat <<'SENTINELFLOW_JSON'\n" + tc.body + "\nSENTINELFLOW_JSON\n"
			if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			a := &Adapter{name: "fake", bin: "fake-scanner", mode: "required", args: func(string) []string { return nil }, parse: parseSemgrep, requiresOutput: true}
			result, err := a.Scan(t.Context(), t.TempDir(), nil)
			if err == nil || result.Status != api.ScanStatusFailed {
				t.Fatal("malformed or truncated required report must fail")
			}
		})
	}
	if _, err := parseGitleaks(".", []byte("{\"unexpected\":\"object\"}")); err == nil {
		t.Fatal("Gitleaks JSON with the wrong root shape must not become zero findings")
	}
}

func TestSC033_JsonReportsRequireToolSpecificResultCollections(t *testing.T) {
	cases := []struct {
		name      string
		parse     func(string, []byte) ([]api.Finding, error)
		malformed string
		clean     string
	}{
		{name: "semgrep", parse: parseSemgrep, malformed: `{}`, clean: `{"results":[]}`},
		{name: "grype", parse: parseGrype, malformed: `{}`, clean: `{"matches":[]}`},
		{name: "syft", parse: parseSyft, malformed: `{}`, clean: `{"artifacts":[]}`},
		{name: "trivy", parse: parseTrivyFS, malformed: `{}`, clean: `{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.parse(".", []byte(tc.malformed)); err == nil {
				t.Fatal("JSON object without the tool's result collection must not become a clean scan")
			}
			findings, err := tc.parse(".", []byte(tc.clean))
			if err != nil || len(findings) != 0 {
				t.Fatalf("valid explicit empty report should be clean: findings=%d err=%v", len(findings), err)
			}
		})
	}
}

func TestSC034_AutoModeKeepsFindingAndWarnsOnToolFailure(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-scanner")
	script := "#!/bin/sh\nprintf '%s' '{\"results\":[{\"check_id\":\"test.rule\",\"path\":\"a.go\",\"extra\":{\"message\":\"hit\",\"severity\":\"ERROR\"},\"start\":{\"line\":1}}]}'\nexit 2\n"
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	a := &Adapter{name: "fake", bin: "fake-scanner", mode: "auto", args: func(string) []string { return nil }, parse: parseSemgrep, requiresOutput: true}
	result, err := a.Scan(t.Context(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("optional failure should remain warning-only: %v", err)
	}
	if result == nil || len(result.Findings) != 1 || len(result.Warnings) != 1 {
		t.Fatalf("optional failure must retain findings and warn: %+v", result)
	}
}

func TestSC034_AutoModeWarnsOnIncompleteSemgrepReportAndKeepsFindings(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-semgrep")
	report := `{"results":[{"check_id":"test.rule","path":"a.go","extra":{"message":"hit","severity":"ERROR"},"start":{"line":1}}],"errors":[{"message":"failed to parse another file"}]}`
	script := "#!/bin/sh\nprintf '%s' '" + report + "'\nexit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	a := &Adapter{name: "semgrep", bin: "fake-semgrep", mode: "auto", args: func(string) []string { return nil }, parse: parseSemgrep, requiresOutput: true}
	result, err := a.Scan(t.Context(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("auto mode should report degraded analysis as a warning: %v", err)
	}
	if result == nil || len(result.Findings) != 1 || len(result.Warnings) == 0 {
		t.Fatalf("retain findings and report incomplete analysis: %+v", result)
	}
}

func TestSC031_JsonAdaptersRequireReportOutput(t *testing.T) {
	for _, a := range []*Adapter{semgrepAdapter(), gitleaksAdapter(), grypeAdapter(), syftAdapter(), trivyFSAdapter()} {
		if !a.requiresOutput {
			t.Errorf("%s must require structured output", a.name)
		}
	}
	args := strings.Join(gitleaksAdapter().args("repo"), " ")
	if !strings.Contains(args, "--exit-code 0") {
		t.Fatalf("gitleaks finding exit must be separated from operational failures: %s", args)
	}
}

func TestSC031_ExternalToolCommandContracts(t *testing.T) {
	root := "/repo with spaces"
	tests := []struct {
		name        string
		adapter     *Adapter
		wantBin     string
		wantArgs    []string
		wantVersion []string
		wantReport  bool
	}{
		{"semgrep", semgrepAdapter(), "semgrep", []string{"--config=auto", "--json", "--quiet", root}, []string{"--version"}, true},
		{"gitleaks", gitleaksAdapter(), "gitleaks", []string{"detect", "--source", root, "--report-format", "json", "--no-banner", "--exit-code", "0"}, []string{"--version"}, true},
		{"grype", grypeAdapter(), "grype", []string{root, "-o", "json"}, []string{"--version"}, true},
		{"syft", syftAdapter(), "syft", []string{root, "-o", "json"}, []string{"--version"}, true},
		{"trivy", trivyFSAdapter(), "trivy", []string{"fs", "--format", "json", "--quiet", root}, []string{"--version"}, true},
		{"yara", yaraAdapter([]string{"rules.yar", "ignored.yar"}), "yara", []string{"-r", "rules.yar", root}, []string{"--version"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.adapter.bin != tc.wantBin {
				t.Fatalf("executable = %q, want %q", tc.adapter.bin, tc.wantBin)
			}
			got := tc.adapter.args(root)
			if strings.Join(got, "\x00") != strings.Join(tc.wantArgs, "\x00") {
				t.Fatalf("args = %#v, want %#v", got, tc.wantArgs)
			}
			if tc.adapter.requiresOutput != tc.wantReport {
				t.Fatalf("requiresOutput = %v, want %v", tc.adapter.requiresOutput, tc.wantReport)
			}
			if strings.Join(tc.adapter.version, "\x00") != strings.Join(tc.wantVersion, "\x00") {
				t.Fatalf("version probe args = %#v, want %#v", tc.adapter.version, tc.wantVersion)
			}
		})
	}
}

func TestParseSemgrep(t *testing.T) {
	raw := []byte(`{"results":[{"check_id":"go.lang.security.audit.xss","path":"a.go","extra":{"message":"xss","severity":"ERROR"},"start":{"line":4}}]}`)
	findings, err := parseSemgrep(".", raw)
	if err != nil || len(findings) != 1 {
		t.Fatalf("got %d %v", len(findings), err)
	}
	if findings[0].Scanner != "semgrep" || findings[0].Location.StartLine != 4 {
		t.Fatalf("%+v", findings[0])
	}
}

func TestParseGitleaks(t *testing.T) {
	raw := []byte(`[{"RuleID":"aws-access-key","Description":"AWS","File":"a.env","StartLine":2,"Match":"AKIATEST"}]`)
	findings, err := parseGitleaks(".", raw)
	if err != nil || len(findings) != 1 {
		t.Fatalf("got %d %v", len(findings), err)
	}
	if findings[0].Type != api.FindingTypeSecret {
		t.Fatalf("%+v", findings[0])
	}
}

func TestAdaptersOffByDefault(t *testing.T) {
	if n := len(Adapters(config.Default())); n != 0 {
		t.Fatalf("expected no external adapters by default, got %d", n)
	}
}

func TestRequiredAdapterMissingIsError(t *testing.T) {
	a := &Adapter{name: "missing-tool", bin: "definitely-not-on-path-sentinelflow", mode: "required",
		args:  func(path string) []string { return nil },
		parse: func(path string, stdout []byte) ([]api.Finding, error) { return nil, nil },
	}
	_, err := a.Scan(t.Context(), ".", nil)
	if err == nil {
		t.Fatal("required missing tool must error")
	}
}

func TestAutoAdapterMissingIsWarning(t *testing.T) {
	a := &Adapter{name: "missing-tool", bin: "definitely-not-on-path-sentinelflow", mode: "auto",
		args:  func(path string) []string { return nil },
		parse: func(path string, stdout []byte) ([]api.Finding, error) { return nil, nil },
	}
	res, err := a.Scan(t.Context(), ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("auto missing tool must warn")
	}
	if res.Status != api.ScanStatusSkipped {
		t.Fatalf("missing optional tool must be visibly skipped, got %q", res.Status)
	}
}

func TestRequiredAdapterMissingHasFailedOutcome(t *testing.T) {
	a := &Adapter{name: "missing-tool", bin: "definitely-not-on-path-sentinelflow", mode: "required",
		args:  func(string) []string { return nil },
		parse: func(string, []byte) ([]api.Finding, error) { return nil, nil },
	}
	result, err := a.Scan(t.Context(), ".", nil)
	if err == nil || result.Status != api.ScanStatusFailed {
		t.Fatalf("required missing tool must fail with explicit status: result=%+v err=%v", result, err)
	}
}

func TestParseTrivyFS(t *testing.T) {
	raw := []byte(`{"SchemaVersion":2,"ArtifactName":"repo","ArtifactType":"filesystem","Results":[{"Target":"go.mod","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-1","PkgName":"x","InstalledVersion":"1.0","Severity":"HIGH","Title":"boom"}]}]}`)
	findings, err := parseTrivyFS(".", raw)
	if err != nil || len(findings) != 1 {
		t.Fatalf("%v %+v", err, findings)
	}
	if findings[0].Scanner != "trivy-fs" {
		t.Fatalf("%+v", findings[0])
	}
}

func TestParseYARA(t *testing.T) {
	findings, err := parseYARA(".", []byte("malware_rule /tmp/bin\n"))
	if err != nil || len(findings) != 1 {
		t.Fatalf("%v %+v", err, findings)
	}
	if findings[0].RuleID != "malware_rule" {
		t.Fatalf("%+v", findings[0])
	}
}
