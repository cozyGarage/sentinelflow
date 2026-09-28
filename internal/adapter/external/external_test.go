package external

import (
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

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
}

func TestParseTrivyFS(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":"go.mod","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-1","PkgName":"x","InstalledVersion":"1.0","Severity":"HIGH","Title":"boom"}]}]}`)
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
