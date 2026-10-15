package dependencies

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/internal/vulndb"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestSeverityFromVulnDB(t *testing.T) {
	tests := []struct {
		in   string
		want api.Severity
	}{
		{"CRITICAL", api.SeverityCritical},
		{"HIGH", api.SeverityHigh},
		{"MODERATE", api.SeverityMedium},
		{"LOW", api.SeverityLow},
		{"", api.SeverityMedium},
	}

	for _, tc := range tests {
		if got := severityFromVulnDB(tc.in, 0); got != tc.want {
			t.Errorf("severityFromVulnDB(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestCheckVulnerabilitiesUsesOSV(t *testing.T) {
	server, _ := fakeOSV(t, "lodash")
	client := testClient(t, server)

	scanner := &Scanner{
		config: &config.Config{},
		client: client,
	}

	vulns, err := scanner.checkVulnerabilities(context.Background(), Dependency{
		Name:      "lodash",
		Version:   "4.17.20",
		Ecosystem: "npm",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].ID != "OSV-TEST-1" {
		t.Fatalf("unexpected vuln id %s", vulns[0].ID)
	}
}

func TestGoModScannerParsesSingleLineRequire(t *testing.T) {
	tmp := t.TempDir()
	content := "module example.com/demo\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n"
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	deps, err := (&GoModScanner{}).Scan(context.Background(), tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dependency, got %d", len(deps))
	}
	if deps[0].Name != "github.com/foo/bar" || deps[0].Version != "v1.2.3" {
		t.Fatalf("unexpected dependency: %+v", deps[0])
	}
}

// fakeOSV serves querybatch and vuln lookups; every package in vulnerable gets OSV-TEST-1.
func fakeOSV(t *testing.T, vulnerable ...string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var batchCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/querybatch":
			batchCalls.Add(1)
			var req struct {
				Queries []vulndb.OSVRequest `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode: %v", err)
			}
			results := make([]vulndb.OSVResponse, len(req.Queries))
			for i, q := range req.Queries {
				for _, name := range vulnerable {
					if q.Package.Name == name {
						results[i].Vulns = []vulndb.OSVVulnerability{{ID: "OSV-TEST-1"}}
					}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			_, _ = w.Write([]byte(`{"id":"OSV-TEST-1","summary":"test vuln","aliases":["CVE-2024-0001"]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return server, &batchCalls
}

func testClient(t *testing.T, server *httptest.Server) *vulndb.Client {
	t.Helper()
	source := vulndb.NewOSVSource(server.Client())
	source.SetBaseURL(server.URL)
	client, err := vulndb.NewClient(vulndb.WithSources(source), vulndb.WithCache(vulndb.NewMemoryCache()))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestScanFindsNestedManifestsWithOneBatchCall(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	files := []string{
		write("svc/a/go.mod", "module a\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n"),
		write("svc/b/go.mod", "module b\n\ngo 1.22\n\nrequire github.com/baz/qux v0.1.0\n"),
		write("svc/a/main.go", "package main\n"),
	}

	server, batchCalls := fakeOSV(t, "github.com/foo/bar", "github.com/baz/qux")
	s := &Scanner{config: &config.Config{}, client: testClient(t, server), ecosystems: map[string]EcosystemScanner{"go": &GoModScanner{}}}

	res, err := s.Scan(context.Background(), root, types.ScanOptions{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Location.File] = true
	}
	if !got["svc/a/go.mod"] || !got["svc/b/go.mod"] || len(res.Findings) != 2 {
		t.Fatalf("want findings in both nested go.mod files, got %+v", res.Findings)
	}
	if n := batchCalls.Load(); n != 1 {
		t.Fatalf("want 1 querybatch call, got %d", n)
	}
}
