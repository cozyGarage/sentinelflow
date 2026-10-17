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

func TestSC011_GoInventoryUsesSelectedGoModRequirement(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module example.com/demo\n\ngo 1.22\n\nrequire (\n\tgithub.com/acme/lib v1.2.0 // indirect\n)\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "go.sum"), []byte("github.com/acme/lib v1.1.0 h1:old\ngithub.com/acme/lib v1.2.0 h1:new\n"), 0644); err != nil {
		t.Fatal(err)
	}
	deps, err := (&GoModScanner{}).Scan(context.Background(), tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Version != "v1.2.0" || deps[0].Inventory != "go.mod_require" || !deps[0].Dev {
		t.Fatalf("go.mod selected inventory mismatch: %+v", deps)
	}
}

func TestSC011_QuerybatchUsesRequireVersionNotChecksumOnlyVersions(t *testing.T) {
	root := t.TempDir()
	goMod := filepath.Join(root, "go.mod")
	if err := os.WriteFile(goMod, []byte("module example.com/demo\n\nrequire example.com/lib v1.2.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte("example.com/lib v1.1.0 h1:old\nexample.com/transitive v0.8.0 h1:sum-only\nexample.com/lib v1.2.0 h1:new\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var queried []vulndb.OSVRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/querybatch" {
			var req struct {
				Queries []vulndb.OSVRequest `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode query: %v", err)
			}
			queried = append(queried, req.Queries...)
			_ = json.NewEncoder(w).Encode(map[string]any{"results": make([]vulndb.OSVResponse, len(req.Queries))})
			return
		}
		t.Errorf("unexpected request: %s", r.URL.Path)
	}))
	t.Cleanup(server.Close)
	s := &Scanner{config: &config.Config{}, client: testClient(t, server), ecosystems: map[string]EcosystemScanner{"go": &GoModScanner{}}}
	if _, err := s.Scan(context.Background(), root, types.ScanOptions{Files: []string{goMod}}); err != nil {
		t.Fatal(err)
	}
	if len(queried) != 1 || queried[0].Package.Name != "example.com/lib" || queried[0].Version != "1.2.0" {
		t.Fatalf("query set must use selected require only, got %+v", queried)
	}
}

func TestSC012_GoInventoryRejectsMalformedGoMod(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module example.com/demo\nrequire (broken\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := (&GoModScanner{}).Scan(context.Background(), tmp); err == nil {
		t.Fatal("malformed go.mod must fail inventory parsing")
	}
}

func TestSC012_GoRequireSyntaxPreservesVersionsAndLocations(t *testing.T) {
	root := t.TempDir()
	body := "module example.com/demo\n\nrequire example.com/inline v1.0.0 // direct\n\nrequire (\n\t// grouped module\n\texample.com/grouped v0.3.4 // indirect\n)\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	deps, err := (&GoModScanner{}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("want inline and grouped requirements, got %+v", deps)
	}
	got := map[string]Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
	}
	if got["example.com/inline"].Version != "v1.0.0" || got["example.com/inline"].Line != 3 || got["example.com/grouped"].Version != "v0.3.4" || got["example.com/grouped"].Line != 7 || !got["example.com/grouped"].Dev {
		t.Fatalf("require syntax/location mismatch: %+v", got)
	}
}

func TestSC013_GoInventorySurvivesMissingOrMalformedSums(t *testing.T) {
	for _, sum := range []struct {
		name string
		body *string
	}{
		{name: "missing"},
		{name: "malformed", body: stringPtr("not a checksum record\n")},
	} {
		t.Run(sum.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/demo\n\nrequire example.com/lib v1.2.3\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if sum.body != nil {
				if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte(*sum.body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			deps, err := (&GoModScanner{}).Scan(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if len(deps) != 1 || deps[0].Name != "example.com/lib" || deps[0].Version != "v1.2.3" {
				t.Fatalf("declared dependency must remain available independent of checksum state: %+v", deps)
			}
		})
	}
}

func stringPtr(s string) *string { return &s }

func TestSC014_GoInventoryWarnsOnWorkspaceAndReplacementLimits(t *testing.T) {
	root := t.TempDir()
	goMod := filepath.Join(root, "go.mod")
	if err := os.WriteFile(goMod, []byte("module example.com/demo\n\ngo 1.22\n\nrequire example.com/lib v1.2.3\nreplace example.com/lib => ../local-lib\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.22\n\nuse .\n"), 0600); err != nil {
		t.Fatal(err)
	}
	server, _ := fakeOSV(t)
	s := &Scanner{
		config:     &config.Config{Scanners: config.ScannersConfig{Dependencies: config.DependenciesConfig{Enabled: true}}},
		client:     testClient(t, server),
		ecosystems: map[string]EcosystemScanner{"go": &GoModScanner{}},
	}
	res, err := s.Scan(context.Background(), root, types.ScanOptions{Files: []string{goMod}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "go.mod requirements") || !strings.Contains(res.Warnings[0], "workspace selection, and replacements") {
		t.Fatalf("unsupported resolved-graph coverage must be explicit: %+v", res.Warnings)
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
