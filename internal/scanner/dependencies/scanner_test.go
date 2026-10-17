package dependencies

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/internal/vulndb"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

type partialDetailOSV struct{}

func (partialDetailOSV) Name() string { return "partial-detail" }
func (partialDetailOSV) Query(context.Context, string, string, string) ([]vulndb.Vulnerability, error) {
	return nil, errors.New("unexpected single query")
}
func (partialDetailOSV) QueryBatch(context.Context, []vulndb.OSVRequest) ([][]vulndb.OSVVulnerability, error) {
	return [][]vulndb.OSVVulnerability{{{ID: "OSV-A"}, {ID: "OSV-B"}}}, nil
}
func (partialDetailOSV) GetVuln(_ context.Context, id string) (*vulndb.OSVVulnerability, error) {
	if id == "OSV-B" {
		return nil, errors.New("synthetic detail failure")
	}
	return &vulndb.OSVVulnerability{ID: id, Summary: "matched advisory"}, nil
}

func TestSC088_CheckAllRetainsFindingsWithBatchLookupError(t *testing.T) {
	client, err := vulndb.NewClient(vulndb.WithSources(partialDetailOSV{}), vulndb.WithCache(vulndb.NewMemoryCache()))
	if err != nil {
		t.Fatal(err)
	}
	scanner := &Scanner{config: &config.Config{}, client: client}
	results, err := scanner.checkAll(context.Background(), []Dependency{{Name: "example.com/lib", Version: "1.0.0", Ecosystem: "go"}})
	if err == nil {
		t.Fatal("lookup detail failure should be reported")
	}
	if len(results) != 1 || len(results[0]) != 1 || results[0][0].ID != "OSV-A" {
		t.Fatalf("safe partial match was discarded: %+v", results)
	}
}

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

func TestSC015_OptInGoModuleGraphUsesSelectedVersionsAndPreservesDirectAttribution(t *testing.T) {
	root := t.TempDir()
	goMod := "module example.com/root\n\ngo 1.22\n\nrequire (\n\texample.com/direct v1.0.0\n\texample.com/indirect v1.1.0 // indirect\n)\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(root, "fake-go")
	script := `#!/bin/sh
test "$GOWORK" = off || exit 20
test "$GOPROXY" = off || exit 21
test "$GOSUMDB" = off || exit 22
test "$GOTOOLCHAIN" = local || exit 23
test -z "$GOFLAGS" || exit 25
test "$1 $2 $3 $4 $5" = "list -m -json -mod=readonly all" || exit 24
printf '%s\n' '{"Path":"example.com/root","Main":true}' '{"Path":"example.com/direct","Version":"v1.4.0"}' '{"Path":"example.com/transitive","Version":"v2.3.1"}'
`
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	deps, err := (&GoModScanner{ResolveGraph: true, goCommand: fake}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("resolved graph should contain direct and transitive modules: %+v", deps)
	}
	byName := map[string]Dependency{}
	for _, dep := range deps {
		byName[dep.Name] = dep
	}
	direct := byName["example.com/direct"]
	if direct.Version != "v1.4.0" || direct.Line == 0 || direct.Inventory != "go_list_module" || direct.Dev {
		t.Fatalf("selected direct module should retain go.mod attribution: %+v", direct)
	}
	transitive := byName["example.com/transitive"]
	if transitive.Version != "v2.3.1" || transitive.Line != 0 || transitive.Inventory != "go_list_module" {
		t.Fatalf("transitive module should be marked as resolved graph evidence: %+v", transitive)
	}
}

func TestSC015_GoModuleGraphFailsClosedForErrorTimeoutAndMissingTool(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/root\n\ngo 1.22\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		script  string
		command string
		timeout time.Duration
		want    string
	}{
		{name: "command error", script: "#!/bin/sh\necho synthetic module error >&2\nexit 2\n", want: "synthetic module error"},
		{name: "timeout", script: "#!/bin/sh\nexec sleep 2\n", timeout: 25 * time.Millisecond, want: "deadline exceeded"},
		{name: "missing tool", command: filepath.Join(root, "missing-go"), want: "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := tc.command
			if command == "" {
				command = filepath.Join(root, "fake-"+strings.ReplaceAll(tc.name, " ", "-"))
				if err := os.WriteFile(command, []byte(tc.script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			cancel := func() {}
			if tc.timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, tc.timeout)
			}
			defer cancel()
			_, err := (&GoModScanner{ResolveGraph: true, goCommand: command}).Scan(ctx, root)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("graph resolution error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestSC015_GoModuleGraphRejectsReplacementsBeforeRunningTool(t *testing.T) {
	root := t.TempDir()
	goMod := "module example.com/root\n\ngo 1.22\n\nreplace example.com/lib => ../lib\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(root, "fake-go")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := (&GoModScanner{ResolveGraph: true, goCommand: fake}).Scan(context.Background(), root)
	if err == nil || !strings.Contains(err.Error(), "local replacements are not yet supported") {
		t.Fatalf("replacement boundary should be explicit before graph command, got %v", err)
	}
}

func TestSC016_VersionedReplacementQueriesBothCoordinatesAndRetainsDeclaration(t *testing.T) {
	root := t.TempDir()
	goMod := filepath.Join(root, "go.mod")
	content := "module example.com/root\n\ngo 1.22\n\nrequire example.com/lib v1.2.0\nreplace example.com/lib v1.2.0 => example.com/fork/lib v2.3.4\n"
	if err := os.WriteFile(goMod, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(root, "fake-go")
	script := `#!/bin/sh
printf '%s\n' '{"Path":"example.com/root","Main":true}' '{"Path":"example.com/lib","Version":"v1.2.0","Replace":{"Path":"example.com/fork/lib","Version":"v2.3.4"}}'
`
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var queried []vulndb.OSVRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/querybatch":
			var req struct {
				Queries []vulndb.OSVRequest `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode query: %v", err)
			}
			queried = append(queried, req.Queries...)
			results := make([]vulndb.OSVResponse, len(req.Queries))
			for i, query := range req.Queries {
				if query.Package.Name == "example.com/fork/lib" {
					results[i].Vulns = []vulndb.OSVVulnerability{{ID: "OSV-REPLACEMENT"}}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/vulns/OSV-REPLACEMENT":
			_, _ = w.Write([]byte(`{"id":"OSV-REPLACEMENT","summary":"replacement advisory"}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	s := &Scanner{
		config: config.Default(), client: testClient(t, server),
		ecosystems: map[string]EcosystemScanner{"go": &GoModScanner{ResolveGraph: true, goCommand: fake}},
	}
	result, err := s.Scan(context.Background(), root, types.ScanOptions{Files: []string{goMod}})
	if err != nil {
		t.Fatal(err)
	}
	if len(queried) != 2 {
		t.Fatalf("both declared and replacement coordinates must be queried: %+v", queried)
	}
	got := map[string]string{}
	for _, query := range queried {
		got[query.Package.Name] = query.Version
	}
	if got["example.com/lib"] != "1.2.0" || got["example.com/fork/lib"] != "2.3.4" {
		t.Fatalf("wrong advisory coordinates: %+v", queried)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("replacement advisory should not disappear: %+v", result.Findings)
	}
	finding := result.Findings[0]
	if finding.Metadata["package"] != "example.com/lib" || finding.Metadata["version"] != "v1.2.0" {
		t.Fatalf("finding should retain the declared dependency attribution: %+v", finding.Metadata)
	}
	coordinates, ok := finding.Metadata["additional_advisory_coordinates"].([]map[string]string)
	if !ok || len(coordinates) != 1 || coordinates[0]["package"] != "example.com/fork/lib" || coordinates[0]["version"] != "v2.3.4" {
		t.Fatalf("finding should disclose replacement advisory coordinates: %#v", finding.Metadata["additional_advisory_coordinates"])
	}
}

func TestSC017_LocalAndUnversionedReplacementsFailWithoutRegistryIdentity(t *testing.T) {
	for _, tc := range []struct {
		name      string
		replace   string
		wantError string
	}{
		{name: "nested local", replace: "replace example.com/lib => ./vendor/lib", wantError: "local replacements are not yet supported"},
		{name: "outside root", replace: "replace example.com/lib => ../shared/lib", wantError: "local replacements are not yet supported"},
		{name: "unversioned module path", replace: "replace example.com/lib => example.com/fork/lib", wantError: "replacement module without version must be directory path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			content := "module example.com/root\n\ngo 1.22\n\nrequire example.com/lib v1.2.0\n" + tc.replace + "\n"
			if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			fake := filepath.Join(root, "fake-go")
			if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
				t.Fatal(err)
			}
			deps, err := (&GoModScanner{ResolveGraph: true, goCommand: fake}).Scan(context.Background(), root)
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("replacement should fail with explicit unresolved coverage, deps=%+v err=%v", deps, err)
			}
			if len(deps) != 0 || strings.Contains(err.Error(), "exit status 99") {
				t.Fatalf("must not invent a registry identity or execute graph resolution: deps=%+v err=%v", deps, err)
			}
		})
	}
}

func TestSC018_WorkspaceUsesSelectedGraphOnceAndKeepsMemberAttribution(t *testing.T) {
	root := t.TempDir()
	moduleA, moduleB := filepath.Join(root, "a"), filepath.Join(root, "b")
	if err := os.MkdirAll(moduleA, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(moduleB, 0700); err != nil {
		t.Fatal(err)
	}
	goModA := filepath.Join(moduleA, "go.mod")
	goModB := filepath.Join(moduleB, "go.mod")
	if err := os.WriteFile(goModA, []byte("module example.com/a\n\ngo 1.22\n\nrequire example.com/lib v1.1.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goModB, []byte("module example.com/b\n\ngo 1.22\n\nrequire example.com/lib v1.2.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	goWork := filepath.Join(root, "go.work")
	workContent := "go 1.22\n\nuse (\n\t./a\n\t./b\n)\n\nreplace example.com/lib => example.com/fork/lib v2.0.0\n"
	if err := os.WriteFile(goWork, []byte(workContent), 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "go-list-invocations")
	fake := filepath.Join(root, "fake-go")
	script := "#!/bin/sh\necho invoked >> '" + marker + "'\ntest \"$GOWORK\" = '" + goWork + "' || exit 20\ntest \"$1 $2 $3 $4 $5\" = 'list -m -json -mod=readonly all' || exit 21\nprintf '%s\\n' '{\"Path\":\"example.com/a\",\"Main\":true}' '{\"Path\":\"example.com/b\",\"Main\":true}' '{\"Path\":\"example.com/lib\",\"Version\":\"v1.2.0\",\"Replace\":{\"Path\":\"example.com/fork/lib\",\"Version\":\"v2.0.0\"}}' '{\"Path\":\"example.com/transitive\",\"Version\":\"v3.1.0\"}'\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var queried []vulndb.OSVRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/querybatch":
			var req struct {
				Queries []vulndb.OSVRequest `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode query: %v", err)
			}
			queried = append(queried, req.Queries...)
			results := make([]vulndb.OSVResponse, len(req.Queries))
			for i, query := range req.Queries {
				if query.Package.Name == "example.com/fork/lib" {
					results[i].Vulns = []vulndb.OSVVulnerability{{ID: "OSV-WORKSPACE"}}
				} else if query.Package.Name == "example.com/transitive" {
					results[i].Vulns = []vulndb.OSVVulnerability{{ID: "OSV-TRANSITIVE"}}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/vulns/OSV-WORKSPACE":
			_, _ = w.Write([]byte(`{"id":"OSV-WORKSPACE","summary":"workspace replacement advisory"}`))
		case "/v1/vulns/OSV-TRANSITIVE":
			_, _ = w.Write([]byte(`{"id":"OSV-TRANSITIVE","summary":"workspace transitive advisory"}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	s := &Scanner{
		config: config.Default(), client: testClient(t, server),
		ecosystems: map[string]EcosystemScanner{"go": &GoModScanner{ResolveGraph: true, goCommand: fake}},
	}
	result, err := s.Scan(context.Background(), root, types.ScanOptions{Files: []string{goModA, goModB}})
	if err != nil {
		t.Fatal(err)
	}
	invocations, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(invocations), "invoked"); got != 1 {
		t.Fatalf("workspace graph should be resolved once, got %d invocations", got)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "resolved once for the selected `go.work` workspace") {
		t.Fatalf("workspace resolution provenance missing: %+v", result.Warnings)
	}
	queries := map[string]bool{}
	for _, query := range queried {
		queries[query.Package.Name+"@"+query.Version] = true
	}
	for _, coordinate := range []string{"example.com/lib@1.2.0", "example.com/fork/lib@2.0.0", "example.com/transitive@3.1.0"} {
		if !queries[coordinate] {
			t.Errorf("workspace-selected advisory coordinate %s missing from %v", coordinate, queries)
		}
	}
	if len(result.Findings) != 3 {
		t.Fatalf("workspace findings should include both module declarations and the transitive component: %+v", result.Findings)
	}
	locations := map[string]bool{}
	for _, finding := range result.Findings {
		locations[finding.Location.File] = true
		wantPackage := "example.com/lib"
		if finding.RuleID == "OSV-TRANSITIVE" {
			wantPackage = "example.com/transitive"
		}
		if finding.Metadata["package"] != wantPackage {
			t.Errorf("finding lost declared module attribution: %+v", finding.Metadata)
		}
	}
	if !locations[filepath.Join("a", "go.mod")] || !locations[filepath.Join("b", "go.mod")] {
		t.Fatalf("workspace member source locations missing: %v", locations)
	}
	if !locations["go.work"] {
		t.Fatalf("transitive workspace component should use the stable workspace manifest location: %v", locations)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	subdirectoryResult, err := s.Scan(context.Background(), moduleA, types.ScanOptions{Files: []string{goModA}})
	if err != nil {
		t.Fatal(err)
	}
	if len(subdirectoryResult.Findings) != 3 {
		t.Fatalf("subdirectory scan should honor parent workspace membership: %+v", subdirectoryResult.Findings)
	}
	subdirectoryInvocations, err := os.ReadFile(marker)
	if err != nil || strings.Count(string(subdirectoryInvocations), "invoked") != 1 {
		t.Fatalf("subdirectory workspace graph should resolve once: calls=%q err=%v", subdirectoryInvocations, err)
	}
}

func TestSC018_LocalWorkspaceReplacementFailsBeforeGraphCommand(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "a")
	if err := os.MkdirAll(moduleDir, 0700); err != nil {
		t.Fatal(err)
	}
	goMod := filepath.Join(moduleDir, "go.mod")
	if err := os.WriteFile(goMod, []byte("module example.com/a\n\ngo 1.22\n"), 0600); err != nil {
		t.Fatal(err)
	}
	goWork := filepath.Join(root, "go.work")
	if err := os.WriteFile(goWork, []byte("go 1.22\n\nuse ./a\nreplace example.com/lib => ./fork\n"), 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "unexpected-go-list")
	fake := filepath.Join(root, "fake-go")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch '"+marker+"'\nexit 99\n"), 0700); err != nil {
		t.Fatal(err)
	}
	deps, err := (&GoModScanner{ResolveGraph: true, WorkspacePath: goWork, goCommand: fake}).Scan(context.Background(), moduleDir)
	if err == nil || !strings.Contains(err.Error(), "local workspace replacements are not yet supported") {
		t.Fatalf("local workspace replacement must fail with explicit coverage error: deps=%+v err=%v", deps, err)
	}
	if len(deps) != 0 {
		t.Fatalf("local workspace replacement must not invent dependencies: %+v", deps)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("graph command must not run for unsupported local workspace replacement: stat err=%v", err)
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
