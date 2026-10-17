package dependencies

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/baseline"
	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/reporter"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/internal/vulndb"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func TestSC021_NpmLockRetainsInstalledInstances(t *testing.T) {
	content := []byte(`{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.21"},"node_modules/a/node_modules/lodash":{"version":"4.17.20"},"node_modules/@babel/core":{"version":"7.24.0"}}}`)
	deps, err := parseNpmLock(content, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 3 {
		t.Fatalf("want all 3 installed package instances, got %+v", deps)
	}
	got := map[string]string{}
	for _, d := range deps {
		got[d.InstallPath] = d.Name + "@" + d.Version
	}
	if got["node_modules/lodash"] != "lodash@4.17.21" || got["node_modules/a/node_modules/lodash"] != "lodash@4.17.20" || got["node_modules/@babel/core"] != "@babel/core@7.24.0" {
		t.Fatalf("unexpected install instances: %#v", got)
	}
}

func TestSC022_NpmLockInventoryIsDeterministic(t *testing.T) {
	first := []byte(`{"lockfileVersion":3,"packages":{"node_modules/z":{"version":"1"},"node_modules/a":{"version":"2"}}}`)
	second := []byte(`{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"2"},"node_modules/z":{"version":"1"}}}`)
	a, err := parseNpmLock(first, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseNpmLock(second, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("inventory sizes differ: %d != %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Version != b[i].Version || a[i].InstallPath != b[i].InstallPath {
			t.Fatalf("input key order changed result at %d: %+v != %+v", i, a[i], b[i])
		}
	}
}

func TestSC023_NpmV1LockTraversesArbitraryNestedDependencies(t *testing.T) {
	content := []byte(`{"lockfileVersion":1,"dependencies":{"a":{"version":"1","dependencies":{"b":{"version":"2","dependencies":{"@scope/c":{"version":"3"}}}}}}}`)
	deps, err := parseNpmLock(content, "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 3 || deps[2].Name != "@scope/c" || deps[2].InstallPath != "node_modules/a/node_modules/b/node_modules/@scope/c" {
		t.Fatalf("nested v1 inventory mismatch: %+v", deps)
	}
}

func TestPipScannerRequirementsAndPyProject(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("requests==2.28.1\n# comment\nflask>=2.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	pyproject := `
[project]
dependencies = [
  "urllib3==1.26.18",
]
[project.optional-dependencies]
dev = ["pytest==7.4.0"]

[tool.poetry.dependencies]
python = "^3.11"
django = {version = "4.2.0"}
`
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte(pyproject), 0644); err != nil {
		t.Fatal(err)
	}

	deps, err := (&PipScanner{}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]Dependency{}
	for _, d := range deps {
		got[d.Name] = d
	}
	for _, name := range []string{"requests", "flask", "urllib3", "django", "pytest"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("missing dependency %s in %#v", name, got)
		}
	}
	if got["requests"].Version != "2.28.1" {
		t.Fatalf("requests version = %s", got["requests"].Version)
	}
	if !got["pytest"].Dev {
		t.Fatal("expected pytest marked as dev")
	}
}

func TestPipScannerPoetryLock(t *testing.T) {
	root := t.TempDir()
	lock := `
[[package]]
name = "certifi"
version = "2023.7.22"
category = "main"

[[package]]
name = "black"
version = "23.9.1"
category = "dev"
`
	if err := os.WriteFile(filepath.Join(root, "poetry.lock"), []byte(lock), 0644); err != nil {
		t.Fatal(err)
	}

	deps, err := (&PipScanner{}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
}

func TestPipScannerPyProjectOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte(`
[project]
name = "demo"
dependencies = ["httpx==0.25.0"]
`), 0644); err != nil {
		t.Fatal(err)
	}

	deps, err := (&PipScanner{}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "httpx" {
		t.Fatalf("unexpected deps: %+v", deps)
	}
}

func TestMavenScannerParsesPom(t *testing.T) {
	root := t.TempDir()
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <properties>
    <jackson.version>2.15.2</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`
	if err := os.WriteFile(filepath.Join(root, "pom.xml"), []byte(pom), 0644); err != nil {
		t.Fatal(err)
	}

	deps, err := (&MavenScanner{}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d (%+v)", len(deps), deps)
	}

	byName := map[string]Dependency{}
	for _, d := range deps {
		byName[d.Name] = d
	}
	jackson := byName["com.fasterxml.jackson.core:jackson-databind"]
	if jackson.Version != "2.15.2" {
		t.Fatalf("jackson version = %s", jackson.Version)
	}
	if !byName["junit:junit"].Dev {
		t.Fatal("expected junit marked as dev/test")
	}
}

func TestCargoScannerLockAndToml(t *testing.T) {
	root := t.TempDir()
	lock := `
[[package]]
name = "demo"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.188"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde_json"
version = "1.0.107"
source = "registry+https://github.com/rust-lang/crates.io-index"
`
	if err := os.WriteFile(filepath.Join(root, "Cargo.lock"), []byte(lock), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte(`
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
`), 0644); err != nil {
		t.Fatal(err)
	}

	deps, err := (&CargoScanner{}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 registry deps from lockfile, got %d (%+v)", len(deps), deps)
	}

	// Toml-only project
	root2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(root2, "Cargo.toml"), []byte(`
[dependencies]
tokio = { version = "1.32.0", features = ["full"] }
[dev-dependencies]
tempfile = "3.8.0"
`), 0644); err != nil {
		t.Fatal(err)
	}
	deps, err = (&CargoScanner{}).Scan(context.Background(), root2)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 toml deps, got %d", len(deps))
	}
	for _, d := range deps {
		if d.Name == "tempfile" && !d.Dev {
			t.Fatal("expected tempfile as dev dependency")
		}
	}
}

func TestParsePythonRequirement(t *testing.T) {
	name, ver, ok := parsePythonRequirement("Requests[security]==2.28.1 ; python_version>='3'")
	if !ok || name != "Requests" || ver != "2.28.1" {
		t.Fatalf("got %s %s %v", name, ver, ok)
	}
	if _, _, ok := parsePythonRequirement("requests @ git+https://example.com/req.git"); ok {
		t.Fatal("URL requirements should be skipped")
	}
}

func TestNpmPrefersPackageLock(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "dependencies": { "lodash": "^4.0.0" }
}`), 0644); err != nil {
		t.Fatal(err)
	}
	lock := `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app" },
    "node_modules/lodash": { "version": "4.17.21" }
  }
}`
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lock), 0644); err != nil {
		t.Fatal(err)
	}
	deps, err := (&NpmScanner{}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "lodash" || deps[0].Version != "4.17.21" {
		t.Fatalf("expected lockfile exact version, got %+v", deps)
	}
	if !strings.HasSuffix(deps[0].FilePath, "package-lock.json") {
		t.Fatalf("expected package-lock path, got %s", deps[0].FilePath)
	}
}

func TestNpmPrefersYarnLock(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"lodash":"^4.0.0"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	yarn := `# yarn lockfile v1

lodash@^4.0.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"
  integrity sha512-abc

"@scope/pkg@^1.0.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.3.tgz#def"
  integrity sha512-def
`
	if err := os.WriteFile(filepath.Join(root, "yarn.lock"), []byte(yarn), 0644); err != nil {
		t.Fatal(err)
	}
	deps, err := (&NpmScanner{}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range deps {
		got[d.Name] = d.Version
	}
	if got["lodash"] != "4.17.21" || got["@scope/pkg"] != "1.2.3" {
		t.Fatalf("expected yarn.lock pins, got %+v", got)
	}
}

func TestSC024_DepFindingIdentityIncludesInstalledInstance(t *testing.T) {
	s := NewScanner(config.Default())
	a := s.createFinding(Dependency{Name: "lodash", Version: "4.17.21", Ecosystem: "npm", FilePath: "/tmp/package-lock.json", InstallPath: "node_modules/a/node_modules/lodash"}, Vulnerability{ID: "CVE-1", Severity: api.SeverityHigh}, "/tmp")
	b := s.createFinding(Dependency{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", FilePath: "/tmp/package-lock.json", InstallPath: "node_modules/b/node_modules/lodash"}, Vulnerability{ID: "CVE-1", Severity: api.SeverityHigh}, "/tmp")
	if a.ID == b.ID {
		t.Fatalf("same CVE in different installed instances must differ: %s", a.ID)
	}
	if a.Location.Snippet == b.Location.Snippet || a.Metadata["install_path"] == b.Metadata["install_path"] {
		t.Fatal("instance identity must survive in location and metadata")
	}
}

func TestSC024_NpmInstancesReachOSVAndSurviveReportBaseline(t *testing.T) {
	root := t.TempDir()
	lockPath := filepath.Join(root, "package-lock.json")
	body := `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"},"node_modules/a/node_modules/lodash":{"version":"4.17.20"}}}`
	if err := os.WriteFile(lockPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(root, "package.json")
	if err := os.WriteFile(packagePath, []byte(`{"name":"fixture"}`), 0600); err != nil {
		t.Fatal(err)
	}
	queried := map[string]bool{}
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
			results := make([]vulndb.OSVResponse, len(req.Queries))
			for i, q := range req.Queries {
				if q.Package.Name != "lodash" || q.Package.Ecosystem != "npm" {
					t.Errorf("unexpected package tuple: %+v", q)
				}
				queried[q.Version] = true
				results[i].Vulns = []vulndb.OSVVulnerability{{ID: "OSV-INSTANCE"}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/vulns/OSV-INSTANCE":
			_, _ = w.Write([]byte(`{"id":"OSV-INSTANCE","summary":"synthetic package issue"}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	deps := &Scanner{config: &config.Config{}, client: testClient(t, server), ecosystems: map[string]EcosystemScanner{"npm": &NpmScanner{}}}
	result, err := deps.Scan(context.Background(), root, types.ScanOptions{Files: []string{lockPath, packagePath}})
	if err != nil {
		t.Fatal(err)
	}
	if len(queried) != 2 || !queried["4.17.20"] || !queried["4.17.21"] || len(result.Findings) != 2 {
		t.Fatalf("both installed versions must be queried and attributed: queries=%v findings=%+v", queried, result.Findings)
	}
	for i := range result.Findings {
		f := &result.Findings[i]
		if f.Metadata["package"] != "lodash" || f.Metadata["ecosystem"] != "npm" || f.Metadata["install_path"] == nil || f.Location.Snippet == "" {
			t.Fatalf("package-instance identity missing from finding: %+v", *f)
		}
	}
	fingerprint.Ensure(result.Findings)
	encoded, err := reporter.New(&config.Config{}).Generate(&api.ScanResult{Findings: result.Findings}, "json")
	if err != nil {
		t.Fatal(err)
	}
	var report api.ScanResult
	if err := json.Unmarshal([]byte(encoded), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 || report.Findings[0].Metadata["install_path"] == report.Findings[1].Metadata["install_path"] {
		t.Fatalf("JSON report lost installed-instance identity: %+v", report.Findings)
	}
	filtered := baseline.Filter(report.Findings, baseline.Generate([]api.Finding{report.Findings[0]}))
	if len(filtered) != 1 || filtered[0].Metadata["install_path"] == report.Findings[0].Metadata["install_path"] {
		t.Fatalf("baseline must suppress only the matching installed instance: %+v", filtered)
	}
}

func TestSC074_OSVAliasesSurviveDependencyFindingConstruction(t *testing.T) {
	s := &Scanner{}
	finding := s.createFinding(
		Dependency{Name: "lodash", Version: "4.17.21", Ecosystem: "npm", FilePath: "/tmp/package-lock.json"},
		Vulnerability{ID: "OSV-1", Aliases: []string{"GHSA-aaaa", "CVE-2024-0001"}},
		"/tmp",
	)
	aliases, ok := finding.Metadata["vulnerability_aliases"].([]string)
	if !ok || len(aliases) != 2 || aliases[0] != "GHSA-aaaa" || aliases[1] != "CVE-2024-0001" {
		t.Fatalf("OSV aliases must remain available for scoped VEX matching: %#v", finding.Metadata["vulnerability_aliases"])
	}
}

func TestSC081_FindingIdentifiesAdvisorySource(t *testing.T) {
	s := &Scanner{config: config.Default()}
	finding := s.createFinding(
		Dependency{Name: "lodash", Version: "4.17.21", Ecosystem: "npm", FilePath: "/tmp/package-lock.json"},
		Vulnerability{ID: "OSV-1", Source: "osv"}, "/tmp",
	)
	if got := finding.Metadata["vulnerability_source"]; got != "osv" {
		t.Fatalf("finding should identify advisory source, got %#v", got)
	}
}

func TestRubyGemsScannerGemfileLock(t *testing.T) {
	root := t.TempDir()
	lock := `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.3)
      actionpack (= 7.1.3)
    actionpack (7.1.3)
    nokogiri (1.16.2-x86_64-linux)
      racc (~> 1.4)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rails (~> 7.1)
`
	if err := os.WriteFile(filepath.Join(root, "Gemfile.lock"), []byte(lock), 0644); err != nil {
		t.Fatal(err)
	}
	s := &RubyGemsScanner{}
	if !s.Detect(root) {
		t.Fatal("expected Detect on Gemfile.lock")
	}
	deps, err := s.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range deps {
		got[d.Name] = d.Version
	}
	if got["rails"] != "7.1.3" || got["actionpack"] != "7.1.3" {
		t.Fatalf("expected gem pins, got %+v", got)
	}
	if got["nokogiri"] != "1.16.2" {
		t.Fatalf("expected platform suffix stripped, got %q", got["nokogiri"])
	}
	if (&RubyGemsScanner{}).Detect(t.TempDir()) {
		t.Fatal("bare dir without Gemfile.lock must not Detect")
	}
	s2 := NewScanner(config.Default())
	if s2.Supports("Gemfile") {
		t.Fatal("bare Gemfile must remain unsupported")
	}
	if !s2.Supports("Gemfile.lock") {
		t.Fatal("expected Supports(Gemfile.lock)")
	}
}
