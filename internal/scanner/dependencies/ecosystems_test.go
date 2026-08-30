package dependencies

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

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

func TestDepFindingIDIncludesPackage(t *testing.T) {
	s := NewScanner(config.Default())
	a := s.createFinding(Dependency{Name: "pkg-a", Version: "1.0.0", Ecosystem: "npm", FilePath: "/tmp/package.json"}, Vulnerability{ID: "CVE-1", Severity: api.SeverityHigh}, "/tmp")
	b := s.createFinding(Dependency{Name: "pkg-b", Version: "1.0.0", Ecosystem: "npm", FilePath: "/tmp/package.json"}, Vulnerability{ID: "CVE-1", Severity: api.SeverityHigh}, "/tmp")
	if a.ID == b.ID {
		t.Fatalf("same CVE in different packages must differ: %s", a.ID)
	}
}
