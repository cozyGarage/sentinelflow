package sbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func TestGenerateFromGoMod(t *testing.T) {
	tmpDir := t.TempDir()
	goMod := `module example.com/test

go 1.24

require (
	github.com/spf13/cobra v1.10.2
	github.com/fatih/color v1.16.0
)
`
	os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644)

	s := NewScanner(&config.Config{})
	result, err := s.Generate(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if len(result.Document.Components) < 2 {
		t.Errorf("expected at least 2 components, got %d", len(result.Document.Components))
	}
	if result.Document.BOMFormat != "CycloneDX" {
		t.Error("expected CycloneDX format")
	}
}

func TestWriteJSON(t *testing.T) {
	tmpDir := t.TempDir()
	s := NewScanner(&config.Config{})
	doc := &CycloneDX{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Components:  []Component{{Type: "library", Name: "test", Version: "1.0.0"}},
	}
	outPath := filepath.Join(tmpDir, "sbom.json")
	if err := s.WriteJSON(doc, outPath); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Error("output file not created")
	}
}

func TestGenerateUsesDependencyParsers(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"requirements.txt": "requests==2.31.0\n",
		"pom.xml":          `<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency></dependencies></project>`,
		"package.json":     `{"dependencies":{"@babel/core":"7.0.0"}}`,
		"yarn.lock":        "\"@babel/core@7.0.0\":\n  version \"7.0.0\"\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := NewScanner(&config.Config{}).Generate(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, c := range res.Document.Components {
		got[c.PURL] = true
	}
	for _, want := range []string{
		"pkg:pypi/requests@2.31.0",
		"pkg:maven/org.apache.commons/commons-text@1.9",
		"pkg:npm/%40babel/core@7.0.0",
	} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
}

func TestPURLKeepsGoVersionPrefix(t *testing.T) {
	if got := PURL("go", "github.com/a/b", "v1.2.3"); got != "pkg:golang/github.com/a/b@v1.2.3" {
		t.Fatal(got)
	}
}

func TestPURLEcosystemRoundTrip(t *testing.T) {
	for _, tc := range []struct{ eco, name, version string }{
		{"npm", "@babel/core", "7.0.0"},
		{"maven", "org.apache.commons:commons-text", "1.9"},
		{"go", "github.com/a/b", "v1.2.3"},
		{"pip", "requests", "2.31.0"},
		{"rubygems", "rails", "7.0.0"},
	} {
		eco, name := purlEcosystem(PURL(tc.eco, tc.name, tc.version))
		if eco != tc.eco || name != tc.name {
			t.Errorf("%s/%s: round trip gave %s/%s", tc.eco, tc.name, eco, name)
		}
	}
	if eco, name := purlEcosystem("pkg:npm/@scope/pkg@1.0.0"); eco != "npm" || name != "@scope/pkg" {
		t.Errorf("unencoded scope: %s/%s", eco, name)
	}
	if eco, _ := purlEcosystem("pkg:unknown/x@1"); eco != "" {
		t.Errorf("unknown type must be skipped, got %s", eco)
	}
}
