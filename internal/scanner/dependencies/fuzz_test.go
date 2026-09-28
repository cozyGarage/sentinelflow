package dependencies

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParseGoSum(f *testing.F) {
	f.Add("github.com/foo/bar v1.2.3 h1:abcd\n")
	f.Add("github.com/foo/bar v1.2.3/go.mod h1:efgh\n")
	f.Fuzz(func(t *testing.T, data string) {
		dir := t.TempDir()
		p := filepath.Join(dir, "go.sum")
		if err := os.WriteFile(p, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
		_, _ = parseGoSum(p)
	})
}

func FuzzParsePythonRequirement(f *testing.F) {
	f.Add("requests==2.31.0")
	f.Add("Foo-Bar>=1.0")
	f.Fuzz(func(t *testing.T, line string) {
		_, _, _ = parsePythonRequirement(line)
	})
}
