package unpack

import (
	"path/filepath"
	"strings"
	"testing"
)

func FuzzSanitize(f *testing.F) {
	f.Add("../../etc/passwd")
	f.Add("/abs/path")
	f.Add("ok/nested/file.txt")
	f.Add("..\\windows\\path")
	f.Fuzz(func(t *testing.T, name string) {
		got, err := sanitize(name)
		if err != nil {
			return
		}
		if got == "" || filepath.IsAbs(got) || strings.HasPrefix(got, "../") || got == ".." || strings.Contains(got, "/../") {
			t.Fatalf("unsafe path accepted: %q", got)
		}
	})
}
