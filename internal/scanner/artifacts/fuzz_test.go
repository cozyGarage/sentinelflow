package artifacts

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzELFHardening(f *testing.F) {
	f.Add([]byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01})
	f.Add([]byte{'M', 'Z'})
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "bin")
		if err := os.WriteFile(p, data, 0644); err != nil {
			t.Fatal(err)
		}
		_ = elfHardening(p, "bin")
		_ = peHardening(p, "bin")
		_ = machoHardening(p, "bin")
	})
}
