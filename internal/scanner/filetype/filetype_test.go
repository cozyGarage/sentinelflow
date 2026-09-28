package filetype

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectBytesMagic(t *testing.T) {
	cases := []struct {
		hdr  []byte
		kind Kind
	}{
		{[]byte{0x7f, 'E', 'L', 'F', 0x02}, KindELF},
		{[]byte{'M', 'Z', 0x90, 0x00}, KindPE},
		{[]byte{'P', 'K', 0x03, 0x04, 0x00}, KindZip},
		{[]byte{0x1f, 0x8b, 0x08}, KindGzip},
		{[]byte("%PDF-1.7"), KindPDF},
		{[]byte("package main\nfunc main() {}\n"), KindText},
		{[]byte{0x00, 0x01, 0x02, 0x03, 0x00}, KindBinary},
	}
	for _, tc := range cases {
		if got := DetectBytes(tc.hdr); got != tc.kind {
			t.Errorf("DetectBytes(%q) = %s, want %s", tc.hdr[:min(8, len(tc.hdr))], got, tc.kind)
		}
	}
}

func TestDetectFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.go")
	if err := os.WriteFile(p, []byte("package a\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if k := Detect(p); k != KindText {
		t.Fatalf("got %s", k)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
