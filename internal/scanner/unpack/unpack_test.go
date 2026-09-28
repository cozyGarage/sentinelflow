package unpack

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestZipSlipRejected(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "evil.zip")
	f, err := os.Create(zp)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("../../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/sh\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, err = Zip(context.Background(), zp, Limits{MaxBytes: 1024 * 1024, MaxDepth: 1})
	if err == nil {
		t.Fatal("expected zip-slip rejection")
	}
}

func TestZipHappyPath(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "ok.zip")
	f, err := os.Create(zp)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("WEB-INF/lib/note.txt")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello artifact")
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	res, err := Zip(context.Background(), zp, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != "WEB-INF/lib/note.txt" {
		t.Fatalf("files = %+v", res.Files)
	}
	if !bytes.Equal(res.Files[0].Data, payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestSanitize(t *testing.T) {
	if _, err := sanitize("/etc/passwd"); err == nil {
		t.Fatal("abs")
	}
	if _, err := sanitize("foo/../../etc/passwd"); err == nil {
		t.Fatal("dotdot")
	}
	got, err := sanitize("./ok/file.txt")
	if err != nil || got != "ok/file.txt" {
		t.Fatalf("got %q %v", got, err)
	}
}
