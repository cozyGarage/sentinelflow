package vulndb

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSC087_CopyLimitedEnforcesInclusiveByteCeiling(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{"at limit", "1234", "1234"},
		{"over limit", "12345", "1234"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dst bytes.Buffer
			n, err := copyLimited(&dst, strings.NewReader(tc.data), 4)
			if tc.want == "1234" && len(tc.data) == 4 {
				if err != nil || n != 4 || dst.String() != tc.want {
					t.Fatalf("copyLimited = %d, %q, %v", n, dst.String(), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "maximum archive size") || n != 5 {
				t.Fatalf("over-limit copy = %d, %q, %v", n, dst.String(), err)
			}
		})
	}
}

func TestSC087_IndexReaderEnforcesDecompressedSize(t *testing.T) {
	if _, err := decodeOfflineIndex(strings.NewReader("{}"), 2); err != nil {
		t.Fatalf("index exactly at byte limit should decode: %v", err)
	}
	if _, err := decodeOfflineIndex(strings.NewReader("{} "), 2); err == nil || !strings.Contains(err.Error(), "maximum uncompressed size") {
		t.Fatalf("oversized index should fail with explicit size error, got %v", err)
	}
	var dst bytes.Buffer
	writer := &sizeLimitWriter{w: &dst, limit: 2}
	if n, err := writer.Write([]byte("{}")); err != nil || n != 2 {
		t.Fatalf("index write at limit = %d, %v", n, err)
	}
	if _, err := writer.Write([]byte(" ")); err == nil || !strings.Contains(err.Error(), "maximum uncompressed size") {
		t.Fatalf("oversized index write should fail explicitly, got %v", err)
	}
}

func TestSC087_FailedRefreshPreservesSnapshotAndCleansTemps(t *testing.T) {
	valid := makeOSVArchive(t, map[string]string{
		"GO-1.json": `{"id":"GO-1","affected":[{"package":{"name":"example.com/lib","ecosystem":"Go"},"versions":["1.0.0"]}]}`,
	})
	var mu sync.Mutex
	response := valid
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write(response)
	}))
	defer server.Close()
	oldBase := OfflineBaseURL
	OfflineBaseURL = server.URL
	t.Cleanup(func() { OfflineBaseURL = oldBase })

	dir := t.TempDir()
	if _, err := UpdateOffline(context.Background(), server.Client(), dir, []string{"go"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "go.json.gz")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	response = []byte("truncated archive")
	mu.Unlock()
	if _, err := UpdateOffline(context.Background(), server.Client(), dir, []string{"go"}); err == nil {
		t.Fatal("invalid replacement archive must fail")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed refresh replaced the previous valid snapshot")
	}
	for _, pattern := range []string{"go-*.zip", "go.json.gz-*.part"} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Errorf("temporary files leaked after failed refresh: %v", matches)
		}
	}
}

func TestSC087_ConcurrentRefreshesAndReadersSeeCompleteSnapshots(t *testing.T) {
	archive := makeOSVArchive(t, map[string]string{
		"GO-1.json": `{"id":"GO-1","affected":[{"package":{"name":"example.com/lib","ecosystem":"Go"},"versions":["1.0.0"]}]}`,
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) }))
	defer server.Close()
	oldBase := OfflineBaseURL
	OfflineBaseURL = server.URL
	t.Cleanup(func() { OfflineBaseURL = oldBase })
	dir := t.TempDir()
	if _, err := UpdateOffline(context.Background(), server.Client(), dir, []string{"go"}); err != nil {
		t.Fatal(err)
	}

	const writers = 6
	var wg sync.WaitGroup
	errCh := make(chan error, writers+1)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := UpdateOffline(context.Background(), server.Client(), dir, []string{"go"}); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			source := NewOfflineSource(dir)
			vulns, err := source.Query(context.Background(), "go", "example.com/lib", "1.0.0")
			if err != nil {
				errCh <- err
				return
			}
			if len(vulns) != 1 || vulns[0].ID != "GO-1" {
				errCh <- errors.New("reader observed incomplete or unexpected snapshot")
				return
			}
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
