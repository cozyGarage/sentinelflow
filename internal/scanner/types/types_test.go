package types

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunWorkersRespectsConcurrency(t *testing.T) {
	var active int32
	var maxActive int32
	items := make([]string, 20)
	for i := range items {
		items[i] = "x"
	}

	RunWorkers(context.Background(), 3, items, func(string) {
		n := atomic.AddInt32(&active, 1)
		for {
			old := atomic.LoadInt32(&maxActive)
			if n <= old || atomic.CompareAndSwapInt32(&maxActive, old, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&active, -1)
	})

	if maxActive > 3 {
		t.Fatalf("expected at most 3 workers, saw %d", maxActive)
	}
}

func TestEffectiveConcurrency(t *testing.T) {
	if got := EffectiveConcurrency(nil, 0, 4); got != 4 {
		t.Fatalf("fallback = %d", got)
	}
	if got := EffectiveConcurrency(ScanOptions{Concurrency: 8}, 10, 4); got != 10 {
		t.Fatalf("scanner-specific should win, got %d", got)
	}
	if got := EffectiveConcurrency(ScanOptions{Concurrency: 8}, 0, 4); got != 8 {
		t.Fatalf("opts concurrency = %d", got)
	}
}

func TestAsScanOptions(t *testing.T) {
	opts := ScanOptions{Concurrency: 5, Files: []string{"a"}}
	got, ok := AsScanOptions(opts)
	if !ok || got.Concurrency != 5 || len(got.Files) != 1 {
		t.Fatalf("unexpected %#v ok=%v", got, ok)
	}
	got, ok = AsScanOptions(&opts)
	if !ok || got.Concurrency != 5 {
		t.Fatalf("pointer opts failed")
	}
}

func TestResolveFilesEmptyListIsAuthoritative(t *testing.T) {
	dir := t.TempDir()
	walked := false
	fallback := func(string) ([]string, error) { walked = true; return []string{"x"}, nil }

	files, err := ResolveFiles(dir, ScanOptions{Files: []string{}}, fallback)
	if err != nil || len(files) != 0 || walked {
		t.Fatalf("empty engine list must not re-walk: files=%v walked=%v err=%v", files, walked, err)
	}
	if _, _ = ResolveFiles(dir, ScanOptions{}, fallback); !walked {
		t.Fatal("nil list should use fallback")
	}
}
