package vulndb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type partialBatchSource struct {
	failID string
	hits   [][]OSVVulnerability
}

func (s *partialBatchSource) Name() string { return "partial-batch" }
func (s *partialBatchSource) Query(context.Context, string, string, string) ([]Vulnerability, error) {
	return nil, errors.New("unexpected single query")
}
func (s *partialBatchSource) QueryBatch(context.Context, []OSVRequest) ([][]OSVVulnerability, error) {
	return s.hits, nil
}
func (s *partialBatchSource) GetVuln(_ context.Context, id string) (*OSVVulnerability, error) {
	if id == s.failID {
		return nil, errors.New("fixture detail failure")
	}
	return &OSVVulnerability{ID: id, Summary: "fixture detail"}, nil
}

func TestSC088_QueryManyPreservesSuccessfulDetailsButDoesNotCachePartialResults(t *testing.T) {
	source := &partialBatchSource{
		failID: "OSV-B",
		hits:   [][]OSVVulnerability{{{ID: "OSV-A"}, {ID: "OSV-B"}}},
	}
	cache := NewMemoryCache()
	client, err := NewClient(WithSources(source), WithCache(cache))
	if err != nil {
		t.Fatal(err)
	}
	queries := []PackageQuery{{Ecosystem: "go", Name: "example.com/lib", Version: "1.0.0"}}
	results, err := client.QueryMany(context.Background(), queries)
	if err == nil {
		t.Fatal("partial advisory detail failure must remain an error")
	}
	if len(results) != 1 || len(results[0]) != 1 || results[0][0].ID != "OSV-A" {
		t.Fatalf("successful advisory detail was lost or incomplete detail leaked: %+v", results)
	}
	key, _ := client.cacheKey(context.Background(), "go", "example.com/lib", "1.0.0")
	if _, err := cache.Get(key); err == nil {
		t.Fatal("partial batch results must not be cached as a complete answer")
	}
}

type failingSource struct{}
type partialQuerySource struct{}

type countingSource struct{ calls int }
type namespacedSource struct {
	identity string
	answer   string
}

func (s namespacedSource) Name() string { return "namespaced" }
func (s namespacedSource) Query(context.Context, string, string, string) ([]Vulnerability, error) {
	return []Vulnerability{{ID: s.answer}}, nil
}
func (s namespacedSource) CacheIdentity(context.Context, string) (string, error) {
	return s.identity, nil
}

func TestSC090_CacheIsolatedByConfiguredSourceIdentity(t *testing.T) {
	cache := NewMemoryCache()
	first, err := NewClient(WithSources(namespacedSource{identity: "source-a", answer: "OSV-A"}), WithCache(cache))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewClient(WithSources(namespacedSource{identity: "source-b", answer: "OSV-B"}), WithCache(cache))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		client *Client
		want   string
	}{{first, "OSV-A"}, {second, "OSV-B"}} {
		vulns, err := tc.client.Query(context.Background(), "go", "example.com/lib", "1.0.0")
		if err != nil || len(vulns) != 1 || vulns[0].ID != tc.want {
			t.Fatalf("query got %+v, %v; want %s", vulns, err, tc.want)
		}
	}
}

func TestSC090_CorruptCacheEntryIsReplacedAfterSuccessfulLookup(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewDiskCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	source := &countingSource{}
	client, err := NewClient(WithSources(source), WithCache(cache))
	if err != nil {
		t.Fatal(err)
	}
	key, err := client.cacheKey(context.Background(), "go", "example.com/lib", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	disk := cache.(*diskCache)
	if err := os.WriteFile(disk.pathFor(key), []byte("{truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := client.Query(context.Background(), "go", "example.com/lib", "1.0.0"); err != nil {
			t.Fatal(err)
		}
	}
	if source.calls != 1 {
		t.Fatalf("corrupt entry should miss once, then use repaired cache; source calls=%d", source.calls)
	}
}

func TestSC090_DiskCacheConcurrentReadersObserveCompleteEntries(t *testing.T) {
	cache, err := NewDiskCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Set("shared-key", []Vulnerability{{ID: "OSV-0"}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	for writer := 0; writer < 4; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if err := cache.Set("shared-key", []Vulnerability{{ID: fmt.Sprintf("OSV-%d-%d", writer, i)}}, time.Hour); err != nil {
					errCh <- err
					return
				}
			}
		}(writer)
	}
	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				vulns, err := cache.Get("shared-key")
				if err != nil {
					errCh <- err
					return
				}
				if len(vulns) != 1 || !strings.HasPrefix(vulns[0].ID, "OSV-") {
					errCh <- fmt.Errorf("reader observed incomplete cache entry: %+v", vulns)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func (s *countingSource) Name() string { return "test-osv" }
func (s *countingSource) Query(ctx context.Context, ecosystem, pkg, version string) ([]Vulnerability, error) {
	s.calls++
	return []Vulnerability{}, nil
}

func (f failingSource) Name() string { return "failing" }
func (f failingSource) Query(ctx context.Context, ecosystem, pkg, version string) ([]Vulnerability, error) {
	return nil, fmt.Errorf("upstream down")
}

func (partialQuerySource) Name() string { return "partial-query" }
func (partialQuerySource) Query(context.Context, string, string, string) ([]Vulnerability, error) {
	return []Vulnerability{{ID: "OSV-PARTIAL"}}, fmt.Errorf("upstream truncated response")
}

func TestSC088_QueryRetainsPartialPositiveAndDoesNotCache(t *testing.T) {
	cache := NewMemoryCache()
	client, err := NewClient(WithSources(partialQuerySource{}), WithCache(cache))
	if err != nil {
		t.Fatal(err)
	}
	vulns, err := client.Query(context.Background(), "go", "example.com/lib", "1.0.0")
	if err == nil {
		t.Fatal("partial source result must retain an operational error")
	}
	if len(vulns) != 1 || vulns[0].ID != "OSV-PARTIAL" {
		t.Fatalf("successful partial match was discarded: %+v", vulns)
	}
	key, _ := client.cacheKey(context.Background(), "go", "example.com/lib", "1.0.0")
	if _, err := cache.Get(key); err == nil {
		t.Fatal("partial source response must not be cached")
	}
}

func TestQueryDoesNotCacheSourceFailures(t *testing.T) {
	cache := NewMemoryCache()
	client, err := NewClient(WithSources(failingSource{}), WithCache(cache))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Query(context.Background(), "npm", "lodash", "4.17.20")
	if err == nil {
		t.Fatal("expected query error when all sources fail")
	}

	key, _ := client.cacheKey(context.Background(), "npm", "lodash", "4.17.20")
	if _, err := cache.Get(key); err == nil {
		t.Fatal("failed lookups must not be cached as empty results")
	}
}

func TestMemoryCacheCopiesSlices(t *testing.T) {
	cache := NewMemoryCache().(*memoryCache)
	vulns := []Vulnerability{{ID: "V1"}}
	if err := cache.Set("k", vulns, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := cache.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	got[0].ID = "mutated"
	again, err := cache.Get("k")
	if err != nil {
		t.Fatal(err)
	}
	if again[0].ID != "V1" {
		t.Fatalf("cache exposed mutable slice, got %s", again[0].ID)
	}
}

func TestSC081_ProvenanceDistinguishesLiveAndCachedLookups(t *testing.T) {
	source := &countingSource{}
	client, err := NewClient(WithSources(source), WithCache(NewMemoryCache()))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := client.Query(context.Background(), "npm", "widget", "1.0.0"); err != nil {
			t.Fatal(err)
		}
	}
	if source.calls != 1 {
		t.Fatalf("cache did not avoid second source call: %d", source.calls)
	}
	var live, cached bool
	for _, data := range client.VulnerabilityData() {
		if data.Ecosystem != "npm" || !data.Supported {
			t.Fatalf("ecosystem capability missing: %+v", data)
		}
		live = live || data.Source == "test-osv" && data.Mode == "online" && data.Status == "available"
		cached = cached || data.Source == "query-cache" && data.Mode == "cache" && data.Status == "hit"
	}
	if !live || !cached {
		t.Fatalf("expected live and cache-hit provenance, got %+v", client.VulnerabilityData())
	}
}
