package vulndb

import (
	"context"
	"errors"
	"fmt"
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
	if _, err := cache.Get(cacheKey("go", "example.com/lib", "1.0.0")); err == nil {
		t.Fatal("partial batch results must not be cached as a complete answer")
	}
}

type failingSource struct{}
type partialQuerySource struct{}

type countingSource struct{ calls int }

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
	if _, err := cache.Get(cacheKey("go", "example.com/lib", "1.0.0")); err == nil {
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

	if _, err := cache.Get("npm:lodash:4.17.20"); err == nil {
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
