package vulndb

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type failingSource struct{}

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
