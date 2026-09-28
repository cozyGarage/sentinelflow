package vulndb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestQueryRetriesThenSucceeds(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(OSVResponse{Vulns: []OSVVulnerability{{
			ID: "GO-1", Summary: "x",
		}}})
	}))
	defer srv.Close()

	src := NewOSVSource(srv.Client())
	src.SetBaseURL(srv.URL)
	vulns, err := src.Query(context.Background(), "go", "example.com/mod", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 || vulns[0].ID != "GO-1" {
		t.Fatalf("%+v", vulns)
	}
	if hits.Load() < 3 {
		t.Fatalf("expected retries, hits=%d", hits.Load())
	}
}

func TestQueryBatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Errorf("path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []OSVResponse{{Vulns: []OSVVulnerability{{ID: "A"}}}},
		})
	}))
	defer srv.Close()
	src := NewOSVSource(srv.Client())
	src.SetBaseURL(srv.URL)
	out, err := src.QueryBatch(context.Background(), []OSVRequest{{Version: "1"}})
	if err != nil || len(out) != 1 || len(out[0]) != 1 || out[0][0].ID != "A" {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestDiskCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c, err := NewDiskCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Set("go:mod:1", []Vulnerability{{ID: "V"}}, 0); err == nil {
		// ttl 0 expires immediately
	}
	_ = c.Set("go:mod:1", []Vulnerability{{ID: "V"}}, 1e9)
	got, err := c.Get("go:mod:1")
	if err != nil || len(got) != 1 || got[0].ID != "V" {
		t.Fatalf("%+v %v", got, err)
	}
}
