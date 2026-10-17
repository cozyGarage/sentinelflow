package vulndb

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type cancelAtEOF struct {
	io.Reader
	cancel context.CancelFunc
}

func (r cancelAtEOF) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		r.cancel()
	}
	return n, err
}

func TestSC088_QueryBatchRetainsCompletedAlignedChunksOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := strings.TrimSuffix(strings.Repeat("{},", 1000), ",")
	body := `{"results":[` + results + `]}`
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(cancelAtEOF{Reader: strings.NewReader(body), cancel: cancel}),
		}, nil
	})}
	source := NewOSVSource(client)
	queries := make([]OSVRequest, 1001)
	resultsByQuery, err := source.QueryBatch(ctx, queries)
	if err == nil {
		t.Fatal("cancelled second querybatch chunk should return an error")
	}
	if len(resultsByQuery) != 1000 {
		t.Fatalf("completed first chunk should remain aligned: got %d results, want 1000; err=%v", len(resultsByQuery), err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancellation error, got %v", err)
	}
}

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
