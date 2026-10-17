package vulndb

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		typ, a, b string
		want      int
	}{
		{"SEMVER", "1.2.3", "1.10.0", -1},
		{"SEMVER", "v1.0.0-rc.1", "1.0.0", -1},
		{"SEMVER", "0.0.0-20230101-abcdef", "0.1.0", -1},
		{"ECOSYSTEM", "2.31.0", "2.4.0", 1}, // numeric, not lexical
		{"ECOSYSTEM", "1.0rc1", "1.0", -1},  // PyPI pre-release
		{"ECOSYSTEM", "1.0", "1.0.0", 0},    // trailing zero
		{"ECOSYSTEM", "1.0.1", "1.0", 1},
		{"ECOSYSTEM", "2.14.1", "2.15.0", -1}, // Maven
		{"ECOSYSTEM", "31.1-jre", "32.0.0-jre", -1},
		{"ECOSYSTEM", "13.0.1", "13.0.1", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.typ, c.a, c.b); got != c.want {
			t.Errorf("%s %s vs %s = %d, want %d", c.typ, c.a, c.b, got, c.want)
		}
	}
}

func TestSC082_OfflineFreshnessPolicyUsesSnapshotTimeAndReportsState(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	configured, err := NewClient(OfflineOptions(true, 24*time.Hour)...)
	if err != nil {
		t.Fatal(err)
	}
	if source, ok := configured.sources[0].(*OfflineSource); !ok || source.maxAge != 24*time.Hour {
		t.Fatalf("strict freshness option was not wired into offline source: %#v", configured.sources)
	}
	for _, tc := range []struct {
		name       string
		index      *offlineIndex
		corrupt    bool
		wantStatus string
		wantErr    string
	}{
		{name: "fresh at boundary", index: &offlineIndex{Ecosystem: "Go", AcquiredAt: now.Add(-24 * time.Hour), Packages: map[string]json.RawMessage{}}, wantStatus: "available"},
		{name: "stale despite future file mtime", index: &offlineIndex{Ecosystem: "Go", AcquiredAt: now.Add(-24*time.Hour - time.Second), Packages: map[string]json.RawMessage{}}, wantStatus: "stale", wantErr: "sentinelflow db update --ecosystems go"},
		{name: "unknown legacy age", index: &offlineIndex{Ecosystem: "Go", Packages: map[string]json.RawMessage{}}, wantStatus: "unknown_age", wantErr: "unknown acquisition time"},
		{name: "missing", wantStatus: "missing", wantErr: "db update"},
		{name: "corrupt", corrupt: true, wantStatus: "corrupt", wantErr: "corrupt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "go.json.gz")
			if tc.corrupt {
				if err := os.WriteFile(path, []byte("not gzip"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if tc.index != nil {
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				gz := gzip.NewWriter(f)
				if err := json.NewEncoder(gz).Encode(tc.index); err != nil {
					t.Fatal(err)
				}
				if err := gz.Close(); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			future := now.Add(365 * 24 * time.Hour)
			if tc.index != nil || tc.corrupt {
				if err := os.Chtimes(path, future, future); err != nil {
					t.Fatal(err)
				}
			}
			source := NewOfflineSource(dir)
			source.maxAge = 24 * time.Hour
			source.now = func() time.Time { return now }
			_, err := source.Query(context.Background(), "go", "example.com/pkg", "1.0.0")
			if tc.wantErr == "" && err != nil {
				t.Fatalf("fresh snapshot rejected: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error=%v, want substring %q", err, tc.wantErr)
			}
			status := "available"
			if tc.wantErr != "" {
				status = "error"
			}
			if got := source.ProvenanceFor("go", status).Status; got != tc.wantStatus {
				t.Fatalf("provenance status=%q, want %q", got, tc.wantStatus)
			}
		})
	}
}

func TestSC082_OfflineCacheHitRechecksFreshness(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("SENTINELFLOW_CACHE_DIR", cacheRoot)
	dir := OfflineDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	index := offlineIndex{Ecosystem: "Go", AcquiredAt: now.Add(-time.Hour), Packages: map[string]json.RawMessage{}}
	f, err := os.Create(filepath.Join(dir, "go.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if err := json.NewEncoder(gz).Encode(index); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(OfflineOptions(true, 24*time.Hour)...)
	if err != nil {
		t.Fatal(err)
	}
	source := client.sources[0].(*OfflineSource)
	source.now = func() time.Time { return now }
	if _, err := client.Query(context.Background(), "go", "example.com/pkg", "1.0.0"); err != nil {
		t.Fatalf("initial fresh lookup failed: %v", err)
	}
	now = now.Add(25 * time.Hour)
	if _, err := client.Query(context.Background(), "go", "example.com/pkg", "1.0.0"); err == nil || !strings.Contains(err.Error(), "is stale") {
		t.Fatalf("cached result bypassed freshness limit: %v", err)
	}
	var sawStale bool
	for _, provenance := range client.VulnerabilityData() {
		sawStale = sawStale || provenance.Status == "stale"
	}
	if !sawStale {
		t.Fatalf("cache-hit provenance does not report stale snapshot: %+v", client.VulnerabilityData())
	}
}

func TestAffects(t *testing.T) {
	// Two windows: [1.0, 1.2) and [2.0, 2.1], plus a last_affected bound.
	events := []rangeEvent{{Introduced: "2.0"}, {Fixed: "1.2"}, {Introduced: "1.0"}, {LastAffected: "2.1"}}
	for v, want := range map[string]bool{"0.9": false, "1.0": true, "1.1.5": true, "1.2": false, "1.9": false, "2.0": true, "2.1": true, "2.1.1": false} {
		if got := affects("ECOSYSTEM", append([]rangeEvent(nil), events...), v); got != want {
			t.Errorf("%s: got %v want %v", v, got, want)
		}
	}
	if !affects("SEMVER", []rangeEvent{{Introduced: "0"}, {Fixed: "0.17.0"}}, "0.16.9") {
		t.Error("introduced 0 must cover everything before fixed")
	}
}

func TestOfflineUpdateAndQuery(t *testing.T) {
	zipOf := func(files map[string]string) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for name, body := range files {
			w, _ := zw.Create(name)
			_, _ = w.Write([]byte(body))
		}
		_ = zw.Close()
		return buf.Bytes()
	}
	exports := map[string][]byte{
		"/Go/all.zip": zipOf(map[string]string{
			"GO-1.json": `{"id":"GO-1","summary":"x/net bug","aliases":["CVE-1"],
				"affected":[{"package":{"name":"golang.org/x/net","ecosystem":"Go"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.38.0"}]}]}]}`,
			"GO-W.json": `{"id":"GO-W","withdrawn":"2024-01-01T00:00:00Z",
				"affected":[{"package":{"name":"golang.org/x/net","ecosystem":"Go"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
		}),
		"/PyPI/all.zip": zipOf(map[string]string{
			"PYSEC-1.json": `{"id":"PYSEC-1","affected":[{"package":{"name":"requests","ecosystem":"PyPI"},
				"versions":["2.30.0"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.3.0"},{"fixed":"2.31.0"}]}]}]}`,
		}),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := exports[r.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	old := OfflineBaseURL
	OfflineBaseURL = srv.URL
	defer func() { OfflineBaseURL = old }()

	dir := t.TempDir()
	counts, err := UpdateOffline(context.Background(), srv.Client(), dir, []string{"go", "pip"})
	if err != nil {
		t.Fatal(err)
	}
	if counts["go"] != 1 || counts["pip"] != 1 {
		t.Fatalf("withdrawn advisories must be dropped: %v", counts)
	}
	status := OfflineStatus(dir)
	goSnapshot := status["go"]
	if goSnapshot.IsZero() {
		t.Fatal("offline index should expose its acquisition time")
	}
	indexPath := filepath.Join(dir, "go.json.gz")
	future := time.Now().Add(365 * 24 * time.Hour)
	if err := os.Chtimes(indexPath, future, future); err != nil {
		t.Fatal(err)
	}
	if got := OfflineStatus(dir)["go"]; !got.Equal(goSnapshot) {
		t.Fatalf("touching the index must not refresh snapshot time: got %s want %s", got, goSnapshot)
	}
	var goData, missingData bool
	for _, data := range OfflineSnapshots(dir) {
		if data.Ecosystem == "go" {
			goData = data.Status == "available" && data.Supported && strings.HasPrefix(data.SnapshotID, "sha256:")
		}
		if data.Ecosystem == "npm" {
			missingData = data.Status == "missing" && data.Supported
		}
	}
	if !goData || !missingData {
		t.Fatal("offline status must expose supported ecosystem and missing/available snapshot state")
	}

	src := NewOfflineSource(dir)
	for _, c := range []struct {
		eco, pkg, version string
		want              []string
	}{
		{"go", "golang.org/x/net", "0.37.0", []string{"GO-1"}},
		{"go", "golang.org/x/net", "v0.38.0", nil},
		{"pip", "requests", "2.30.0", []string{"PYSEC-1"}},
		{"pip", "requests", "2.4.0", []string{"PYSEC-1"}},
		{"pip", "requests", "2.31.0", nil},
		{"pip", "unknown", "1.0", nil},
	} {
		vulns, err := src.Query(context.Background(), c.eco, c.pkg, c.version)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, v := range vulns {
			ids = append(ids, v.ID)
		}
		if strings.Join(ids, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s %s@%s: got %v want %v", c.eco, c.pkg, c.version, ids, c.want)
		}
	}
	prov := src.ProvenanceFor("go", "available")
	if prov.Mode != "offline" || prov.Source != srv.URL+"/Go/all.zip" || !strings.HasPrefix(prov.SnapshotID, "sha256:") || prov.AcquiredAt == nil {
		t.Fatalf("offline snapshot provenance missing or invalid: %+v", prov)
	}
	if vulns, _ := src.Query(context.Background(), "go", "golang.org/x/net", "0.37.0"); vulns[0].CVE != "CVE-1" {
		t.Errorf("alias lost in index: %+v", vulns[0])
	}
	if _, err := src.Query(context.Background(), "npm", "x", "1"); err == nil || !strings.Contains(err.Error(), "db update") {
		t.Errorf("missing ecosystem must point at db update, got %v", err)
	}
}
