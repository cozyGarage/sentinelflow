package vulndb

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
)

func TestSC086_OnlineOfflineParityAgainstSameAdvisoryFixture(t *testing.T) {
	fixtures := map[string]string{
		"GO-RANGE-1.json":  `{"id":"GO-RANGE-1","summary":"range case","aliases":["CVE-2026-1001"],"affected":[{"package":{"name":"example.com/lib","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]}`,
		"GO-LISTED-1.json": `{"id":"GO-LISTED-1","summary":"listed case","affected":[{"package":{"name":"example.com/lib","ecosystem":"Go"},"versions":["2.0.0"]}]}`,
	}
	archive := makeOSVArchive(t, fixtures)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/Go/all.zip" {
			_, _ = w.Write(archive)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/query" {
			http.NotFound(w, r)
			return
		}
		var request OSVRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.Package.Name != "example.com/lib" || request.Package.Ecosystem != "Go" {
			http.Error(w, "unexpected package tuple", http.StatusBadRequest)
			return
		}
		var ids []string
		switch request.Version {
		case "0.9.0":
		case "1.0.0", "1.5.0":
			ids = []string{"GO-RANGE-1"}
		case "2.0.0":
			ids = []string{"GO-LISTED-1"}
		default:
			http.Error(w, "unexpected version", http.StatusBadRequest)
			return
		}
		var vulns []json.RawMessage
		for _, id := range ids {
			vulns = append(vulns, json.RawMessage(fixtures[id+".json"]))
		}
		w.Header().Set("Content-Type", "application/json")
		var decoded []OSVVulnerability
		for _, raw := range vulns {
			var vuln OSVVulnerability
			if err := json.Unmarshal(raw, &vuln); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			decoded = append(decoded, vuln)
		}
		_ = json.NewEncoder(w).Encode(OSVResponse{Vulns: decoded})
	}))
	defer server.Close()

	dir := t.TempDir()
	oldBase := OfflineBaseURL
	OfflineBaseURL = server.URL
	t.Cleanup(func() { OfflineBaseURL = oldBase })
	if _, err := UpdateOffline(context.Background(), server.Client(), dir, []string{"go"}); err != nil {
		t.Fatal(err)
	}
	offline := NewOfflineSource(dir)
	online := NewOSVSource(server.Client())
	online.SetBaseURL(server.URL)
	for _, tc := range []struct {
		version string
		want    []string
	}{
		{"0.9.0", []string{}},
		{"1.0.0", []string{"GO-RANGE-1"}},
		{"1.5.0", []string{"GO-RANGE-1"}},
		{"2.0.0", []string{"GO-LISTED-1"}},
	} {
		t.Run(tc.version, func(t *testing.T) {
			live, err := online.Query(context.Background(), "go", "example.com/lib", tc.version)
			if err != nil {
				t.Fatalf("online query: %v", err)
			}
			cached, err := offline.Query(context.Background(), "go", "example.com/lib", tc.version)
			if err != nil {
				t.Fatalf("offline query: %v", err)
			}
			if got := vulnerabilityIDs(live); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("online IDs %v; want %v", got, tc.want)
			}
			if got := vulnerabilityIDs(cached); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("offline IDs %v; want %v", got, tc.want)
			}
			if !reflect.DeepEqual(parityProjection(live), parityProjection(cached)) {
				t.Fatalf("online/offline vulnerability projections differ:\nonline:  %#v\noffline: %#v", parityProjection(live), parityProjection(cached))
			}
		})
	}
}

func makeOSVArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func vulnerabilityIDs(vulns []Vulnerability) []string {
	ids := make([]string, 0, len(vulns))
	for _, vuln := range vulns {
		ids = append(ids, vuln.ID)
	}
	sort.Strings(ids)
	return ids
}

func parityProjection(vulns []Vulnerability) []Vulnerability {
	projected := make([]Vulnerability, 0, len(vulns))
	for _, vuln := range vulns {
		projected = append(projected, Vulnerability{
			ID: vuln.ID, CVE: vuln.CVE, Package: vuln.Package, Ecosystem: vuln.Ecosystem,
			Summary: vuln.Summary, Severity: vuln.Severity, Aliases: append([]string(nil), vuln.Aliases...),
			Affected: append([]Range(nil), vuln.Affected...), Fixed: append([]string(nil), vuln.Fixed...),
			References: append([]string(nil), vuln.References...), Source: vuln.Source,
		})
	}
	sort.Slice(projected, func(i, j int) bool { return projected[i].ID < projected[j].ID })
	return projected
}
