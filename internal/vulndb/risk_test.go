package vulndb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchRisk(t *testing.T) {
	t.Setenv("SENTINELFLOW_CACHE_DIR", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev":
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-1"}]}`))
		case "/epss":
			if r.URL.Query().Get("cve") != "CVE-1,CVE-2" {
				t.Errorf("cve query %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-1","epss":"0.94"},{"cve":"CVE-2","epss":"0.01"}]}`))
		}
	}))
	defer srv.Close()
	oldKEV, oldEPSS := KEVURL, EPSSURL
	KEVURL, EPSSURL = srv.URL+"/kev", srv.URL+"/epss"
	defer func() { KEVURL, EPSSURL = oldKEV, oldEPSS }()

	risk, err := FetchRisk(context.Background(), srv.Client(), []string{"CVE-1", "CVE-2"})
	if err != nil {
		t.Fatal(err)
	}
	if !risk.KEV["CVE-1"] || risk.KEV["CVE-2"] || risk.EPSS["CVE-1"] != 0.94 || risk.EPSS["CVE-2"] != 0.01 {
		t.Fatalf("%+v", risk)
	}
}
