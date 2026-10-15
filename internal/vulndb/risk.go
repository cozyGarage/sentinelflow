package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Feed URLs; variables so tests can point them at a local server.
var (
	KEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	EPSSURL = "https://api.first.org/data/v1/epss"
)

// Risk holds exploit-likelihood signals for a set of CVEs.
type Risk struct {
	EPSS map[string]float64 // CVE -> probability of exploitation in the next 30 days
	KEV  map[string]bool    // CVE -> listed in CISA Known Exploited Vulnerabilities
}

// FetchRisk looks up EPSS scores and KEV membership for cves.
// The KEV catalog is cached on disk for 24h; EPSS is queried in batches of 100.
func FetchRisk(ctx context.Context, client *http.Client, cves []string) (Risk, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	risk := Risk{EPSS: map[string]float64{}, KEV: map[string]bool{}}
	if len(cves) == 0 {
		return risk, nil
	}

	kev, err := kevCatalog(ctx, client)
	if err != nil {
		return risk, fmt.Errorf("CISA KEV: %w", err)
	}
	for _, c := range cves {
		if kev[c] {
			risk.KEV[c] = true
		}
	}

	// ponytail: EPSS is not cached; a scan makes ceil(len(cves)/100) requests. Cache if rate limits bite.
	for i := 0; i < len(cves); i += 100 {
		end := min(i+100, len(cves))
		var resp struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		u := EPSSURL + "?cve=" + url.QueryEscape(strings.Join(cves[i:end], ","))
		if err := getJSON(ctx, client, u, &resp); err != nil {
			return risk, fmt.Errorf("EPSS: %w", err)
		}
		for _, d := range resp.Data {
			if p, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				risk.EPSS[d.CVE] = p
			}
		}
	}
	return risk, nil
}

func kevCatalog(ctx context.Context, client *http.Client) (map[string]bool, error) {
	path := filepath.Join(DefaultCacheDir(), "kev.json")
	data, err := os.ReadFile(path)
	if info, statErr := os.Stat(path); err != nil || statErr != nil || time.Since(info.ModTime()) > 24*time.Hour {
		data, err = fetch(ctx, client, KEVURL)
		if err != nil {
			return nil, err
		}
		if os.MkdirAll(filepath.Dir(path), 0755) == nil {
			_ = os.WriteFile(path, data, 0644)
		}
	}
	var catalog struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		set[v.CVEID] = true
	}
	return set, nil
}

func getJSON(ctx context.Context, client *http.Client, u string, dest any) error {
	data, err := fetch(ctx, client, u)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

func fetch(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}
