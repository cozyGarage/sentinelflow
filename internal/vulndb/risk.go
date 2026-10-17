package vulndb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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

// RiskLookupError separates KEV and EPSS completeness so a KEV policy does not
// fail merely because optional EPSS enrichment is unavailable.
type RiskLookupError struct {
	KEV  error
	EPSS error
}

func (e *RiskLookupError) Error() string {
	var parts []error
	if e.KEV != nil {
		parts = append(parts, fmt.Errorf("CISA KEV: %w", e.KEV))
	}
	if e.EPSS != nil {
		parts = append(parts, fmt.Errorf("EPSS: %w", e.EPSS))
	}
	if len(parts) == 0 {
		return "risk lookup incomplete"
	}
	return errors.Join(parts...).Error()
}

func (e *RiskLookupError) Unwrap() []error {
	var errs []error
	if e.KEV != nil {
		errs = append(errs, e.KEV)
	}
	if e.EPSS != nil {
		errs = append(errs, e.EPSS)
	}
	return errs
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

	var lookupErr RiskLookupError
	kev, kevErr := kevCatalog(ctx, client)
	if kevErr != nil {
		lookupErr.KEV = kevErr
	} else {
		for _, c := range cves {
			if kev[c] {
				risk.KEV[c] = true
			}
		}
	}

	// ponytail: EPSS is not cached; a scan makes ceil(len(cves)/100) requests. Cache if rate limits bite.
	seenEPSS := map[string]bool{}
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
			lookupErr.EPSS = errors.Join(lookupErr.EPSS, err)
			continue
		}
		for _, d := range resp.Data {
			p, err := strconv.ParseFloat(d.EPSS, 64)
			if err != nil || math.IsNaN(p) || math.IsInf(p, 0) || p < 0 || p > 1 {
				if err == nil {
					err = fmt.Errorf("score %q is outside [0,1]", d.EPSS)
				}
				lookupErr.EPSS = errors.Join(lookupErr.EPSS, fmt.Errorf("%s: invalid score: %w", d.CVE, err))
				continue
			}
			risk.EPSS[d.CVE] = p
			seenEPSS[d.CVE] = true
		}
	}
	var missing []string
	for _, cve := range cves {
		if !seenEPSS[cve] {
			missing = append(missing, cve)
		}
	}
	if len(missing) > 0 {
		lookupErr.EPSS = errors.Join(lookupErr.EPSS, fmt.Errorf("response omitted requested CVEs: %s", strings.Join(missing, ", ")))
	}
	if lookupErr.KEV != nil || lookupErr.EPSS != nil {
		return risk, &lookupErr
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
