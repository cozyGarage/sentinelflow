package vulndb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// OSVSource implements the OSV (Open Source Vulnerabilities) API
// https://osv.dev/
type OSVSource struct {
	baseURL string
	client  *http.Client
}

// NewOSVSource creates a new OSV source
func NewOSVSource(client *http.Client) *OSVSource {
	if client == nil {
		client = http.DefaultClient
	}

	return &OSVSource{
		baseURL: "https://api.osv.dev",
		client:  client,
	}
}

func (s *OSVSource) Name() string {
	return "osv"
}

// SetBaseURL overrides the OSV API base URL (for tests).
func (s *OSVSource) SetBaseURL(url string) {
	s.baseURL = url
}

// OSVRequest is the request format for OSV API
type OSVRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version,omitempty"`
}

// OSVResponse is the response format from OSV API
type OSVResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// OSVVulnerability represents an OSV vulnerability entry
type OSVVulnerability struct {
	ID        string `json:"id"`
	Summary   string `json:"summary"`
	Details   string `json:"details"`
	Published string `json:"published"`
	Modified  string `json:"modified"`
	Affected  []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions,omitempty"`
	} `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity,omitempty"`
	DatabaseSpecific struct {
		Severity string `json:"severity,omitempty"`
	} `json:"database_specific,omitempty"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
}

// Query queries the OSV API for vulnerabilities
func (s *OSVSource) Query(ctx context.Context, ecosystem, pkg, version string) ([]Vulnerability, error) {
	// Map ecosystem names to OSV format
	osvEcosystem := mapEcosystem(ecosystem)

	// Build request
	req := OSVRequest{}
	req.Package.Name = pkg
	req.Package.Ecosystem = osvEcosystem
	req.Version = version

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	apiURL := s.baseURL + "/v1/query"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert OSV vulnerabilities to our format
	var vulns []Vulnerability
	for _, osv := range osvResp.Vulns {
		v := Vulnerability{
			ID:        osv.ID,
			Package:   pkg,
			Ecosystem: ecosystem,
			Summary:   osv.Summary,
			Details:   osv.Details,
			Source:    "osv",
		}

		// Extract CVE from aliases
		for _, alias := range osv.Aliases {
			if len(alias) > 3 && alias[:3] == "CVE" {
				v.CVE = alias
				break
			}
		}

		// Extract CVSS score from vector or numeric score field
		for _, sev := range osv.Severity {
			if sev.Type == "CVSS_V3" || sev.Type == "CVSS_V4" {
				v.CVSSVector = sev.Score
				if score, err := strconv.ParseFloat(sev.Score, 64); err == nil {
					v.CVSS = score
					v.Severity = cvssToSeverity(score)
				} else if score := parseCVSSBaseScore(sev.Score); score > 0 {
					v.CVSS = score
					v.Severity = cvssToSeverity(score)
				}
				// If vector could not be scored, leave Severity empty for
				// database_specific / default fallback below.
				break
			}
		}
		if v.Severity == "" {
			if sev := normalizeOSVSeverity(osv.DatabaseSpecific.Severity); sev != "" {
				v.Severity = sev
			} else {
				v.Severity = "medium"
			}
		}

		// Extract references
		for _, ref := range osv.References {
			v.References = append(v.References, ref.URL)
		}

		// Extract affected ranges
		for _, affected := range osv.Affected {
			for _, r := range affected.Ranges {
				for _, event := range r.Events {
					if event.Introduced != "" || event.Fixed != "" {
						v.Affected = append(v.Affected, Range{
							Introduced: event.Introduced,
							Fixed:      event.Fixed,
						})
					}
				}
			}
		}

		vulns = append(vulns, v)
	}

	return vulns, nil
}

// mapEcosystem maps our ecosystem names to OSV ecosystem names
func mapEcosystem(ecosystem string) string {
	mapping := map[string]string{
		"npm":      "npm",
		"go":       "Go",
		"pip":      "PyPI",
		"maven":    "Maven",
		"cargo":    "crates.io",
		"rubygems": "RubyGems",
	}

	if mapped, ok := mapping[ecosystem]; ok {
		return mapped
	}
	return ecosystem
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

func parseCVSSBaseScore(vector string) float64 {
	// CVSS vector format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
	// Approximate base score from impact metrics when a full calculator is unavailable.
	if !strings.HasPrefix(vector, "CVSS:") {
		return 0
	}
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		metrics[kv[0]] = kv[1]
	}
	rank := func(v string) int {
		switch strings.ToUpper(v) {
		case "H":
			return 2
		case "L":
			return 1
		default:
			return 0
		}
	}
	c, i, a := rank(metrics["C"]), rank(metrics["I"]), rank(metrics["A"])
	sum := c + i + a
	hasHigh := c == 2 || i == 2 || a == 2
	switch {
	case sum >= 6:
		return 9.8
	case sum >= 4 && hasHigh:
		return 8.1
	case hasHigh:
		return 7.5
	case sum >= 2:
		return 5.3
	case sum >= 1:
		return 3.1
	default:
		return 0
	}
}

func normalizeOSVSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	default:
		return ""
	}
}
