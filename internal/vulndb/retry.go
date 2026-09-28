package vulndb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

func (s *OSVSource) doJSON(ctx context.Context, method, url string, body []byte, dest any) error {
	var last error
	backoff := 200 * time.Millisecond
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rdr)
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := s.client.Do(req)
		if err != nil {
			last = err
			sleepBackoff(ctx, backoff, attempt)
			backoff *= 2
			continue
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			last = readErr
			sleepBackoff(ctx, backoff, attempt)
			backoff *= 2
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			last = fmt.Errorf("OSV API returned status %d", resp.StatusCode)
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil {
					sleepBackoff(ctx, time.Duration(secs)*time.Second, 0)
					continue
				}
			}
			sleepBackoff(ctx, backoff, attempt)
			backoff *= 2
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("OSV API returned status %d", resp.StatusCode)
		}
		if dest == nil {
			return nil
		}
		if err := json.Unmarshal(data, dest); err != nil {
			return err
		}
		return nil
	}
	if last == nil {
		last = fmt.Errorf("OSV request failed")
	}
	return last
}

func sleepBackoff(ctx context.Context, base time.Duration, attempt int) {
	jitter := time.Duration(rand.Intn(150)) * time.Millisecond
	t := time.NewTimer(base + jitter)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// QueryBatch looks up many packages. Results are aligned with queries.
func (s *OSVSource) QueryBatch(ctx context.Context, queries []OSVRequest) ([][]OSVVulnerability, error) {
	if len(queries) == 0 {
		return nil, nil
	}
	const chunk = 100
	var all [][]OSVVulnerability
	for i := 0; i < len(queries); i += chunk {
		end := i + chunk
		if end > len(queries) {
			end = len(queries)
		}
		part := queries[i:end]
		payload, err := json.Marshal(map[string]any{"queries": part})
		if err != nil {
			return nil, err
		}
		var resp struct {
			Results []OSVResponse `json:"results"`
		}
		if err := s.doJSON(ctx, http.MethodPost, s.baseURL+"/v1/querybatch", payload, &resp); err != nil {
			return nil, err
		}
		for _, r := range resp.Results {
			all = append(all, r.Vulns)
		}
	}
	return all, nil
}

// GetVuln fetches a vulnerability by ID.
func (s *OSVSource) GetVuln(ctx context.Context, id string) (*OSVVulnerability, error) {
	var v OSVVulnerability
	if err := s.doJSON(ctx, http.MethodGet, s.baseURL+"/v1/vulns/"+id, nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
