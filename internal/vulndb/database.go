// Package vulndb provides vulnerability database integration
package vulndb

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID         string    `json:"id"`
	CVE        string    `json:"cve,omitempty"`
	Package    string    `json:"package"`
	Ecosystem  string    `json:"ecosystem"`
	Summary    string    `json:"summary"`
	Details    string    `json:"details"`
	Severity   string    `json:"severity"`
	CVSS       float64   `json:"cvss"`
	CVSSVector string    `json:"cvss_vector,omitempty"`
	Published  time.Time `json:"published"`
	Modified   time.Time `json:"modified"`
	Affected   []Range   `json:"affected"`
	Fixed      []string  `json:"fixed"`
	References []string  `json:"references"`
	Aliases    []string  `json:"aliases,omitempty"`
	Source     string    `json:"source"`
}

// Range represents a version range affected by a vulnerability
type Range struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Client is the main vulnerability database client
type Client struct {
	sources      []Source
	cache        Cache
	client       *http.Client
	provenanceMu sync.Mutex
	provenance   map[string]api.VulnerabilityDataSource
}

// Source represents a vulnerability data source
type Source interface {
	Name() string
	Query(ctx context.Context, ecosystem, pkg, version string) ([]Vulnerability, error)
}

// Cache interface for local caching
type Cache interface {
	Get(key string) ([]Vulnerability, error)
	Set(key string, vulns []Vulnerability, ttl time.Duration) error
	Clear() error
}

// NewClient creates a new vulnerability database client
func NewClient(opts ...Option) (*Client, error) {
	client := &Client{
		sources: []Source{},
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	// Initialize default sources if none provided
	if len(client.sources) == 0 {
		client.sources = append(client.sources, NewOSVSource(client.client))
	}

	// Initialize cache: prefer disk, fall back to memory.
	if client.cache == nil {
		if dc, err := NewDiskCache(""); err == nil {
			client.cache = dc
		} else {
			client.cache = NewMemoryCache()
		}
	}
	client.provenance = make(map[string]api.VulnerabilityDataSource)

	return client, nil
}

// VulnerabilityData returns a stable snapshot of data-source evidence observed
// by this client, including cache hits and offline database snapshots.
func (c *Client) VulnerabilityData() []api.VulnerabilityDataSource {
	c.provenanceMu.Lock()
	defer c.provenanceMu.Unlock()
	out := make([]api.VulnerabilityDataSource, 0, len(c.provenance))
	for _, source := range c.provenance {
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Mode != b.Mode {
			return a.Mode < b.Mode
		}
		return a.SnapshotID < b.SnapshotID
	})
	return out
}

func (c *Client) recordDataSource(entry api.VulnerabilityDataSource) {
	key := entry.Source + "\x00" + entry.Mode + "\x00" + entry.Ecosystem + "\x00" + entry.SnapshotID + "\x00" + entry.Status
	c.provenanceMu.Lock()
	c.provenance[key] = entry
	c.provenanceMu.Unlock()
}

func (c *Client) recordSource(source Source, ecosystem, status string) {
	entry := api.VulnerabilityDataSource{Source: source.Name(), Mode: "online", Ecosystem: ecosystem, Supported: ecosystemSupported(ecosystem), Status: status}
	if provider, ok := source.(interface {
		ProvenanceFor(string, string) api.VulnerabilityDataSource
	}); ok {
		entry = provider.ProvenanceFor(ecosystem, status)
	}
	c.recordDataSource(entry)
}

func ecosystemSupported(ecosystem string) bool {
	for _, supported := range OfflineEcosystems {
		if ecosystem == supported {
			return true
		}
	}
	return false
}

// Query searches for vulnerabilities across all sources
func (c *Client) Query(ctx context.Context, ecosystem, pkg, version string) ([]Vulnerability, error) {
	// Check cache first
	cacheKey := cacheKey(ecosystem, pkg, version)
	if vulns, err := c.cache.Get(cacheKey); err == nil {
		c.recordDataSource(api.VulnerabilityDataSource{Source: "query-cache", Mode: "cache", Ecosystem: ecosystem, Supported: ecosystemSupported(ecosystem), Status: "hit"})
		return vulns, nil
	}

	var allVulns []Vulnerability
	seen := make(map[string]bool)
	var sourceErrs []string
	queried := 0

	// Query all sources
	for _, source := range c.sources {
		queried++
		vulns, err := source.Query(ctx, ecosystem, pkg, version)
		status := "available"
		if err != nil {
			status = "error"
			if len(vulns) > 0 {
				status = "partial"
			}
			sourceErrs = append(sourceErrs, fmt.Sprintf("%s: %v", source.Name(), err))
			c.recordSource(source, ecosystem, status)
			continue
		}
		c.recordSource(source, ecosystem, status)

		// Deduplicate by ID
		for _, v := range vulns {
			if !seen[v.ID] {
				seen[v.ID] = true
				allVulns = append(allVulns, v)
			}
		}
	}

	// If every source failed, surface the error and do not cache emptiness
	if queried > 0 && len(sourceErrs) == queried && len(allVulns) == 0 {
		return nil, fmt.Errorf("vulnerability lookup failed for %s/%s@%s: %s", ecosystem, pkg, version, strings.Join(sourceErrs, "; "))
	}

	// Cache successful results only (including empty = no known vulns)
	_ = c.cache.Set(cacheKey, allVulns, 24*time.Hour)

	return allVulns, nil
}

func cacheKey(ecosystem, pkg, version string) string {
	return fmt.Sprintf("%s:%s:%s", ecosystem, pkg, version)
}

// PackageQuery identifies one package version to look up.
type PackageQuery struct {
	Ecosystem string
	Name      string
	Version   string
}

// batchSource is a source that supports OSV-style batch lookups.
type batchSource interface {
	QueryBatch(ctx context.Context, queries []OSVRequest) ([][]OSVVulnerability, error)
	GetVuln(ctx context.Context, id string) (*OSVVulnerability, error)
}

// QueryMany looks up many packages; results are aligned with qs. Cache misses
// go through one batched lookup when the only source supports batching.
func (c *Client) QueryMany(ctx context.Context, qs []PackageQuery) ([][]Vulnerability, error) {
	out := make([][]Vulnerability, len(qs))
	var miss []int
	for i, q := range qs {
		if vulns, err := c.cache.Get(cacheKey(q.Ecosystem, q.Name, q.Version)); err == nil {
			out[i] = vulns
			c.recordDataSource(api.VulnerabilityDataSource{Source: "query-cache", Mode: "cache", Ecosystem: q.Ecosystem, Supported: ecosystemSupported(q.Ecosystem), Status: "hit"})
		} else {
			miss = append(miss, i)
		}
	}
	if len(miss) == 0 {
		return out, nil
	}

	bs, ok := c.sources[0].(batchSource)
	if len(c.sources) != 1 || !ok {
		for _, i := range miss {
			vulns, err := c.Query(ctx, qs[i].Ecosystem, qs[i].Name, qs[i].Version)
			if err != nil {
				return nil, err
			}
			out[i] = vulns
		}
		return out, nil
	}

	reqs := make([]OSVRequest, len(miss))
	for j, i := range miss {
		reqs[j].Package.Name = qs[i].Name
		reqs[j].Package.Ecosystem = mapEcosystem(qs[i].Ecosystem)
		reqs[j].Version = qs[i].Version
	}
	hits, err := bs.QueryBatch(ctx, reqs)
	if err != nil {
		for _, i := range miss {
			c.recordSource(c.sources[0], qs[i].Ecosystem, "error")
		}
		return nil, fmt.Errorf("vulnerability batch lookup failed: %w", err)
	}
	if len(hits) != len(miss) {
		for _, i := range miss {
			c.recordSource(c.sources[0], qs[i].Ecosystem, "error")
		}
		return nil, fmt.Errorf("vulnerability batch lookup returned %d results for %d queries", len(hits), len(miss))
	}

	// querybatch returns only IDs; fetch each distinct vulnerability once.
	details, err := fetchVulns(ctx, bs, hits)
	if err != nil {
		for _, i := range miss {
			c.recordSource(c.sources[0], qs[i].Ecosystem, "partial")
		}
		return nil, err
	}
	for _, i := range miss {
		c.recordSource(c.sources[0], qs[i].Ecosystem, "available")
	}
	for j, i := range miss {
		q := qs[i]
		vulns := []Vulnerability{}
		for _, h := range hits[j] {
			vulns = append(vulns, details[h.ID].toVulnerability(q.Name, q.Ecosystem))
		}
		out[i] = vulns
		_ = c.cache.Set(cacheKey(q.Ecosystem, q.Name, q.Version), vulns, 24*time.Hour)
	}
	return out, nil
}

func fetchVulns(ctx context.Context, bs batchSource, hits [][]OSVVulnerability) (map[string]OSVVulnerability, error) {
	var ids []string
	details := map[string]OSVVulnerability{}
	for _, hs := range hits {
		for _, h := range hs {
			if _, ok := details[h.ID]; !ok {
				details[h.ID] = h
				ids = append(ids, h.ID)
			}
		}
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		firstErr error
		sem      = make(chan struct{}, 8)
	)
	for _, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			v, err := bs.GetVuln(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("fetch %s: %w", id, err)
				}
				return
			}
			details[id] = *v
		}(id)
	}
	wg.Wait()
	return details, firstErr
}

// Option is a functional option for Client
type Option func(*Client)

// WithSources sets custom vulnerability sources
func WithSources(sources ...Source) Option {
	return func(c *Client) {
		c.sources = sources
	}
}

// WithCache sets a custom cache implementation
func WithCache(cache Cache) Option {
	return func(c *Client) {
		c.cache = cache
	}
}

// OfflineOptions makes a client answer from the local OSV database
// (`sentinelflow db update`) with no network access when offline is true.
func OfflineOptions(offline bool) []Option {
	if !offline {
		return nil
	}
	// Memory cache: online results in the disk cache must not mix with the offline DB.
	return []Option{WithSources(NewOfflineSource("")), WithCache(NewMemoryCache())}
}
