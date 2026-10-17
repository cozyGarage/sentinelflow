// Package vulndb provides vulnerability database integration
package vulndb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
		if a.SnapshotID != b.SnapshotID {
			return a.SnapshotID < b.SnapshotID
		}
		return a.Status < b.Status
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
	cacheKey, err := c.cacheKey(ctx, ecosystem, pkg, version)
	if err != nil {
		for _, source := range c.sources {
			c.recordSource(source, ecosystem, "error")
		}
		return nil, fmt.Errorf("prepare vulnerability lookup: %w", err)
	}
	if vulns, err := c.cache.Get(cacheKey); err == nil {
		if err := c.checkSourceFreshness(ecosystem); err != nil {
			c.recordOfflineFreshnessFailure(ecosystem)
			return nil, err
		}
		c.recordDataSource(api.VulnerabilityDataSource{Source: "query-cache", Mode: "cache", Ecosystem: ecosystem, Supported: ecosystemSupported(ecosystem), Status: "hit"})
		return vulns, nil
	}

	var allVulns []Vulnerability
	seen := make(map[string]bool)
	var sourceErrs []string

	// Query all sources
	for _, source := range c.sources {
		vulns, err := source.Query(ctx, ecosystem, pkg, version)
		status := "available"
		if err != nil {
			status = "error"
			if len(vulns) > 0 {
				status = "partial"
			}
			sourceErrs = append(sourceErrs, fmt.Sprintf("%s: %v", source.Name(), err))
			c.recordSource(source, ecosystem, status)
		}
		if err == nil {
			c.recordSource(source, ecosystem, status)
		}

		// Deduplicate by ID
		for _, v := range vulns {
			if !seen[v.ID] {
				seen[v.ID] = true
				allVulns = append(allVulns, v)
			}
		}
	}

	// Any failed source leaves the answer incomplete. Keep safe positives but
	// surface the error and do not cache a partial or potentially empty answer.
	if len(sourceErrs) > 0 {
		return allVulns, fmt.Errorf("vulnerability lookup incomplete for %s/%s@%s: %s", ecosystem, pkg, version, strings.Join(sourceErrs, "; "))
	}

	// Cache successful results only (including empty = no known vulns)
	_ = c.cache.Set(cacheKey, allVulns, 24*time.Hour)

	return allVulns, nil
}

type cacheIdentitySource interface {
	CacheIdentity(context.Context, string) (string, error)
}

func (c *Client) cacheKey(ctx context.Context, ecosystem, pkg, version string) (string, error) {
	identities := make([]string, 0, len(c.sources))
	for _, source := range c.sources {
		identity := fmt.Sprintf("%T:%s", source, source.Name())
		if provider, ok := source.(cacheIdentitySource); ok {
			customIdentity, err := provider.CacheIdentity(ctx, ecosystem)
			if err != nil {
				return "", err
			}
			identity += ":" + customIdentity
		}
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	parts := append([]string{"sentinelflow-vulnerability-cache-v2"}, identities...)
	parts = append(parts, ecosystem, pkg, version)
	encoded, err := json.Marshal(parts)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "v2-" + hex.EncodeToString(sum[:]), nil
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
	keys := make([]string, len(qs))
	for i, q := range qs {
		key, err := c.cacheKey(ctx, q.Ecosystem, q.Name, q.Version)
		if err != nil {
			return out, fmt.Errorf("prepare vulnerability lookup for %s/%s@%s: %w", q.Ecosystem, q.Name, q.Version, err)
		}
		keys[i] = key
	}
	var miss []int
	for i, q := range qs {
		if vulns, err := c.cache.Get(keys[i]); err == nil {
			if err := c.checkSourceFreshness(q.Ecosystem); err != nil {
				c.recordOfflineFreshnessFailure(q.Ecosystem)
				return nil, err
			}
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
			out[i] = vulns
			if err != nil {
				return out, err
			}
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
			status := "error"
			if len(hits) > 0 {
				status = "partial"
			}
			c.recordSource(c.sources[0], qs[i].Ecosystem, status)
		}
		// QueryBatch only returns a prefix of complete, aligned chunks on error.
		if len(hits) <= len(miss) {
			details, detailErr := fetchVulns(ctx, bs, hits)
			out = attachBatchResults(out, miss, hits, details, qs, keys, c.cache, detailErr == nil)
			if detailErr != nil {
				err = errors.Join(err, detailErr)
			}
		}
		return out, fmt.Errorf("vulnerability batch lookup failed: %w", err)
	}
	if len(hits) != len(miss) {
		for _, i := range miss {
			c.recordSource(c.sources[0], qs[i].Ecosystem, "error")
		}
		return out, fmt.Errorf("vulnerability batch lookup returned %d results for %d queries", len(hits), len(miss))
	}

	// querybatch returns only IDs; fetch each distinct vulnerability once.
	details, err := fetchVulns(ctx, bs, hits)
	if err != nil {
		for _, i := range miss {
			c.recordSource(c.sources[0], qs[i].Ecosystem, "partial")
		}
		out = attachBatchResults(out, miss, hits, details, qs, keys, c.cache, false)
		return out, err
	}
	for _, i := range miss {
		c.recordSource(c.sources[0], qs[i].Ecosystem, "available")
	}
	out = attachBatchResults(out, miss, hits, details, qs, keys, c.cache, true)
	return out, nil
}

func attachBatchResults(out [][]Vulnerability, miss []int, hits [][]OSVVulnerability, details map[string]OSVVulnerability, qs []PackageQuery, keys []string, cache Cache, cacheComplete bool) [][]Vulnerability {
	for j, i := range miss {
		if j >= len(hits) {
			break
		}
		q := qs[i]
		vulns := make([]Vulnerability, 0, len(hits[j]))
		complete := true
		for _, h := range hits[j] {
			v, ok := details[h.ID]
			if !ok {
				complete = false
				continue
			}
			vulns = append(vulns, v.toVulnerability(q.Name, q.Ecosystem))
		}
		out[i] = vulns
		if cacheComplete && complete {
			_ = cache.Set(keys[i], vulns, 24*time.Hour)
		}
	}
	return out
}

func (c *Client) checkSourceFreshness(ecosystem string) error {
	for _, source := range c.sources {
		if checker, ok := source.(interface{ CheckFreshness(string) error }); ok {
			return checker.CheckFreshness(ecosystem)
		}
	}
	return nil
}

func (c *Client) recordOfflineFreshnessFailure(ecosystem string) {
	for _, source := range c.sources {
		if _, ok := source.(interface{ CheckFreshness(string) error }); ok {
			c.recordSource(source, ecosystem, "error")
			return
		}
	}
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
				delete(details, id)
				return
			}
			if v == nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("fetch %s: OSV returned an empty vulnerability", id)
				}
				return
			}
			if v.ID != id {
				if firstErr == nil {
					firstErr = fmt.Errorf("fetch %s: OSV returned mismatched vulnerability %s", id, v.ID)
				}
				delete(details, id)
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
func OfflineOptions(offline bool, requiredMaxAge ...time.Duration) []Option {
	if !offline {
		return nil
	}
	// Memory cache: online results in the disk cache must not mix with the offline DB.
	source := NewOfflineSource("")
	if len(requiredMaxAge) > 0 && requiredMaxAge[0] > 0 {
		source.maxAge = requiredMaxAge[0]
	}
	return []Option{WithSources(source), WithCache(NewMemoryCache())}
}
