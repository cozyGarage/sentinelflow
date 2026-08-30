// Package vulndb provides vulnerability database integration
package vulndb

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Database is the main vulnerability database interface
type Database interface {
	// Query searches for vulnerabilities in a package
	Query(ctx context.Context, ecosystem, name, version string) ([]Vulnerability, error)

	// Update refreshes the vulnerability database
	Update(ctx context.Context) error

	// Close closes the database
	Close() error
}

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
	Source     string    `json:"source"`
}

// Range represents a version range affected by a vulnerability
type Range struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Client is the main vulnerability database client
type Client struct {
	sources []Source
	cache   Cache
	client  *http.Client
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

	// Initialize in-memory cache if not provided
	if client.cache == nil {
		client.cache = NewMemoryCache()
	}

	return client, nil
}

// Query searches for vulnerabilities across all sources
func (c *Client) Query(ctx context.Context, ecosystem, pkg, version string) ([]Vulnerability, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s:%s", ecosystem, pkg, version)
	if vulns, err := c.cache.Get(cacheKey); err == nil {
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
		if err != nil {
			sourceErrs = append(sourceErrs, fmt.Sprintf("%s: %v", source.Name(), err))
			continue
		}

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

// Update updates vulnerability data from all sources
func (c *Client) Update(ctx context.Context) error {
	// Clear cache
	if err := c.cache.Clear(); err != nil {
		return fmt.Errorf("failed to clear cache: %w", err)
	}

	return nil
}

// Close closes the database client
func (c *Client) Close() error {
	return nil
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
