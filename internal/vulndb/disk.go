package vulndb

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultCacheDir is the on-disk OSV cache location.
func DefaultCacheDir() string {
	if d := os.Getenv("SENTINELFLOW_CACHE_DIR"); d != "" {
		return d
	}
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return filepath.Join(os.TempDir(), "sentinelflow", "vulndb")
	}
	return filepath.Join(base, "sentinelflow", "vulndb")
}

type diskCache struct {
	dir string
}

// NewDiskCache stores vulnerability query results as JSON files.
func NewDiskCache(dir string) (Cache, error) {
	if dir == "" {
		dir = DefaultCacheDir()
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return &diskCache{dir: dir}, nil
}

func (c *diskCache) pathFor(key string) string {
	safe := strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '@':
			return '_'
		default:
			return r
		}
	}, key)
	return filepath.Join(c.dir, safe+".json")
}

type diskEntry struct {
	Expires time.Time       `json:"expires"`
	Vulns   []Vulnerability `json:"vulns"`
}

func (c *diskCache) Get(key string) ([]Vulnerability, error) {
	data, err := os.ReadFile(c.pathFor(key))
	if err != nil {
		return nil, err
	}
	var e diskEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	if time.Now().After(e.Expires) {
		return nil, fmt.Errorf("cache miss")
	}
	out := make([]Vulnerability, len(e.Vulns))
	copy(out, e.Vulns)
	return out, nil
}

func (c *diskCache) Set(key string, vulns []Vulnerability, ttl time.Duration) error {
	e := diskEntry{Expires: time.Now().Add(ttl), Vulns: vulns}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return os.WriteFile(c.pathFor(key), data, 0644)
}

func (c *diskCache) Clear() error {
	return os.RemoveAll(c.dir)
}
