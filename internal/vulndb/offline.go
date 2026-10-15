package vulndb

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// OfflineBaseURL serves OSV's per-ecosystem exports (<base>/<Ecosystem>/all.zip).
var OfflineBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// OfflineEcosystems are the ecosystems SentinelFlow can scan, by our names.
var OfflineEcosystems = []string{"go", "npm", "pip", "maven", "cargo", "rubygems", "composer", "nuget"}

// OfflineDir is where `sentinelflow db update` stores the indexes.
func OfflineDir() string { return filepath.Join(DefaultCacheDir(), "offline") }

// offlineIndex maps a package name to the advisories affecting it, each
// trimmed to that package's affected entries. Values stay raw JSON so a scan
// decodes only the packages it asks about (npm alone has ~230k advisories).
type offlineIndex struct {
	Updated  time.Time                  `json:"updated"`
	Packages map[string]json.RawMessage `json:"packages"`
}

// UpdateOffline downloads the OSV export for each ecosystem and writes
// <dir>/<ecosystem>.json.gz. It returns the number of advisories per ecosystem.
func UpdateOffline(ctx context.Context, client *http.Client, dir string, ecosystems []string) (map[string]int, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Minute}
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, eco := range ecosystems {
		n, err := updateEcosystem(ctx, client, dir, eco)
		if err != nil {
			return counts, fmt.Errorf("%s: %w", eco, err)
		}
		counts[eco] = n
	}
	return counts, nil
}

func updateEcosystem(ctx context.Context, client *http.Client, dir, eco string) (int, error) {
	tmp, err := os.CreateTemp(dir, eco+"-*.zip")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, OfflineBaseURL+"/"+mapEcosystem(eco)+"/all.zip", nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download returned status %d", resp.StatusCode)
	}
	size, err := io.Copy(tmp, resp.Body)
	if err != nil {
		return 0, err
	}

	zr, err := zip.NewReader(tmp, size)
	if err != nil {
		return 0, err
	}
	byPkg := map[string][]OSVVulnerability{}
	osvEco := mapEcosystem(eco)
	count := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return 0, err
		}
		var v OSVVulnerability
		err = json.NewDecoder(rc).Decode(&v)
		rc.Close()
		if err != nil {
			return 0, fmt.Errorf("%s: %w", f.Name, err)
		}
		if v.Withdrawn != "" {
			continue
		}
		count++
		affected := v.Affected
		for _, a := range affected {
			if a.Package.Ecosystem != osvEco {
				continue
			}
			entry := v
			entry.Details = ""                    // summaries are enough for reports; keeps the index small
			entry.Affected = entry.Affected[:0:0] // only this package's entry
			entry.Affected = append(entry.Affected, a)
			byPkg[a.Package.Name] = append(byPkg[a.Package.Name], entry)
		}
	}

	idx := offlineIndex{Updated: time.Now().UTC(), Packages: make(map[string]json.RawMessage, len(byPkg))}
	for name, vulns := range byPkg {
		raw, err := json.Marshal(vulns)
		if err != nil {
			return 0, err
		}
		idx.Packages[name] = raw
	}

	out := filepath.Join(dir, eco+".json.gz")
	part := out + ".part"
	w, err := os.Create(part)
	if err != nil {
		return 0, err
	}
	gz := gzip.NewWriter(w)
	if err := json.NewEncoder(gz).Encode(idx); err != nil {
		w.Close()
		return 0, err
	}
	if err := gz.Close(); err != nil {
		w.Close()
		return 0, err
	}
	if err := w.Close(); err != nil {
		return 0, err
	}
	return count, os.Rename(part, out) // atomic: a failed update keeps the old index
}

// OfflineStatus reports when each ecosystem index was last updated (zero time = missing).
func OfflineStatus(dir string) map[string]time.Time {
	out := map[string]time.Time{}
	for _, eco := range OfflineEcosystems {
		if info, err := os.Stat(filepath.Join(dir, eco+".json.gz")); err == nil {
			out[eco] = info.ModTime()
		} else {
			out[eco] = time.Time{}
		}
	}
	return out
}

// OfflineSource answers queries from indexes built by UpdateOffline. It loads
// an ecosystem's index on first use.
// ponytail: the raw index for each used ecosystem stays in memory (npm is
// ~120 MB raw); switch to an on-disk keyed store if memory becomes a problem.
type OfflineSource struct {
	dir   string
	mu    sync.Mutex
	index map[string]map[string]json.RawMessage
}

// NewOfflineSource reads indexes from dir (OfflineDir() when empty).
func NewOfflineSource(dir string) *OfflineSource {
	if dir == "" {
		dir = OfflineDir()
	}
	return &OfflineSource{dir: dir, index: map[string]map[string]json.RawMessage{}}
}

func (s *OfflineSource) Name() string { return "osv-offline" }

func (s *OfflineSource) load(eco string) (map[string]json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx, ok := s.index[eco]; ok {
		return idx, nil
	}
	f, err := os.Open(filepath.Join(s.dir, eco+".json.gz"))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no offline database for %s; run `sentinelflow db update`", eco)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var idx offlineIndex
	if err := json.NewDecoder(gz).Decode(&idx); err != nil {
		return nil, fmt.Errorf("offline database for %s is corrupt: %w", eco, err)
	}
	s.index[eco] = idx.Packages
	return idx.Packages, nil
}

// Query returns advisories whose affected ranges or version lists include version.
func (s *OfflineSource) Query(ctx context.Context, ecosystem, pkg, version string) ([]Vulnerability, error) {
	idx, err := s.load(ecosystem)
	if err != nil {
		return nil, err
	}
	raw, ok := idx[pkg]
	if !ok {
		return nil, nil
	}
	var entries []OSVVulnerability
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("offline database entry for %s/%s: %w", ecosystem, pkg, err)
	}
	var out []Vulnerability
	for _, v := range entries {
		if versionAffected(v, version) {
			out = append(out, v.toVulnerability(pkg, ecosystem))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func versionAffected(v OSVVulnerability, version string) bool {
	for _, a := range v.Affected {
		for _, listed := range a.Versions {
			if strings.TrimPrefix(listed, "v") == strings.TrimPrefix(version, "v") {
				return true
			}
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue
			}
			events := make([]rangeEvent, 0, len(r.Events))
			for _, e := range r.Events {
				events = append(events, rangeEvent{Introduced: e.Introduced, Fixed: e.Fixed, LastAffected: e.LastAffected})
			}
			if affects(r.Type, events, version) {
				return true
			}
		}
	}
	return false
}
