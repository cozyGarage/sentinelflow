package vulndb

import (
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cozygarage/sentinelflow/pkg/api"
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
	SchemaVersion int                        `json:"schema_version,omitempty"`
	Source        string                     `json:"source,omitempty"`
	Ecosystem     string                     `json:"ecosystem,omitempty"`
	SnapshotID    string                     `json:"snapshot_id,omitempty"`
	AcquiredAt    time.Time                  `json:"acquired_at,omitempty"`
	Updated       time.Time                  `json:"updated,omitempty"` // legacy alias for AcquiredAt
	Packages      map[string]json.RawMessage `json:"packages"`
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
	snapshotHash := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, snapshotHash), resp.Body)
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

	acquiredAt := time.Now().UTC()
	idx := offlineIndex{
		SchemaVersion: 1, Source: safeSourceURL(req.URL.String()), Ecosystem: eco,
		SnapshotID: "sha256:" + hex.EncodeToString(snapshotHash.Sum(nil)),
		AcquiredAt: acquiredAt, Updated: acquiredAt,
		Packages: make(map[string]json.RawMessage, len(byPkg)),
	}
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

func safeSourceURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// OfflineStatus reports snapshot acquisition times from index metadata, never
// filesystem modification times (zero time means missing, corrupt, or unknown).
func OfflineStatus(dir string) map[string]time.Time {
	out := map[string]time.Time{}
	for _, eco := range OfflineEcosystems {
		idx, err := readOfflineIndex(filepath.Join(dir, eco+".json.gz"))
		out[eco] = time.Time{}
		if err == nil {
			out[eco] = indexAcquiredAt(idx)
		}
	}
	return out
}

// OfflineSnapshots reports index source, digest, acquisition time and
// availability for every supported ecosystem. It never infers freshness from
// the index file's modification time.
func OfflineSnapshots(dir string) []api.VulnerabilityDataSource {
	out := make([]api.VulnerabilityDataSource, 0, len(OfflineEcosystems))
	for _, eco := range OfflineEcosystems {
		idx, err := readOfflineIndex(filepath.Join(dir, eco+".json.gz"))
		entry := api.VulnerabilityDataSource{
			Source: safeSourceURL(OfflineBaseURL + "/" + mapEcosystem(eco) + "/all.zip"),
			Mode:   "offline", Ecosystem: eco, Supported: true,
		}
		if os.IsNotExist(err) {
			entry.Status = "missing"
		} else if err != nil {
			entry.Status = "corrupt"
		} else {
			entry.Status = "available"
			entry.SnapshotID = idx.SnapshotID
			if idx.Source != "" {
				entry.Source = safeSourceURL(idx.Source)
			}
			at := indexAcquiredAt(idx)
			if !at.IsZero() {
				entry.AcquiredAt = &at
			}
		}
		out = append(out, entry)
	}
	return out
}

func readOfflineIndex(path string) (offlineIndex, error) {
	f, err := os.Open(path)
	if err != nil {
		return offlineIndex{}, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return offlineIndex{}, err
	}
	defer gz.Close()
	var idx offlineIndex
	err = json.NewDecoder(gz).Decode(&idx)
	return idx, err
}

func indexAcquiredAt(idx offlineIndex) time.Time {
	if !idx.AcquiredAt.IsZero() {
		return idx.AcquiredAt.UTC()
	}
	return idx.Updated.UTC()
}

// OfflineSource answers queries from indexes built by UpdateOffline. It loads
// an ecosystem's index on first use.
// ponytail: the raw index for each used ecosystem stays in memory (npm is
// ~120 MB raw); switch to an on-disk keyed store if memory becomes a problem.
type OfflineSource struct {
	dir       string
	mu        sync.Mutex
	index     map[string]map[string]json.RawMessage
	snapshots map[string]api.VulnerabilityDataSource
	maxAge    time.Duration
	now       func() time.Time
}

// NewOfflineSource reads indexes from dir (OfflineDir() when empty).
func NewOfflineSource(dir string) *OfflineSource {
	if dir == "" {
		dir = OfflineDir()
	}
	return &OfflineSource{dir: dir, index: map[string]map[string]json.RawMessage{}, snapshots: map[string]api.VulnerabilityDataSource{}, now: time.Now}
}

func (s *OfflineSource) Name() string { return "osv-offline" }

func (s *OfflineSource) load(eco string) (map[string]json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx, ok := s.index[eco]; ok {
		if err := s.validateFreshness(eco); err != nil {
			return nil, err
		}
		return idx, nil
	}
	path := filepath.Join(s.dir, eco+".json.gz")
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		s.snapshots[eco] = api.VulnerabilityDataSource{Source: safeSourceURL(OfflineBaseURL + "/" + mapEcosystem(eco) + "/all.zip"), Mode: "offline", Ecosystem: eco, Supported: ecosystemSupported(eco), Status: "missing"}
		return nil, fmt.Errorf("no offline database for %s; run `sentinelflow db update`", eco)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		s.snapshots[eco] = api.VulnerabilityDataSource{Source: safeSourceURL(OfflineBaseURL + "/" + mapEcosystem(eco) + "/all.zip"), Mode: "offline", Ecosystem: eco, Supported: ecosystemSupported(eco), Status: "corrupt"}
		return nil, fmt.Errorf("offline database for %s is corrupt: %w", eco, err)
	}
	var idx offlineIndex
	if err := json.NewDecoder(gz).Decode(&idx); err != nil {
		s.snapshots[eco] = api.VulnerabilityDataSource{Source: safeSourceURL(OfflineBaseURL + "/" + mapEcosystem(eco) + "/all.zip"), Mode: "offline", Ecosystem: eco, Supported: ecosystemSupported(eco), Status: "corrupt"}
		return nil, fmt.Errorf("offline database for %s is corrupt: %w", eco, err)
	}
	s.index[eco] = idx.Packages
	acquiredAt := indexAcquiredAt(idx)
	var acquired *time.Time
	if !acquiredAt.IsZero() {
		acquired = &acquiredAt
	}
	source := idx.Source
	if source != "" {
		source = safeSourceURL(source)
	}
	if source == "" {
		source = safeSourceURL(OfflineBaseURL + "/" + mapEcosystem(eco) + "/all.zip")
	}
	s.snapshots[eco] = api.VulnerabilityDataSource{
		Source: source, Mode: "offline", Ecosystem: eco,
		SnapshotID: idx.SnapshotID, AcquiredAt: acquired, Supported: ecosystemSupported(eco), Status: "available",
	}
	if err := s.validateFreshness(eco); err != nil {
		return nil, err
	}
	return idx.Packages, nil
}

func (s *OfflineSource) validateFreshness(eco string) error {
	if s.maxAge <= 0 {
		return nil
	}
	snapshot := s.snapshots[eco]
	if snapshot.AcquiredAt == nil || snapshot.AcquiredAt.IsZero() {
		snapshot.Status = "unknown_age"
		s.snapshots[eco] = snapshot
		return fmt.Errorf("offline OSV snapshot for %s has unknown acquisition time; refresh it with `sentinelflow db update --ecosystems %s`", eco, eco)
	}
	acquiredAt := snapshot.AcquiredAt.UTC()
	age := s.now().Sub(acquiredAt)
	if age < 0 {
		age = 0
	}
	if age > s.maxAge {
		snapshot.Status = "stale"
		s.snapshots[eco] = snapshot
		return fmt.Errorf("offline OSV snapshot for %s is stale (acquired %s, age %s, maximum %s); refresh it with `sentinelflow db update --ecosystems %s`", eco, acquiredAt.Format(time.RFC3339), age.Round(time.Second), s.maxAge, eco)
	}
	snapshot.Status = "available"
	s.snapshots[eco] = snapshot
	return nil
}

// CheckFreshness revalidates evidence before serving an in-memory query-cache
// hit, so a long-running strict-offline client cannot outlive its age policy.
func (s *OfflineSource) CheckFreshness(eco string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxAge <= 0 {
		return nil
	}
	if _, ok := s.snapshots[eco]; !ok {
		return fmt.Errorf("offline OSV snapshot for %s has not been verified; refresh it with `sentinelflow db update --ecosystems %s`", eco, eco)
	}
	return s.validateFreshness(eco)
}

// ProvenanceFor reports metadata from the loaded index. Missing and corrupt
// snapshots remain visible as errors rather than borrowing file modification time.
func (s *OfflineSource) ProvenanceFor(ecosystem, status string) api.VulnerabilityDataSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	if snapshot, ok := s.snapshots[ecosystem]; ok {
		if snapshot.Status == "available" || status == "available" {
			snapshot.Status = status
		}
		return snapshot
	}
	return api.VulnerabilityDataSource{
		Source: safeSourceURL(OfflineBaseURL + "/" + mapEcosystem(ecosystem) + "/all.zip"),
		Mode:   "offline", Ecosystem: ecosystem, Supported: ecosystemSupported(ecosystem), Status: status,
	}
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
		affected, err := versionAffected(v, ecosystem, version)
		if err != nil {
			return nil, fmt.Errorf("evaluate %s for %s/%s@%s: %w", v.ID, ecosystem, pkg, version, err)
		}
		if affected {
			out = append(out, v.toVulnerability(pkg, ecosystem))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func versionAffected(v OSVVulnerability, ecosystem, version string) (bool, error) {
	for _, a := range v.Affected {
		for _, listed := range a.Versions {
			if strings.TrimPrefix(listed, "v") == strings.TrimPrefix(version, "v") {
				return true, nil
			}
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				return false, fmt.Errorf("unsupported OSV GIT range for %s (advisory %s); exact listed versions are still evaluated", ecosystem, v.ID)
			}
			events := make([]rangeEvent, 0, len(r.Events))
			for _, e := range r.Events {
				events = append(events, rangeEvent{Introduced: e.Introduced, Fixed: e.Fixed, LastAffected: e.LastAffected})
			}
			affected, err := affects(r.Type, ecosystem, events, version)
			if err != nil {
				return false, err
			}
			if affected {
				return true, nil
			}
		}
	}
	return false, nil
}
