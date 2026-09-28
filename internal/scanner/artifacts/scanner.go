// Package artifacts scans binaries, archives, and built outputs.
package artifacts

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/filetype"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/scanner/secrets"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/internal/scanner/unpack"
	"github.com/cozygarage/sentinelflow/internal/vulndb"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

type Scanner struct {
	config *config.Config
	client *vulndb.Client
	secret *secrets.Scanner
}

type ScannerResult = types.ScannerResult

func NewScanner(cfg *config.Config) *Scanner {
	s := &Scanner{config: cfg, secret: secrets.NewScanner(cfg)}
	client, err := vulndb.NewClient()
	if err == nil {
		s.client = client
	}
	return s
}

func (s *Scanner) Name() string { return "artifacts" }

func (s *Scanner) Supports(path string) bool {
	k := filetype.Detect(path)
	if k.IsArchive() || k.IsExecutable() {
		return true
	}
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasSuffix(base, ".jar"), strings.HasSuffix(base, ".war"),
		strings.HasSuffix(base, ".whl"), strings.HasSuffix(base, ".egg"),
		strings.HasSuffix(base, ".tar"), strings.HasSuffix(base, ".tar.gz"),
		strings.HasSuffix(base, ".tgz"):
		return true
	}
	return false
}

func (s *Scanner) enabledChecks() map[string]bool {
	out := map[string]bool{}
	checks := s.config.Scanners.Artifacts.Checks
	if len(checks) == 0 {
		checks = []string{"components", "secrets", "hardening"}
	}
	for _, c := range checks {
		out[strings.ToLower(strings.TrimSpace(c))] = true
	}
	return out
}

func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{Findings: []api.Finding{}}
	files, err := types.ResolveFiles(path, opts, s.collectFiles)
	if err != nil {
		return nil, err
	}

	checks := s.enabledChecks()
	var warnings []string
	var scanFiles []string
	for _, f := range files {
		if s.Supports(f) || s.matchesPathGlob(path, f) {
			scanFiles = append(scanFiles, f)
		}
	}
	result.FilesCount = len(scanFiles)

	for _, file := range scanFiles {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		findings, warn, err := s.scanOne(ctx, file, path, checks)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		warnings = append(warnings, warn...)
		result.Findings = append(result.Findings, findings...)
	}
	result.Warnings = warnings
	return result, nil
}

func (s *Scanner) matchesPathGlob(root, file string) bool {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		rel = file
	}
	rel = filepath.ToSlash(rel)
	for _, g := range s.config.Scanners.Artifacts.Paths {
		ok, _ := filepath.Match(g, rel)
		if ok || strings.HasPrefix(rel, strings.TrimSuffix(g, "/**")+"/") {
			return true
		}
	}
	return false
}

func (s *Scanner) scanOne(ctx context.Context, file, root string, checks map[string]bool) ([]api.Finding, []string, error) {
	rel, _ := filepath.Rel(root, file)
	rel = filepath.ToSlash(rel)
	kind := filetype.Detect(file)
	var findings []api.Finding
	var warnings []string

	if checks["hardening"] && kind.IsExecutable() {
		findings = append(findings, hardeningFindings(file, rel, kind)...)
	}
	if checks["malware"] && kind.IsExecutable() {
		findings = append(findings, malwareBinary(file, rel)...)
	}

	if checks["components"] {
		comps, err := catalogFile(file, rel, kind)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: catalog: %v", rel, err))
		}
		for _, c := range comps {
			findings = append(findings, s.componentFindings(ctx, c)...)
		}
	}

	if checks["secrets"] {
		findings = append(findings, s.secretFindings(ctx, file, rel, kind)...)
	}

	if kind.IsArchive() {
		limits := unpack.Limits{
			MaxDepth: s.config.Scanners.Artifacts.MaxArchiveDepth,
			MaxBytes: s.config.Scanners.Artifacts.MaxExtractedBytes,
		}
		members, err := extract(ctx, file, kind, limits)
		if err != nil {
			return findings, warnings, fmt.Errorf("%s: %w", rel, err)
		}
		for _, m := range members {
			art := rel + "!/" + m.Path
			if checks["secrets"] {
				findings = append(findings, s.secretBytes(ctx, m.Data, art)...)
			}
			if checks["malware"] {
				findings = append(findings, malwareBytes(m.Data, art, m.Path)...)
			}
			if checks["components"] {
				for _, c := range catalogMember(m, art) {
					findings = append(findings, s.componentFindings(ctx, c)...)
				}
			}
		}
	}

	for i := range findings {
		if findings[i].Fingerprint == "" {
			findings[i].Fingerprint = fingerprint.Of(findings[i])
		}
	}
	return findings, warnings, nil
}

func extract(ctx context.Context, path string, kind filetype.Kind, limits unpack.Limits) ([]unpack.File, error) {
	var res *unpack.Result
	var err error
	switch kind {
	case filetype.KindZip:
		res, err = unpack.Zip(ctx, path, limits)
	case filetype.KindGzip:
		res, err = unpack.TarGz(ctx, path, limits)
	case filetype.KindTar:
		res, err = unpack.Tar(ctx, path, limits)
	default:
		base := strings.ToLower(path)
		switch {
		case strings.HasSuffix(base, ".jar"), strings.HasSuffix(base, ".war"), strings.HasSuffix(base, ".whl"):
			res, err = unpack.Zip(ctx, path, limits)
		case strings.HasSuffix(base, ".tar.gz"), strings.HasSuffix(base, ".tgz"):
			res, err = unpack.TarGz(ctx, path, limits)
		default:
			return nil, nil
		}
	}
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return res.Files, nil
}

func (s *Scanner) secretFindings(ctx context.Context, file, rel string, kind filetype.Kind) []api.Finding {
	minLen := s.config.Scanners.Artifacts.MinStringLen
	if minLen <= 0 {
		minLen = 8
	}
	if kind == filetype.KindText || kind == filetype.KindUnknown {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil
		}
		return s.secretBytes(ctx, data, rel)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	joined := strings.Join(extractPrintable(data, minLen), "\n")
	return s.secretBytes(ctx, []byte(joined), rel)
}

func (s *Scanner) secretBytes(ctx context.Context, data []byte, displayPath string) []api.Finding {
	if s.secret == nil || len(data) == 0 {
		return nil
	}
	findings, err := s.secret.ScanReader(ctx, bytes.NewReader(data), displayPath, "")
	if err != nil {
		return nil
	}
	for i := range findings {
		if strings.Contains(displayPath, "!/") {
			parts := strings.SplitN(displayPath, "!/", 2)
			findings[i].Location.File = parts[0]
			findings[i].Location.ArtifactPath = displayPath
		}
	}
	return findings
}

func (s *Scanner) collectFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && info.Name() == ".git" {
				return filepath.SkipDir
			}
			return err
		}
		files = append(files, path)
		return nil
	})
	return files, err
}

func catalogFile(path, rel string, kind filetype.Kind) ([]Component, error) {
	var comps []Component
	if kind.IsExecutable() || kind == filetype.KindUnknown {
		if bi, err := buildinfo.ReadFile(path); err == nil {
			comps = append(comps, componentsFromBuildInfo(bi, rel)...)
		}
	}
	return comps, nil
}

func catalogMember(m unpack.File, artifactPath string) []Component {
	lower := strings.ToLower(m.Path)
	switch {
	case strings.Contains(lower, "pom.properties"):
		return componentsFromPomProperties(m.Data, artifactPath)
	case strings.HasSuffix(lower, ".dist-info/metadata") || strings.HasSuffix(lower, "metadata"):
		return componentsFromWheelMetadata(m.Data, artifactPath)
	case strings.HasSuffix(lower, "package.json"):
		return componentsFromPackageJSON(m.Data, artifactPath)
	case strings.HasSuffix(lower, "var/lib/dpkg/status") || strings.HasSuffix(lower, "lib/dpkg/status"):
		return componentsFromDpkgStatus(m.Data, artifactPath)
	case strings.Contains(lower, "lib/apk/db/installed"):
		return componentsFromApkInstalled(m.Data, artifactPath)
	}
	return nil
}

func ArtifactJoin(archive, member string) string {
	return archive + "!/" + member
}
