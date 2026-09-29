// Package scanner provides the scanning engine and scanner implementations
package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/cozygarage/sentinelflow/internal/adapter"
	"github.com/cozygarage/sentinelflow/internal/adapter/external"
	"github.com/cozygarage/sentinelflow/internal/baseline"
	"github.com/cozygarage/sentinelflow/internal/buildinfo"
	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/diff"
	"github.com/cozygarage/sentinelflow/internal/scanner/filter"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/scanner/suppress"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner defines the interface for all security scanners
type Scanner = adapter.Scanner

// Engine orchestrates all security scanners
type Engine struct {
	config   *config.Config
	scanners []Scanner
	Staged   bool
	DiffBase string
}

// NewEngine creates a new scanning engine with configured scanners
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{
		config:   cfg,
		scanners: []Scanner{},
	}
	if cfg == nil {
		return e
	}
	e.DiffBase = cfg.DiffBase

	if cfg.Scanners.Secrets.Enabled {
		e.scanners = append(e.scanners, adapter.NewSecretsAdapter(cfg))
	}
	if cfg.Scanners.IaC.Enabled {
		e.scanners = append(e.scanners, adapter.NewIaCAdapter(cfg))
	}
	if cfg.Scanners.Dependencies.Enabled {
		e.scanners = append(e.scanners, adapter.NewDependenciesAdapter(cfg))
	}
	if cfg.Policies.Enabled {
		e.scanners = append(e.scanners, adapter.NewPolicyAdapter(cfg))
	}
	if cfg.Scanners.SAST.Enabled {
		e.scanners = append(e.scanners, adapter.NewSASTAdapter(cfg))
	}
	if cfg.Scanners.Container.Enabled {
		e.scanners = append(e.scanners, adapter.NewContainerAdapter(cfg))
	}
	if cfg.Scanners.License.Enabled {
		e.scanners = append(e.scanners, adapter.NewLicenseAdapter(cfg))
	}
	if cfg.Scanners.Artifacts.Enabled {
		e.scanners = append(e.scanners, adapter.NewArtifactsAdapter(cfg))
	}
	for _, ext := range external.Adapters(cfg) {
		e.scanners = append(e.scanners, ext)
	}

	return e
}

// Scan runs all enabled scanners on the target path
func (e *Engine) Scan(ctx context.Context, targetPath string) (*api.ScanResult, error) {
	startTime := time.Now()

	if _, err := os.Stat(targetPath); err != nil {
		return nil, fmt.Errorf("target path does not exist: %s", targetPath)
	}

	files, skipped, err := e.collectFiles(ctx, targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to collect files: %w", err)
	}

	result := &api.ScanResult{
		Findings:    []api.Finding{},
		ScannerRuns: []api.ScannerRun{},
		Skipped:     skipped,
		Metadata: api.ScanMetadata{
			TargetPath:          targetPath,
			StartTime:           startTime,
			SentinelFlowVersion: buildinfo.Version,
		},
	}

	e.collectGitMetadata(targetPath, &result.Metadata)

	concurrency := e.config.Scanners.Concurrency
	if concurrency <= 0 {
		concurrency = 8
	}

	opts := types.ScanOptions{
		Files:       files,
		Concurrency: concurrency,
		MaxFileSize: e.config.EffectiveMaxFileSize(),
		Skipped:     skipped,
		DiffBase:    e.diffBase(),
		Staged:      e.Staged,
	}

	type scanOutcome struct {
		run      api.ScannerRun
		findings []api.Finding
	}
	outcomes := make([]scanOutcome, len(e.scanners))
	var wg sync.WaitGroup

	for i, scanner := range e.scanners {
		wg.Add(1)
		go func(i int, s Scanner) {
			defer wg.Done()

			scanStart := time.Now()
			scanResult, err := s.Scan(ctx, targetPath, opts)
			scanDuration := time.Since(scanStart)

			run := api.ScannerRun{
				Scanner:   s.Name(),
				StartTime: scanStart,
				EndTime:   time.Now(),
				Duration:  api.DurationMS(scanDuration),
			}

			if err != nil {
				run.Error = err.Error()
			}
			if scanResult != nil {
				run.FilesCount = scanResult.FilesCount
				run.FindingsCount = len(scanResult.Findings)
				run.Warnings = append([]string(nil), scanResult.Warnings...)
				outcomes[i].findings = scanResult.Findings
			}

			outcomes[i].run = run
		}(i, scanner)
	}

	wg.Wait()
	for _, outcome := range outcomes {
		result.ScannerRuns = append(result.ScannerRuns, outcome.run)
		result.Findings = append(result.Findings, outcome.findings...)
	}
	sortFindings(result.Findings)

	fingerprint.Ensure(result.Findings)

	kept, inline := suppress.Filter(result.Findings, targetPath)
	result.Findings = kept

	if e.diffBase() != "" || e.Staged {
		changed, derr := diff.Collect(diff.Spec{
			Root:   targetPath,
			Base:   e.diffBase(),
			Staged: e.Staged,
		})
		if derr != nil {
			return nil, fmt.Errorf("diff filter: %w", derr)
		}
		result.Findings = diff.Filter(result.Findings, changed)
	}

	if e.config.Baseline.Enabled {
		blPath := e.config.Baseline.File
		if blPath == "" {
			blPath = baseline.DefaultPath
		}
		if !filepath.IsAbs(blPath) {
			blPath = filepath.Join(targetPath, blPath)
		}
		bl, err := baseline.Load(blPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load baseline %s: %w", blPath, err)
		}
		before := result.Findings
		filtered := baseline.Filter(before, bl)
		summary := baseline.Summarize(before, filtered)
		result.Findings = filtered
		result.Baseline = &api.BaselineSummary{
			Enabled:    true,
			Total:      summary.Total,
			Suppressed: summary.Suppressed,
			New:        summary.New,
			Inline:     len(inline),
		}
	} else if len(inline) > 0 {
		result.Baseline = &api.BaselineSummary{
			Enabled:    false,
			Total:      len(kept) + len(inline),
			Suppressed: len(inline),
			New:        len(kept),
			Inline:     len(inline),
		}
	}

	if len(skipped) > 0 {
		var skipMsgs []string
		for _, s := range skipped {
			skipMsgs = append(skipMsgs, fmt.Sprintf("%s (%s)", s.Path, s.Reason))
		}
		if len(result.ScannerRuns) > 0 {
			result.ScannerRuns[0].Warnings = append(result.ScannerRuns[0].Warnings, skipMsgs...)
		}
	}

	result.Metadata.EndTime = time.Now()
	result.Duration = api.DurationMS(time.Since(startTime))

	return result, nil
}

func sortFindings(findings []api.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		aRank, bRank := a.Severity.Rank(), b.Severity.Rank()
		if aRank != bRank {
			return aRank > bRank
		}
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		if a.Location.StartCol != b.Location.StartCol {
			return a.Location.StartCol < b.Location.StartCol
		}
		if a.Scanner != b.Scanner {
			return a.Scanner < b.Scanner
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Fingerprint != b.Fingerprint {
			return a.Fingerprint < b.Fingerprint
		}
		return a.Title < b.Title
	})
}

func (e *Engine) diffBase() string {
	if e.DiffBase != "" {
		return e.DiffBase
	}
	if e.config != nil {
		return e.config.DiffBase
	}
	return ""
}

func (e *Engine) collectFiles(ctx context.Context, targetPath string) ([]string, []api.SkippedFile, error) {
	var files []string
	var skipped []api.SkippedFile
	maxSize := e.config.EffectiveMaxFileSize()

	err := filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			rel, _ := filepath.Rel(targetPath, path)
			skipped = append(skipped, api.SkippedFile{Path: filepath.ToSlash(rel), Reason: "unreadable: " + err.Error()})
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == ".terraform" || name == "__pycache__" || name == ".venv" ||
				name == "dist" || name == "build" || name == ".cache" {
				return filepath.SkipDir
			}
			if path != targetPath && (name == "testdata" || filter.IsBundledSampleDir(targetPath, path)) {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			rel, _ := filepath.Rel(targetPath, path)
			skipped = append(skipped, api.SkippedFile{Path: filepath.ToSlash(rel), Reason: "unreadable"})
			return nil
		}
		if info.Size() > maxSize {
			rel, _ := filepath.Rel(targetPath, path)
			skipped = append(skipped, api.SkippedFile{
				Path:   filepath.ToSlash(rel),
				Reason: fmt.Sprintf("exceeds max_file_size (%d bytes)", maxSize),
			})
			return nil
		}

		relPath, _ := filepath.Rel(targetPath, path)
		if e.shouldSkip(relPath) {
			return nil
		}

		files = append(files, path)
		return nil
	})

	return files, skipped, err
}

func (e *Engine) shouldSkip(path string) bool {
	if e.config == nil {
		return filter.ShouldSkip(path, nil)
	}
	return filter.ShouldSkip(path, e.config.Scanners.Exclude)
}
