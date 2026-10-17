// Package scanner provides the scanning engine and scanner implementations
package scanner

import (
	"context"
	"errors"
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
	"github.com/cozygarage/sentinelflow/internal/scanner/dependencies"
	"github.com/cozygarage/sentinelflow/internal/scanner/diff"
	"github.com/cozygarage/sentinelflow/internal/scanner/filter"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/scanner/redact"
	"github.com/cozygarage/sentinelflow/internal/scanner/suppress"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/internal/scanner/vex"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Scanner defines the interface for all security scanners
type Scanner = adapter.Scanner

// Engine orchestrates all security scanners
type Engine struct {
	config         *config.Config
	scanners       []Scanner
	scannerFactory func(*config.Config) []Scanner
	gitRunner      func(context.Context, string, ...string) (string, error)
	Staged         bool
	DiffBase       string
	// BaselineRef, when set, reports only findings absent at this git ref.
	BaselineRef string
}

// NewEngine creates a new scanning engine with configured scanners
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{
		config: cfg,
	}
	if cfg == nil {
		return e
	}
	e.DiffBase = cfg.DiffBase
	e.scannerFactory = configuredScanners
	e.scanners = configuredScanners(cfg)
	return e
}

func configuredScanners(cfg *config.Config) []Scanner {
	var scanners []Scanner
	if cfg.Scanners.Secrets.Enabled {
		scanners = append(scanners, adapter.NewSecretsAdapter(cfg))
	}
	if cfg.Scanners.IaC.Enabled {
		scanners = append(scanners, adapter.NewIaCAdapter(cfg))
	}
	if cfg.Scanners.Dependencies.Enabled {
		scanners = append(scanners, adapter.NewDependenciesAdapter(cfg))
	}
	if cfg.Policies.Enabled {
		scanners = append(scanners, adapter.NewPolicyAdapter(cfg))
	}
	if cfg.Scanners.SAST.Enabled {
		scanners = append(scanners, adapter.NewSASTAdapter(cfg))
	}
	if cfg.Scanners.Container.Enabled {
		scanners = append(scanners, adapter.NewContainerAdapter(cfg))
	}
	if cfg.Scanners.License.Enabled {
		scanners = append(scanners, adapter.NewLicenseAdapter(cfg))
	}
	if cfg.Scanners.Artifacts.Enabled {
		scanners = append(scanners, adapter.NewArtifactsAdapter(cfg))
	}
	for _, ext := range external.Adapters(cfg) {
		scanners = append(scanners, ext)
	}
	return scanners
}

func (e *Engine) runGit(ctx context.Context, dir string, args ...string) (string, error) {
	if e.gitRunner != nil {
		return e.gitRunner(ctx, dir, args...)
	}
	return runGit(ctx, dir, args...)
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
		run               api.ScannerRun
		findings          []api.Finding
		vulnerabilityData []api.VulnerabilityDataSource
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
				run.Error = redact.Line(err.Error())
			}
			if scanResult != nil {
				run.FilesCount = scanResult.FilesCount
				run.FindingsCount = len(scanResult.Findings)
				run.Warnings = make([]string, len(scanResult.Warnings))
				for i, warning := range scanResult.Warnings {
					run.Warnings[i] = redact.Line(warning)
				}
				outcomes[i].findings = scanResult.Findings
				outcomes[i].vulnerabilityData = scanResult.VulnerabilityData
				run.Status = scanResult.Status
			}
			if errors.Is(err, context.DeadlineExceeded) {
				run.Status = api.ScanStatusTimedOut
			} else if err != nil && (run.Status == "" || run.Status == api.ScanStatusComplete || run.Status == api.ScanStatusSkipped) {
				if scanResult != nil && len(scanResult.Findings) > 0 {
					run.Status = api.ScanStatusPartial
				} else {
					run.Status = api.ScanStatusFailed
				}
			} else if run.Status == "" {
				switch {
				case errors.Is(err, context.Canceled):
					run.Status = api.ScanStatusFailed
				case err != nil && scanResult != nil && len(scanResult.Findings) > 0:
					run.Status = api.ScanStatusPartial
				case err != nil:
					run.Status = api.ScanStatusFailed
				case scanResult != nil && len(scanResult.Warnings) > 0:
					run.Status = api.ScanStatusPartial
				default:
					run.Status = api.ScanStatusComplete
				}
			}

			outcomes[i].run = run
		}(i, scanner)
	}

	wg.Wait()
	for _, outcome := range outcomes {
		result.ScannerRuns = append(result.ScannerRuns, outcome.run)
		result.Findings = append(result.Findings, outcome.findings...)
		result.Metadata.VulnerabilityData = append(result.Metadata.VulnerabilityData, outcome.vulnerabilityData...)
	}
	result.Metadata.VulnerabilityData = uniqueVulnerabilityData(result.Metadata.VulnerabilityData)
	sortFindings(result.Findings)

	fingerprint.Ensure(result.Findings)

	if e.config.Scanners.Dependencies.RiskEnrichment && !e.config.Scanners.Dependencies.Offline {
		if err := enrichRisk(ctx, result.Findings); err != nil && len(result.ScannerRuns) > 0 {
			run := depsRun(result)
			msg := redact.Line("EPSS/KEV enrichment incomplete: " + err.Error())
			if e.config.FailOn.KEV && run.Error == "" {
				// The KEV gate cannot be evaluated; fail closed instead of passing silently.
				run.Error = msg
				run.Status = api.ScanStatusFailed
			} else {
				run.Warnings = append(run.Warnings, msg)
				if run.Status == api.ScanStatusComplete {
					run.Status = api.ScanStatusPartial
				}
			}
		}
	}

	if mode := config.ExternalMode(e.config.Scanners.Dependencies.Reachability); mode != "off" {
		err := dependencies.AnnotateGoReachability(ctx, targetPath, result.Findings)
		if err != nil && len(result.ScannerRuns) > 0 {
			run := depsRun(result)
			switch {
			case mode == "required":
				run.Status = api.ScanStatusFailed
				if errors.Is(err, context.DeadlineExceeded) {
					run.Status = api.ScanStatusTimedOut
				}
				if run.Error == "" {
					run.Error = redact.Line("reachability: " + err.Error())
				} else {
					run.Error = redact.Line(run.Error + "; reachability: " + err.Error())
				}
			case errors.Is(err, dependencies.ErrGovulncheckMissing):
				run.Warnings = append(run.Warnings, "reachability: govulncheck not on PATH (mode=auto; skipping)")
				run.Status = api.ScanStatusPartial
			default:
				run.Warnings = append(run.Warnings, redact.Line("reachability: "+err.Error()))
				run.Status = api.ScanStatusPartial
			}
		}
	}

	kept, inline, inlineErr := suppress.FilterWithOptions(result.Findings, targetPath, e.config.StrictIgnores)
	if inlineErr != nil {
		markPostProcessFailure(result, startTime, "inline-suppression", inlineErr)
		return result, inlineErr
	}
	appendSuppressed(result, inline, "inline", "matched inline ignore directive", "repository")
	result.Findings = kept

	var vexed []api.Finding
	if len(e.config.VEX) > 0 {
		paths := make([]string, len(e.config.VEX))
		for i, p := range e.config.VEX {
			if !filepath.IsAbs(p) {
				p = filepath.Join(targetPath, p)
			}
			paths[i] = p
		}
		rules, err := vex.LoadWithOptions(paths, vex.LoadOptions{AllowBroad: e.config.VEXAllowBroad})
		if err != nil {
			markPostProcessFailure(result, startTime, "vex", err)
			return result, fmt.Errorf("load VEX: %w", err)
		}
		result.Findings, vexed = vex.Filter(result.Findings, rules)
		appendSuppressed(result, vexed, "vex", "matched not_affected or fixed VEX statement", "repository")
	}

	if e.diffBase() != "" || e.Staged {
		changed, derr := diff.Collect(diff.Spec{
			Root:   targetPath,
			Base:   e.diffBase(),
			Staged: e.Staged,
		})
		if derr != nil {
			markPostProcessFailure(result, startTime, "diff", derr)
			return result, fmt.Errorf("diff filter: %w", derr)
		}
		before := result.Findings
		result.Findings = diff.Filter(before, changed)
		appendRemovedSuppressed(result, before, result.Findings, "diff", "finding is outside the selected changed lines", "repository")
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
			markPostProcessFailure(result, startTime, "baseline", err)
			return result, fmt.Errorf("failed to load baseline %s: %w", blPath, err)
		}
		before := result.Findings
		filtered := baseline.Filter(before, bl)
		appendRemovedSuppressed(result, before, filtered, "baseline", "matched active baseline entry", "repository")
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

	if e.BaselineRef != "" {
		if err := e.filterBaselineRef(ctx, targetPath, result); err != nil {
			result.ScannerRuns = append(result.ScannerRuns, api.ScannerRun{Scanner: "baseline-ref", Status: api.ScanStatusFailed, Error: redact.Line(err.Error())})
			result.Status = statusForRuns(result.ScannerRuns)
			result.Metadata.EndTime = time.Now()
			result.Duration = api.DurationMS(time.Since(startTime))
			return result, err
		}
	}
	if len(vexed) > 0 {
		if result.Baseline == nil {
			result.Baseline = &api.BaselineSummary{Total: len(result.Findings), New: len(result.Findings)}
		}
		result.Baseline.Total += len(vexed)
		result.Baseline.Suppressed += len(vexed)
		result.Baseline.VEX = len(vexed)
	}
	reconcileSuppressionSummary(result, e.config.Baseline.Enabled || e.BaselineRef != "")

	if len(skipped) > 0 {
		var skipMsgs []string
		for _, s := range skipped {
			skipMsgs = append(skipMsgs, fmt.Sprintf("%s (%s)", s.Path, s.Reason))
		}
		if len(result.ScannerRuns) > 0 {
			result.ScannerRuns[0].Warnings = append(result.ScannerRuns[0].Warnings, skipMsgs...)
			if result.ScannerRuns[0].Status == api.ScanStatusComplete {
				result.ScannerRuns[0].Status = api.ScanStatusPartial
			}
		}
	}

	result.Metadata.EndTime = time.Now()
	result.Duration = api.DurationMS(time.Since(startTime))
	result.Status = statusForRuns(result.ScannerRuns)
	if len(skipped) > 0 && result.Status == api.ScanStatusComplete {
		result.Status = api.ScanStatusPartial
	}

	return result, nil
}

func uniqueVulnerabilityData(in []api.VulnerabilityDataSource) []api.VulnerabilityDataSource {
	seen := make(map[string]bool, len(in))
	out := make([]api.VulnerabilityDataSource, 0, len(in))
	for _, entry := range in {
		key := entry.Source + "\x00" + entry.Mode + "\x00" + entry.Ecosystem + "\x00" + entry.SnapshotID + "\x00" + entry.Status
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, entry)
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

func appendSuppressed(result *api.ScanResult, findings []api.Finding, source, reason, authority string) {
	for _, f := range findings {
		result.Suppressed = append(result.Suppressed, api.SuppressedObservation{
			Fingerprint: fingerprint.Of(f), RuleID: f.RuleID, Source: source,
			Reason: reason, Authority: authority,
		})
	}
}

func appendRemovedSuppressed(result *api.ScanResult, before, after []api.Finding, source, reason, authority string) {
	remaining := make(map[string]int, len(after))
	for _, f := range after {
		remaining[fingerprint.Of(f)]++
	}
	var removed []api.Finding
	for _, f := range before {
		key := fingerprint.Of(f)
		if remaining[key] > 0 {
			remaining[key]--
			continue
		}
		removed = append(removed, f)
	}
	appendSuppressed(result, removed, source, reason, authority)
}

func reconcileSuppressionSummary(result *api.ScanResult, enabled bool) {
	if result == nil || (result.Baseline == nil && len(result.Suppressed) == 0) {
		return
	}
	if result.Baseline == nil {
		result.Baseline = &api.BaselineSummary{}
	}
	summary := result.Baseline
	summary.Enabled = summary.Enabled || enabled
	summary.New = len(result.Findings)
	summary.Suppressed = len(result.Suppressed)
	summary.Total = summary.New + summary.Suppressed
	summary.Inline, summary.VEX, summary.Diff, summary.BaselineRef = 0, 0, 0, 0
	for _, observation := range result.Suppressed {
		switch observation.Source {
		case "inline":
			summary.Inline++
		case "vex":
			summary.VEX++
		case "diff":
			summary.Diff++
		case "baseline-ref":
			summary.BaselineRef++
		}
	}
}

func markPostProcessFailure(result *api.ScanResult, startTime time.Time, name string, err error) {
	status := api.ScanStatusFailed
	if errors.Is(err, context.DeadlineExceeded) {
		status = api.ScanStatusTimedOut
	}
	result.ScannerRuns = append(result.ScannerRuns, api.ScannerRun{
		Scanner: "postprocess:" + name,
		Status:  status,
		Error:   redact.Line(err.Error()),
	})
	result.Metadata.EndTime = time.Now()
	result.Duration = api.DurationMS(time.Since(startTime))
	result.Status = statusForRuns(result.ScannerRuns)
}

func statusForRuns(runs []api.ScannerRun) api.ScanStatus {
	if len(runs) == 0 {
		return api.ScanStatusSkipped
	}
	status := api.ScanStatusComplete
	allSkipped := true
	allNotApplicable := true
	for _, run := range runs {
		if run.Status != api.ScanStatusSkipped {
			allSkipped = false
		}
		if run.Status != api.ScanStatusNotApplicable {
			allNotApplicable = false
		}
		switch run.Status {
		case api.ScanStatusComplete:
			// A successful run contributes no degradation.
		case api.ScanStatusTimedOut:
			return api.ScanStatusTimedOut
		case api.ScanStatusFailed:
			status = api.ScanStatusFailed
		case api.ScanStatusPartial, api.ScanStatusNotApplicable, api.ScanStatusSkipped:
			if status == api.ScanStatusComplete {
				status = api.ScanStatusPartial
			}
		default:
			// Unknown producer states must not be interpreted as complete coverage.
			status = api.ScanStatusFailed
		}
	}
	if allSkipped {
		return api.ScanStatusSkipped
	}
	if allNotApplicable {
		return api.ScanStatusNotApplicable
	}
	return status
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
	files := []string{} // non-nil: an empty list means "nothing to scan", not "walk again"
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

// depsRun returns the dependencies scanner run (or the first run) for warnings.
func depsRun(result *api.ScanResult) *api.ScannerRun {
	for i := range result.ScannerRuns {
		if result.ScannerRuns[i].Scanner == "dependencies" {
			return &result.ScannerRuns[i]
		}
	}
	return &result.ScannerRuns[0]
}
