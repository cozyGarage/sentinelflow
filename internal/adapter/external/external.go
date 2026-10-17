// Package external runs optional third-party scanners and maps their output.
package external

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

type Scanner = types.ScannerResult

// Adapter is a PATH-based tool wrapper.
type Adapter struct {
	name           string
	bin            string
	mode           string
	version        []string
	args           func(path string) []string
	parse          func(path string, stdout []byte) ([]api.Finding, error)
	requiresOutput bool
}

func (a *Adapter) Name() string              { return a.name }
func (a *Adapter) Supports(path string) bool { return true }

func (a *Adapter) Scan(ctx context.Context, path string, opts interface{}) (*types.ScannerResult, error) {
	result := &types.ScannerResult{Findings: []api.Finding{}}
	if config.ExternalMode(a.mode) == "off" {
		result.Status = api.ScanStatusSkipped
		return result, nil
	}
	if _, err := exec.LookPath(a.bin); err != nil {
		msg := fmt.Sprintf("%s not found on PATH", a.bin)
		if config.ExternalMode(a.mode) == "required" {
			result.Status = api.ScanStatusFailed
			return result, fmt.Errorf("%s", msg)
		}
		result.Status = api.ScanStatusSkipped
		result.Warnings = []string{msg + " (mode=auto; skipping)"}
		return result, nil
	}

	args := a.args(path)
	// The executable is a PATH tool name chosen at adapter construction (semgrep, grype, …).
	cmd := exec.CommandContext(ctx, a.bin, args...) // sentinelflow:ignore go-ast-exec-nonconst -- fixed adapter binary
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	findings, parseErr := a.parse(path, stdout.Bytes())
	result.Findings = findings
	result.FilesCount = 1
	var failures []error
	if parseErr != nil {
		failures = append(failures, fmt.Errorf("invalid report: %w", parseErr))
	}
	if err != nil {
		failures = append(failures, err)
	}
	if a.requiresOutput && len(bytes.TrimSpace(stdout.Bytes())) == 0 && err == nil {
		failures = append(failures, errors.New("produced no report output"))
	}
	if len(failures) > 0 {
		failure := errors.Join(failures...)
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			failure = fmt.Errorf("%w (%s)", failure, detail)
		}
		if config.ExternalMode(a.mode) == "required" {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				result.Status = api.ScanStatusTimedOut
			} else if len(findings) > 0 {
				result.Status = api.ScanStatusPartial
			} else {
				result.Status = api.ScanStatusFailed
			}
			return result, fmt.Errorf("%s: %w", a.bin, failure)
		}
		result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %v", a.bin, failure))
		result.Status = api.ScanStatusPartial
	}
	if result.Status == "" {
		result.Status = api.ScanStatusComplete
	}
	return result, nil
}

// Adapters returns enabled external scanners for the engine.
func Adapters(cfg *config.Config) []*Adapter {
	if cfg == nil {
		return nil
	}
	var out []*Adapter
	add := func(mode string, a *Adapter) {
		if config.ExternalMode(mode) == "off" {
			return
		}
		a.mode = mode
		out = append(out, a)
	}
	add(cfg.Scanners.External.Semgrep.Mode, semgrepAdapter())
	add(cfg.Scanners.External.Gitleaks.Mode, gitleaksAdapter())
	add(cfg.Scanners.External.Grype.Mode, grypeAdapter())
	add(cfg.Scanners.External.Syft.Mode, syftAdapter())
	add(cfg.Scanners.External.TrivyFS.Mode, trivyFSAdapter())
	add(cfg.Scanners.External.YARA.Mode, yaraAdapter(cfg.Scanners.External.YARA.Rules))
	return out
}

func semgrepAdapter() *Adapter {
	return &Adapter{
		name:    "semgrep",
		bin:     "semgrep",
		version: []string{"--version"},
		args: func(path string) []string {
			return []string{"--config=auto", "--json", "--quiet", path}
		},
		parse: parseSemgrep, requiresOutput: true,
	}
}

func gitleaksAdapter() *Adapter {
	return &Adapter{
		name:    "gitleaks",
		bin:     "gitleaks",
		version: []string{"--version"},
		args: func(path string) []string {
			return []string{"detect", "--source", path, "--report-format", "json", "--no-banner", "--exit-code", "0"}
		},
		parse: parseGitleaks, requiresOutput: true,
	}
}

func grypeAdapter() *Adapter {
	return &Adapter{
		name:    "grype",
		bin:     "grype",
		version: []string{"--version"},
		args: func(path string) []string {
			return []string{path, "-o", "json"}
		},
		parse: parseGrype, requiresOutput: true,
	}
}

func syftAdapter() *Adapter {
	return &Adapter{
		name:    "syft",
		bin:     "syft",
		version: []string{"--version"},
		args: func(path string) []string {
			return []string{path, "-o", "json"}
		},
		parse: parseSyft, requiresOutput: true,
	}
}

func trivyFSAdapter() *Adapter {
	return &Adapter{
		name:    "trivy-fs",
		bin:     "trivy",
		version: []string{"--version"},
		args: func(path string) []string {
			return []string{"fs", "--format", "json", "--quiet", path}
		},
		parse: parseTrivyFS, requiresOutput: true,
	}
}

func yaraAdapter(rules []string) *Adapter {
	return &Adapter{
		name:    "yara",
		bin:     "yara",
		version: []string{"--version"},
		args: func(path string) []string {
			r := "."
			if len(rules) > 0 {
				r = rules[0]
			}
			return []string{"-r", r, path}
		},
		parse: parseYARA,
	}
}

func requireJSONArray(stdout []byte, field, tool string) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(stdout, &root); err != nil {
		return err
	}
	raw, ok := root[field]
	if !ok || len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '[' {
		return fmt.Errorf("invalid %s report: expected %q array", tool, field)
	}
	return nil
}

func parseSemgrep(root string, stdout []byte) ([]api.Finding, error) {
	if len(bytes.TrimSpace(stdout)) == 0 {
		return nil, nil
	}
	if err := requireJSONArray(stdout, "results", "semgrep"); err != nil {
		return nil, err
	}
	var report struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Extra   struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
			} `json:"extra"`
			Start struct {
				Line int `json:"line"`
			} `json:"start"`
		} `json:"results"`
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(stdout, &report); err != nil {
		return nil, err
	}
	var out []api.Finding
	for _, r := range report.Results {
		f := api.Finding{
			ID:          "EXT-SEMGREP-" + fingerprint.ValueHash(r.CheckID+r.Path+fmt.Sprint(r.Start.Line)),
			Type:        api.FindingTypeInsecureCode,
			Severity:    mapToolSev(r.Extra.Severity),
			Title:       r.CheckID,
			Description: r.Extra.Message,
			Location:    api.Location{File: r.Path, StartLine: r.Start.Line, EndLine: r.Start.Line},
			Scanner:     "semgrep",
			RuleID:      r.CheckID,
			Confidence:  0.8,
		}
		f.Fingerprint = fingerprint.Of(f)
		out = append(out, f)
	}
	if len(report.Errors) > 0 {
		return out, fmt.Errorf("semgrep reported %d analysis errors", len(report.Errors))
	}
	return out, nil
}

func parseGitleaks(root string, stdout []byte) ([]api.Finding, error) {
	stdout = bytes.TrimSpace(stdout)
	if len(stdout) == 0 {
		return nil, nil
	}
	if stdout[0] != '[' {
		return nil, fmt.Errorf("invalid gitleaks report: expected JSON array")
	}
	var hits []struct {
		RuleID      string `json:"RuleID"`
		Description string `json:"Description"`
		File        string `json:"File"`
		StartLine   int    `json:"StartLine"`
		Match       string `json:"Match"`
	}
	if err := json.Unmarshal(stdout, &hits); err != nil {
		return nil, err
	}
	var out []api.Finding
	for _, h := range hits {
		f := api.Finding{
			ID:          "EXT-GITLEAKS-" + fingerprint.ValueHash(h.RuleID+h.File+h.Match),
			Type:        api.FindingTypeSecret,
			Severity:    api.SeverityHigh,
			Title:       h.Description,
			Description: h.Description,
			Location:    api.Location{File: h.File, StartLine: h.StartLine, EndLine: h.StartLine},
			Scanner:     "gitleaks",
			RuleID:      h.RuleID,
			ValueHash:   fingerprint.ValueHash(h.Match),
			Confidence:  0.85,
		}
		f.Fingerprint = fingerprint.Of(f)
		out = append(out, f)
	}
	return out, nil
}

func parseGrype(root string, stdout []byte) ([]api.Finding, error) {
	if len(bytes.TrimSpace(stdout)) == 0 {
		return nil, nil
	}
	if err := requireJSONArray(stdout, "matches", "grype"); err != nil {
		return nil, err
	}
	var report struct {
		Matches []struct {
			Vulnerability struct {
				ID          string `json:"id"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(stdout, &report); err != nil {
		return nil, err
	}
	var out []api.Finding
	for _, m := range report.Matches {
		f := api.Finding{
			ID:          "EXT-GRYPE-" + m.Vulnerability.ID + "-" + fingerprint.ValueHash(m.Artifact.Name),
			Type:        api.FindingTypeVulnerability,
			Severity:    mapToolSev(m.Vulnerability.Severity),
			Title:       fmt.Sprintf("%s in %s@%s", m.Vulnerability.ID, m.Artifact.Name, m.Artifact.Version),
			Description: m.Vulnerability.Description,
			Location:    api.Location{File: root, Snippet: m.Artifact.Name + "@" + m.Artifact.Version},
			Scanner:     "grype",
			RuleID:      m.Vulnerability.ID,
			CVE:         m.Vulnerability.ID,
			Confidence:  0.9,
		}
		f.Fingerprint = fingerprint.Of(f)
		out = append(out, f)
	}
	return out, nil
}

func parseSyft(root string, stdout []byte) ([]api.Finding, error) {
	// Syft is a cataloger; we emit info-level component findings.
	if len(bytes.TrimSpace(stdout)) == 0 {
		return nil, nil
	}
	if err := requireJSONArray(stdout, "artifacts", "syft"); err != nil {
		return nil, err
	}
	var report struct {
		Artifacts []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(stdout, &report); err != nil {
		return nil, err
	}
	var out []api.Finding
	for _, a := range report.Artifacts {
		f := api.Finding{
			ID:          "EXT-SYFT-" + fingerprint.ValueHash(a.PURL+a.Name),
			Type:        api.FindingTypeComponent,
			Severity:    api.SeverityInfo,
			Title:       fmt.Sprintf("Syft component %s@%s", a.Name, a.Version),
			Description: a.PURL,
			Location:    api.Location{File: root, Snippet: a.PURL},
			Scanner:     "syft",
			RuleID:      "syft-component",
			Confidence:  0.8,
		}
		f.Fingerprint = fingerprint.Of(f)
		out = append(out, f)
	}
	return out, nil
}

func parseTrivyFS(root string, stdout []byte) ([]api.Finding, error) {
	if len(bytes.TrimSpace(stdout)) == 0 {
		return nil, nil
	}
	var report struct {
		SchemaVersion int    `json:"SchemaVersion"`
		ArtifactName  string `json:"ArtifactName"`
		Results       []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(stdout, &report); err != nil {
		return nil, err
	}
	if report.SchemaVersion == 0 || report.ArtifactName == "" {
		return nil, fmt.Errorf("invalid trivy report: missing schema version or artifact name")
	}
	var out []api.Finding
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			f := api.Finding{
				ID:          "EXT-TRIVYFS-" + v.VulnerabilityID + "-" + fingerprint.ValueHash(v.PkgName),
				Type:        api.FindingTypeVulnerability,
				Severity:    mapToolSev(v.Severity),
				Title:       v.Title,
				Description: fmt.Sprintf("%s@%s", v.PkgName, v.InstalledVersion),
				Location:    api.Location{File: r.Target},
				Scanner:     "trivy-fs",
				RuleID:      v.VulnerabilityID,
				CVE:         v.VulnerabilityID,
				Confidence:  0.9,
			}
			f.Fingerprint = fingerprint.Of(f)
			out = append(out, f)
		}
	}
	return out, nil
}

func parseYARA(root string, stdout []byte) ([]api.Finding, error) {
	var out []api.Finding
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		rule, file := fields[0], fields[len(fields)-1]
		f := api.Finding{
			ID:          "EXT-YARA-" + fingerprint.ValueHash(rule+file),
			Type:        api.FindingTypeMalware,
			Severity:    api.SeverityMedium,
			Title:       "YARA rule " + rule,
			Description: line,
			Location:    api.Location{File: file},
			Scanner:     "yara",
			RuleID:      rule,
			Confidence:  0.7,
		}
		f.Fingerprint = fingerprint.Of(f)
		out = append(out, f)
	}
	return out, nil
}

func mapToolSev(s string) api.Severity {
	return api.ParseSeverity(s)
}
