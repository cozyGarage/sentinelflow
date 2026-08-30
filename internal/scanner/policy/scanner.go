// Package policy provides policy-as-code enforcement using OPA
package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/pkg/api"
	"github.com/cozygarage/sentinelflow/policies"
)

// Scanner implements policy-as-code scanning using OPA
type Scanner struct {
	config     *config.Config
	severities map[string]api.Severity
}

// ScannerResult contains scan results
type ScannerResult struct {
	Findings   []api.Finding
	FilesCount int
}

// NewScanner creates a new policy scanner
func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		config:     cfg,
		severities: make(map[string]api.Severity),
	}
}

// Name returns the scanner identifier
func (s *Scanner) Name() string {
	return "policy"
}

// Supports returns true for files that policies should check
func (s *Scanner) Supports(path string) bool {
	return true
}

// Scan performs policy enforcement
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{
		Findings: []api.Finding{},
	}

	if !s.config.Policies.Enabled {
		return result, nil
	}

	engine := NewOPAEngine()
	if err := s.loadPolicyFiles(engine, path); err != nil {
		return result, err
	}

	policyNames := engine.ListPolicies()
	if len(policyNames) == 0 {
		return result, nil
	}

	inputs, err := collectPolicyInputs(path)
	if err != nil {
		return result, err
	}

	result.FilesCount = len(inputs)

	var evalErrs []string
	for _, input := range inputs {
		for _, name := range policyNames {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			policyResult, err := engine.EvaluatePolicy(name, input.Data)
			if err != nil {
				evalErrs = append(evalErrs, fmt.Sprintf("%s/%s: %v", input.FilePath, name, err))
				continue
			}

			severity := s.severityFor(name)
			findings := ConvertToFindings(policyResult, severity)
			for i := range findings {
				if findings[i].Location.File == "" {
					findings[i].Location.File = input.FilePath
				}
			}
			result.Findings = append(result.Findings, findings...)
		}
	}

	if len(evalErrs) > 0 {
		return result, fmt.Errorf("policy evaluation errors (%d): %s", len(evalErrs), strings.Join(evalErrs, "; "))
	}
	return result, nil
}

func (s *Scanner) loadPolicyFiles(engine *OPAEngine, scanRoot string) error {
	seenNames := make(map[string]bool)
	seenPaths := make(map[string]bool)
	var loadErrs []string

	loadContent := func(name, content, source string, overwrite bool) {
		if seenNames[name] && !overwrite {
			return
		}
		if err := engine.LoadPolicy(name, content); err != nil {
			loadErrs = append(loadErrs, fmt.Sprintf("%s: %v", source, err))
			return
		}
		seenNames[name] = true
		s.severities[name] = parseSeverityFromRego(content)
	}

	loadFile := func(path string, overwrite bool) {
		if !strings.HasSuffix(path, ".rego") || seenPaths[path] {
			return
		}
		seenPaths[path] = true

		content, err := os.ReadFile(path)
		if err != nil {
			loadErrs = append(loadErrs, fmt.Sprintf("%s: %v", path, err))
			return
		}

		name := strings.TrimSuffix(filepath.Base(path), ".rego")
		loadContent(name, string(content), path, overwrite)
	}

	// Built-ins first; project/custom files may override by name.
	if len(s.config.Policies.Builtin) > 0 {
		selected, err := policies.LoadSelected(s.config.Policies.Builtin)
		if err != nil {
			return fmt.Errorf("built-in policies: %w", err)
		}
		for name, content := range selected {
			loadContent(name, content, "builtin:"+name, false)
		}
	}

	loadDir := func(dir string) {
		if dir == "" {
			return
		}
		if _, err := os.Stat(dir); err != nil {
			return
		}
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			loadFile(path, true)
			return nil
		})
	}

	loadDir(filepath.Join(scanRoot, "policies"))
	loadDir(filepath.Join(scanRoot, ".sentinelflow", "policies"))

	for _, pattern := range s.config.Policies.Files {
		patterns := []string{}
		if filepath.IsAbs(pattern) {
			patterns = append(patterns, pattern)
		} else {
			patterns = append(patterns, filepath.Join(scanRoot, pattern))
		}
		for _, p := range patterns {
			matches, err := filepath.Glob(p)
			if err != nil {
				loadErrs = append(loadErrs, fmt.Sprintf("glob %s: %v", p, err))
				continue
			}
			for _, path := range matches {
				loadFile(path, true)
			}
		}
	}

	if len(loadErrs) > 0 {
		return fmt.Errorf("failed to load policies: %s", strings.Join(loadErrs, "; "))
	}
	return nil
}

func parseSeverityFromRego(content string) api.Severity {
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "# severity:") {
			parts := strings.SplitN(line, "severity:", 2)
			if len(parts) == 2 {
				return api.ParseSeverity(strings.TrimSpace(parts[1]))
			}
		}
	}
	return api.SeverityMedium
}

func (s *Scanner) severityFor(name string) api.Severity {
	if sev, ok := s.severities[name]; ok {
		return sev
	}
	return api.SeverityMedium
}
