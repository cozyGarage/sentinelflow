// Package sast provides static application security testing
package sast

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/filter"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/scanner/redact"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

//go:embed rules.yaml
var rulesYAML []byte

// Scanner implements SAST rule scanning
type Scanner struct {
	config *config.Config
	rules  []Rule
}

// Rule defines a SAST detection rule
type Rule struct {
	ID          string
	Name        string
	Category    string
	Pattern     *regexp.Regexp
	PatternNot  *regexp.Regexp
	Languages   []string
	Paths       []string
	Severity    api.Severity
	Description string
	CWE         string
	OWASP       string
	Confidence  float64
}

type ruleFile struct {
	Rules []ruleDef `yaml:"rules"`
}

type ruleDef struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Category    string   `yaml:"category"`
	Pattern     string   `yaml:"pattern"`
	PatternNot  string   `yaml:"pattern-not"`
	Languages   []string `yaml:"languages"`
	Paths       []string `yaml:"paths"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	CWE         string   `yaml:"cwe"`
	OWASP       string   `yaml:"owasp"`
	Confidence  float64  `yaml:"confidence"`
}

// ScannerResult contains scan results
type ScannerResult = types.ScannerResult

// NewScanner creates a new SAST scanner
func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		config: cfg,
		rules:  loadRules(),
	}
}

func (s *Scanner) Name() string { return "sast" }

func (s *Scanner) Supports(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	// Shared regex sinks focus on these ecosystems; other extensions are omitted
	// until language-specific rules exist (honesty over empty coverage claims).
	supported := map[string]bool{
		".go": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".py": true, ".java": true,
	}
	return supported[ext]
}

func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{Findings: []api.Finding{}}

	files, err := types.ResolveFiles(path, opts, s.collectFiles)
	if err != nil {
		return nil, err
	}

	var scanFiles []string
	var warnings []string
	for _, file := range files {
		if !s.Supports(file) {
			continue
		}
		if info, err := os.Stat(file); err == nil && info.Size() > 1*1024*1024 {
			rel := file
			if r, err := filepath.Rel(path, file); err == nil {
				rel = r
			}
			warnings = append(warnings, fmt.Sprintf("skipped %s (exceeds 1MB)", filepath.ToSlash(rel)))
			continue
		}
		scanFiles = append(scanFiles, file)
	}
	result.Warnings = warnings
	result.FilesCount = len(scanFiles)

	concurrency := types.EffectiveConcurrency(opts, s.config.Scanners.SAST.Concurrency, 8)
	var mu sync.Mutex
	var scanErrs []string
	types.RunWorkers(ctx, concurrency, scanFiles, func(fp string) {
		findings, err := s.scanFile(ctx, fp, path)
		if err != nil {
			mu.Lock()
			scanErrs = append(scanErrs, fmt.Sprintf("%s: %v", fp, err))
			mu.Unlock()
			return
		}
		if len(findings) == 0 {
			return
		}
		mu.Lock()
		result.Findings = append(result.Findings, findings...)
		mu.Unlock()
	})

	result.Findings = s.filterFindings(result.Findings)
	if astFindings, err := s.scanGoAST(ctx, scanFiles, path); err != nil {
		scanErrs = append(scanErrs, err.Error())
	} else {
		result.Findings = append(result.Findings, astFindings...)
		result.Findings = s.filterFindings(result.Findings)
	}

	if len(scanErrs) > 0 {
		return result, fmt.Errorf("sast scan errors (%d): %s", len(scanErrs), strings.Join(scanErrs, "; "))
	}
	return result, nil
}

func (s *Scanner) filterFindings(findings []api.Finding) []api.Finding {
	if len(findings) == 0 {
		return findings
	}

	skip := map[string]bool{}
	if s.config != nil {
		for _, rule := range s.config.Scanners.SAST.SkipRules {
			skip[strings.TrimSpace(rule)] = true
		}
	}

	minSeverity := ""
	if s.config != nil {
		minSeverity = s.config.Scanners.SAST.Severity
	}

	var out []api.Finding
	for _, f := range findings {
		if skip[f.RuleID] || skip[f.ID] {
			continue
		}
		if minSeverity != "" && !api.MeetsMinimum(f.Severity, minSeverity) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func (s *Scanner) scanFile(ctx context.Context, filePath, basePath string) ([]api.Finding, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []api.Finding
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		lineNum++
		line := scanner.Text()

		if s.isComment(line) {
			continue
		}

		for _, rule := range s.rules {
			if !languageMatches(rule, filePath) {
				continue
			}
			if locs := rule.Pattern.FindAllStringIndex(line, -1); len(locs) > 0 {
				if rule.PatternNot != nil && rule.PatternNot.MatchString(line) {
					continue
				}
				relPath := filePath
				if rel, err := filepath.Rel(basePath, filePath); err == nil {
					relPath = rel
				}
				relPath = filepath.ToSlash(relPath)

				for _, loc := range locs {
					conf := rule.Confidence
					if conf == 0 {
						conf = 0.8
					}
					cwe := []string{}
					if rule.CWE != "" {
						cwe = []string{rule.CWE}
					}
					owasp := []string{}
					if rule.OWASP != "" {
						owasp = []string{rule.OWASP}
					}
					finding := api.Finding{
						ID:          fmt.Sprintf("SAST-%s-%s-%d", rule.ID, pathToken(relPath), lineNum),
						Type:        api.FindingTypeInsecureCode,
						Severity:    rule.Severity,
						Title:       rule.Name,
						Description: rule.Description,
						Location: api.Location{
							File:      relPath,
							StartLine: lineNum,
							EndLine:   lineNum,
							StartCol:  loc[0] + 1,
							EndCol:    loc[1] + 1,
							Snippet:   redact.Snippet(line),
						},
						Remediation: remediationFor(rule.Category),
						Scanner:     "sast",
						RuleID:      rule.ID,
						CWE:         cwe,
						OWASP:       owasp,
						Confidence:  conf,
					}
					finding.Fingerprint = fingerprint.Of(finding)
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings, scanner.Err()
}

func (s *Scanner) collectFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == ".terraform" || name == "__pycache__" || name == ".venv" ||
				name == "dist" || name == "build" || name == ".cache" {
				return filepath.SkipDir
			}
			if path != dir && (name == "testdata" || filter.IsBundledSampleDir(dir, path)) {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > 1024*1024 {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			rel = path
		}
		if filter.ShouldSkip(rel, s.config.Scanners.Exclude) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	return files, err
}

func (s *Scanner) isComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*")
}

func languageMatches(rule Rule, path string) bool {
	if len(rule.Languages) == 0 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	lang := map[string]string{
		".go": "go", ".py": "python", ".js": "javascript", ".jsx": "javascript",
		".ts": "javascript", ".tsx": "javascript", ".java": "java",
	}[ext]
	for _, l := range rule.Languages {
		if strings.EqualFold(l, lang) {
			return true
		}
	}
	return false
}

func pathToken(relPath string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(relPath))
	return fmt.Sprintf("%08x", h.Sum32())
}

func remediationFor(category string) string {
	remediations := map[string]string{
		"sqli":       "Use parameterized queries or prepared statements instead of string concatenation.",
		"xss":        "Sanitize user input and use context-appropriate output encoding.",
		"path":       "Validate and canonicalize file paths; reject traversal sequences.",
		"ssrf":       "Validate URLs against an allowlist; block internal/private IP ranges.",
		"cmd-inject": "Avoid shell execution with user input; use safe APIs with argument lists.",
	}
	if r, ok := remediations[category]; ok {
		return r
	}
	return "Review and remediate this security issue."
}

func loadRules() []Rule {
	rules, err := parseRules(rulesYAML)
	if err != nil {
		panic(fmt.Sprintf("sast: invalid embedded rules.yaml: %v", err))
	}
	return rules
}

func parseRules(data []byte) ([]Rule, error) {
	var file ruleFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if len(file.Rules) == 0 {
		return nil, fmt.Errorf("no rules defined")
	}
	out := make([]Rule, 0, len(file.Rules))
	for _, def := range file.Rules {
		if strings.TrimSpace(def.ID) == "" || strings.TrimSpace(def.Pattern) == "" {
			return nil, fmt.Errorf("rule missing id or pattern")
		}
		re, err := regexp.Compile(def.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", def.ID, err)
		}
		var not *regexp.Regexp
		if strings.TrimSpace(def.PatternNot) != "" {
			not, err = regexp.Compile(def.PatternNot)
			if err != nil {
				return nil, fmt.Errorf("rule %s pattern-not: %w", def.ID, err)
			}
		}
		out = append(out, Rule{
			ID:          def.ID,
			Name:        def.Name,
			Category:    def.Category,
			Pattern:     re,
			PatternNot:  not,
			Languages:   def.Languages,
			Paths:       def.Paths,
			Severity:    api.ParseSeverity(def.Severity),
			Description: def.Description,
			CWE:         def.CWE,
			OWASP:       def.OWASP,
			Confidence:  def.Confidence,
		})
	}
	return out, nil
}
