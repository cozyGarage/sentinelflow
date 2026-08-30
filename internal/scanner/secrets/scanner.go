// Package secrets provides secret detection scanning
package secrets

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/filter"
	"github.com/cozygarage/sentinelflow/internal/scanner/redact"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/pkg/api"
	"gopkg.in/yaml.v3"
)

// Scanner implements secret detection
type Scanner struct {
	config   *config.Config
	patterns []*SecretPattern
}

// SecretPattern defines a secret detection pattern
type SecretPattern struct {
	ID             string
	Name           string
	Pattern        *regexp.Regexp
	Severity       api.Severity
	Description    string
	Keywords       []string
	RequireKeyword bool // when true, at least one keyword must appear before regex runs
}

// NewScanner creates a new secret scanner
func NewScanner(cfg *config.Config) *Scanner {
	s := &Scanner{
		config: cfg,
	}
	s.patterns = s.loadPatterns()
	s.patterns = append(s.patterns, s.loadConfigPatterns()...)
	return s
}

// Name returns the scanner identifier
func (s *Scanner) Name() string {
	return "secrets"
}

// Supports returns true for files that should be scanned for secrets
func (s *Scanner) Supports(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".ico": true, ".svg": true, ".woff": true, ".woff2": true,
		".ttf": true, ".eot": true, ".pdf": true, ".zip": true,
		".tar": true, ".gz": true, ".rar": true, ".7z": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
	}
	return !binaryExts[ext]
}

// ScannerResult contains scan results
type ScannerResult = types.ScannerResult

// Scan performs secret detection on the target path
func (s *Scanner) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	result := &ScannerResult{
		Findings: []api.Finding{},
	}

	if _, err := s.loadConfigPatternsStrict(); err != nil {
		return nil, err
	}

	// Load .sentinelflow/patterns.yaml relative to the scan root (not process CWD).
	basePatterns := s.patterns
	filePatterns, err := s.loadFilePatterns(path)
	if err != nil {
		return nil, err
	}
	s.patterns = append(append([]*SecretPattern{}, basePatterns...), filePatterns...)
	defer func() { s.patterns = basePatterns }()

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
			msg := fmt.Sprintf("skipped %s (exceeds 1MB)", filepath.ToSlash(rel))
			warnings = append(warnings, msg)
			fmt.Fprintf(os.Stderr, "warning: secrets: %s\n", msg)
			continue
		}
		rel, _ := filepath.Rel(path, file)
		if rel == "" {
			rel = file
		}
		if filter.ShouldSkip(rel, s.config.Scanners.Secrets.Allowlist) {
			continue
		}
		scanFiles = append(scanFiles, file)
	}
	result.FilesCount = len(scanFiles)
	result.Warnings = warnings

	concurrency := types.EffectiveConcurrency(opts, s.config.Scanners.Secrets.Concurrency, 10)
	var mu sync.Mutex
	var scanErrs []string
	types.RunWorkers(ctx, concurrency, scanFiles, func(filePath string) {
		findings, err := s.scanFile(ctx, filePath, path)
		if err != nil {
			mu.Lock()
			scanErrs = append(scanErrs, fmt.Sprintf("%s: %v", filePath, err))
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

	if s.shouldScanGitHistory(path) {
		historyFindings, err := s.scanGitHistory(ctx, path)
		if err != nil {
			scanErrs = append(scanErrs, fmt.Sprintf("git history: %v", err))
		} else {
			result.Findings = append(result.Findings, historyFindings...)
		}
	}

	if len(scanErrs) > 0 {
		return result, fmt.Errorf("secrets scan errors (%d): %s", len(scanErrs), strings.Join(scanErrs, "; "))
	}
	return result, nil
}

// scanFile scans a single file for secrets
func (s *Scanner) scanFile(ctx context.Context, filePath, basePath string) ([]api.Finding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return s.scanReader(ctx, file, filePath, basePath)
}

// scanReader scans content from a reader for secrets
func (s *Scanner) scanReader(ctx context.Context, r io.Reader, filePath, basePath string) ([]api.Finding, error) {
	var findings []api.Finding
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		lineNum++
		line := scanner.Text()
		lineLower := strings.ToLower(line)

		// Check each pattern
		for _, pattern := range s.patterns {
			if pattern.RequireKeyword && !containsAnyKeyword(lineLower, pattern.Keywords) {
				continue
			}
			matches := pattern.Pattern.FindAllStringSubmatchIndex(line, -1)
			for _, loc := range matches {
				if len(loc) < 2 {
					continue
				}
				start, end := loc[0], loc[1]
				secret := line[start:end]

				// Prefer the last capture group as the secret value so placeholder
				// and entropy checks are not skewed by keywords in the full match.
				secretValue := secret
				if n := len(loc); n >= 4 {
					gs, ge := loc[n-2], loc[n-1]
					if gs >= 0 && ge > gs {
						secretValue = line[gs:ge]
					}
				}

				// Skip if it looks like a placeholder
				if s.isPlaceholder(secretValue) {
					continue
				}

				// Additional entropy check for generic patterns
				if pattern.ID == "generic-secret" && s.calculateEntropy(secretValue) < s.config.Scanners.Secrets.EntropyThreshold {
					continue
				}

				relPath := filePath
				if basePath != "" {
					rel, err := filepath.Rel(basePath, filePath)
					if err == nil {
						relPath = rel
					}
				}
				relPath = filepath.ToSlash(relPath)

				finding := api.Finding{
					ID:          fmt.Sprintf("SEC-%s-%s-%d-%d", pattern.ID, pathToken(relPath), lineNum, start+1),
					Type:        api.FindingTypeSecret,
					Severity:    pattern.Severity,
					Title:       fmt.Sprintf("Potential %s detected", pattern.Name),
					Description: pattern.Description,
					Location: api.Location{
						File:      relPath,
						StartLine: lineNum,
						EndLine:   lineNum,
						StartCol:  start + 1,
						EndCol:    end + 1,
						Snippet:   s.maskSecret(line, start, end),
					},
					Remediation: s.getRemediation(pattern),
					Scanner:     "secrets",
					RuleID:      pattern.ID,
					Confidence:  0.9,
				}

				findings = append(findings, finding)
			}
		}

		// Check for high-entropy strings
		if entropyFindings := s.checkHighEntropy(line, lineNum, filePath, basePath); len(entropyFindings) > 0 {
			findings = append(findings, entropyFindings...)
		}
	}

	return findings, scanner.Err()
}

// loadPatterns loads all secret detection patterns
func (s *Scanner) loadPatterns() []*SecretPattern {
	return []*SecretPattern{
		// AWS
		{
			ID:          "aws-access-key",
			Name:        "AWS Access Key ID",
			Pattern:     regexp.MustCompile(`(?i)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`),
			Severity:    api.SeverityCritical,
			Description: "AWS Access Key ID found in code",
			Keywords:    []string{"aws", "access", "key"},
		},
		{
			ID:             "aws-secret-key",
			Name:           "AWS Secret Access Key",
			Pattern:        regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]["']?([A-Za-z0-9/+=]{40})["']?`),
			Severity:       api.SeverityCritical,
			Description:    "AWS Secret Access Key found in code",
			Keywords:       []string{"aws"},
			RequireKeyword: true,
		},
		// GCP
		{
			ID:          "gcp-api-key",
			Name:        "Google Cloud API Key",
			Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			Severity:    api.SeverityCritical,
			Description: "Google Cloud API Key found in code",
			Keywords:    []string{"google", "gcp", "api"},
		},
		{
			ID:             "gcp-service-account",
			Name:           "GCP Service Account",
			Pattern:        regexp.MustCompile(`"type"\s*:\s*"service_account"`),
			Severity:       api.SeverityHigh,
			Description:    "GCP Service Account credentials file detected",
			Keywords:       []string{"service_account"},
			RequireKeyword: true,
		},
		// Azure
		{
			ID:             "azure-storage-key",
			Name:           "Azure Storage Account Key",
			Pattern:        regexp.MustCompile(`(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{88})`),
			Severity:       api.SeverityCritical,
			Description:    "Azure Storage Account Key found in code",
			Keywords:       []string{"accountkey"},
			RequireKeyword: true,
		},
		// GitHub
		{
			ID:          "github-token",
			Name:        "GitHub Token",
			Pattern:     regexp.MustCompile(`(ghp|gho|ghr)_[A-Za-z0-9_]{36,255}`),
			Severity:    api.SeverityCritical,
			Description: "GitHub personal access token or OAuth/refresh token found",
			Keywords:    []string{"github", "token"},
		},
		{
			ID:          "github-app-token",
			Name:        "GitHub App Token",
			Pattern:     regexp.MustCompile(`(ghu|ghs)_[A-Za-z0-9_]{36,255}`),
			Severity:    api.SeverityHigh,
			Description: "GitHub App user-to-server or installation token found",
			Keywords:    []string{"github", "app", "token"},
		},
		// GitLab
		{
			ID:          "gitlab-token",
			Name:        "GitLab Token",
			Pattern:     regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20,}`),
			Severity:    api.SeverityCritical,
			Description: "GitLab personal access token found",
			Keywords:    []string{"gitlab", "token"},
		},
		// Slack
		{
			ID:          "slack-token",
			Name:        "Slack Token",
			Pattern:     regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
			Severity:    api.SeverityHigh,
			Description: "Slack API token found in code",
			Keywords:    []string{"slack", "token"},
		},
		{
			ID:             "slack-webhook",
			Name:           "Slack Webhook URL",
			Pattern:        regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`),
			Severity:       api.SeverityMedium,
			Description:    "Slack webhook URL found in code",
			Keywords:       []string{"hooks.slack.com"},
			RequireKeyword: true,
		},
		// Stripe
		{
			ID:          "stripe-secret-key",
			Name:        "Stripe Secret Key",
			Pattern:     regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
			Severity:    api.SeverityCritical,
			Description: "Stripe live secret key found in code",
			Keywords:    []string{"stripe", "key"},
		},
		{
			ID:          "stripe-publishable-key",
			Name:        "Stripe Publishable Key",
			Pattern:     regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`),
			Severity:    api.SeverityMedium,
			Description: "Stripe live publishable key found in code",
			Keywords:    []string{"stripe", "key"},
		},
		// Twilio
		{
			ID:          "twilio-api-key",
			Name:        "Twilio API Key",
			Pattern:     regexp.MustCompile(`SK[a-fA-F0-9]{32}`),
			Severity:    api.SeverityHigh,
			Description: "Twilio API Key found in code",
			Keywords:    []string{"twilio"},
		},
		// SendGrid
		{
			ID:          "sendgrid-api-key",
			Name:        "SendGrid API Key",
			Pattern:     regexp.MustCompile(`SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`),
			Severity:    api.SeverityHigh,
			Description: "SendGrid API Key found in code",
			Keywords:    []string{"sendgrid"},
		},
		// Private Keys
		{
			ID:             "private-key",
			Name:           "Private Key",
			Pattern:        regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----`),
			Severity:       api.SeverityCritical,
			Description:    "Private key file content detected",
			Keywords:       []string{"begin", "private key"},
			RequireKeyword: true,
		},
		// JWT
		{
			ID:          "jwt-token",
			Name:        "JWT Token",
			Pattern:     regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`),
			Severity:    api.SeverityMedium,
			Description: "JWT token found in code (may contain sensitive claims)",
			Keywords:    []string{"jwt", "token", "bearer"},
		},
		// Generic
		{
			ID:             "generic-api-key",
			Name:           "Generic API Key",
			Pattern:        regexp.MustCompile(`(?i)(api[_\-]?key|apikey|api_secret)[\s]*[=:][\s]*["']?([A-Za-z0-9_\-]{20,})["']?`),
			Severity:       api.SeverityHigh,
			Description:    "Generic API key pattern detected",
			Keywords:       []string{"api"},
			RequireKeyword: true,
		},
		{
			ID:             "generic-secret",
			Name:           "Generic Secret",
			Pattern:        regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|auth)[\s]*[=:][\s]*["']([^"']{8,})["']`),
			Severity:       api.SeverityHigh,
			Description:    "Hardcoded secret detected",
			Keywords:       []string{"password", "passwd", "pwd", "secret", "token", "auth"},
			RequireKeyword: true,
		},
		// Database connection strings
		{
			ID:             "database-url",
			Name:           "Database Connection String",
			Pattern:        regexp.MustCompile(`(?i)(mysql|postgres|postgresql|mongodb|redis|mongodb\+srv):\/\/[^:]+:[^@]+@[^\/]+`),
			Severity:       api.SeverityHigh,
			Description:    "Database connection string with credentials found",
			Keywords:       []string{"mysql://", "postgres://", "postgresql://", "mongodb://", "redis://", "mongodb+srv://"},
			RequireKeyword: true,
		},
		// Heroku
		{
			ID:             "heroku-api-key",
			Name:           "Heroku API Key",
			Pattern:        regexp.MustCompile(`(?i)heroku[_\-]?api[_\-]?key[\s]*[=:][\s]*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']?`),
			Severity:       api.SeverityHigh,
			Description:    "Heroku API Key found in code",
			Keywords:       []string{"heroku"},
			RequireKeyword: true,
		},
		// npm
		{
			ID:             "npm-token",
			Name:           "NPM Token",
			Pattern:        regexp.MustCompile(`(?i)//registry\.npmjs\.org/:_authToken=([A-Za-z0-9\-_]+)`),
			Severity:       api.SeverityHigh,
			Description:    "NPM authentication token found",
			Keywords:       []string{"npmjs.org", "_authtoken"},
			RequireKeyword: true,
		},
		// Discord
		{
			ID:          "discord-token",
			Name:        "Discord Bot Token",
			Pattern:     regexp.MustCompile(`[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`),
			Severity:    api.SeverityHigh,
			Description: "Discord bot token found in code",
			Keywords:    []string{"discord", "bot"},
		},
		// Telegram
		{
			ID:          "telegram-bot-token",
			Name:        "Telegram Bot Token",
			Pattern:     regexp.MustCompile(`[0-9]+:AA[A-Za-z0-9_-]{33}`),
			Severity:    api.SeverityHigh,
			Description: "Telegram bot token found in code",
			Keywords:    []string{"telegram", "bot"},
		},
	}
}

// collectFiles recursively collects files from a directory
func (s *Scanner) collectFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories we shouldn't scan
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == ".terraform" || name == "__pycache__" || name == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip large files
		if info.Size() > 1024*1024 { // 1MB
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			rel = path
		}
		if filter.ShouldSkip(rel, s.config.Scanners.Secrets.Allowlist) {
			return nil
		}

		files = append(files, path)
		return nil
	})

	return files, err
}

// isPlaceholder checks if a secret looks like a placeholder value
func (s *Scanner) isPlaceholder(secret string) bool {
	placeholders := []string{
		"xxx", "your-", "your_", "<your", "replace",
		"example", "dummy", "changeme", "placeholder",
		"insert", "todo", "fixme",
	}

	lower := strings.ToLower(strings.TrimSpace(secret))
	// Exact matches for generic words that commonly appear as literal placeholders.
	// Avoid substring matching here — real secrets often contain these words.
	switch lower {
	case "secret", "password", "token", "key", "apikey", "api_key", "passwd", "pwd":
		return true
	}
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true
		}
	}

	// Check for repetitive characters (e.g., "aaaaaaa", "1234567")
	if len(secret) >= 8 && s.calculateEntropy(secret) < 2.0 {
		return true
	}

	return false
}

// calculateEntropy calculates the Shannon entropy of a string
func (s *Scanner) calculateEntropy(str string) float64 {
	if len(str) == 0 {
		return 0
	}

	charCount := make(map[rune]int)
	for _, c := range str {
		charCount[c]++
	}

	entropy := 0.0
	strLen := float64(len(str))

	for _, count := range charCount {
		freq := float64(count) / strLen
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// checkHighEntropy looks for high-entropy strings that might be secrets
func (s *Scanner) checkHighEntropy(line string, lineNum int, filePath, basePath string) []api.Finding {
	var findings []api.Finding

	// Look for potential base64 or hex encoded secrets
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`[=:]["']([A-Za-z0-9+/]{40,}={0,2})["']`), // Base64
		regexp.MustCompile(`[=:]["']([a-fA-F0-9]{32,})["']`),         // Hex
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatchIndex(line, -1)
		for matchIdx, loc := range matches {
			if len(loc) < 4 {
				continue
			}
			secret := line[loc[2]:loc[3]]
			entropy := s.calculateEntropy(secret)

			if entropy >= s.config.Scanners.Secrets.EntropyThreshold && !s.isPlaceholder(secret) {
				relPath := filePath
				if basePath != "" {
					if rel, err := filepath.Rel(basePath, filePath); err == nil {
						relPath = rel
					}
				}
				relPath = filepath.ToSlash(relPath)

				finding := api.Finding{
					ID:          fmt.Sprintf("SEC-entropy-%s-%d-%d", pathToken(relPath), lineNum, loc[2]+1),
					Type:        api.FindingTypeSecret,
					Severity:    api.SeverityMedium,
					Title:       "High-entropy string detected",
					Description: fmt.Sprintf("High-entropy string (%.2f bits) may be a secret", entropy),
					Location: api.Location{
						File:      relPath,
						StartLine: lineNum,
						EndLine:   lineNum,
						StartCol:  loc[2] + 1,
						EndCol:    loc[3] + 1,
						Snippet:   s.maskSecret(line, 0, len(line)),
					},
					Remediation: "Review this string and move to environment variables if it's a secret",
					Scanner:     "secrets",
					RuleID:      "high-entropy",
					Confidence:  0.7,
					Metadata: map[string]any{
						"entropy": entropy,
						"match":   matchIdx,
					},
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// maskSecret masks the secret in the line for safe display
func (s *Scanner) maskSecret(line string, start, end int) string {
	return redact.Substring(line, start, end)
}

// getRemediation returns remediation advice for a secret type
func (s *Scanner) getRemediation(pattern *SecretPattern) string {
	remediations := map[string]string{
		"aws-access-key": "Remove the AWS access key from code. Use IAM roles or environment variables instead. Rotate the exposed key immediately.",
		"aws-secret-key": "Remove the AWS secret key from code. Use IAM roles, AWS Secrets Manager, or environment variables. Rotate the key immediately.",
		"gcp-api-key":    "Remove the GCP API key from code. Use service accounts or restrict the API key. Rotate if exposed.",
		"github-token":   "Remove the GitHub token from code. Use GitHub Actions secrets or environment variables. Revoke and regenerate the token.",
		"private-key":    "Never commit private keys to source control. Use secret management solutions or environment variables.",
		"generic-secret": "Move hardcoded secrets to environment variables or a secret management solution like HashiCorp Vault.",
		"database-url":   "Use environment variables for database connection strings. Never commit credentials to source control.",
	}

	if remediation, ok := remediations[pattern.ID]; ok {
		return remediation
	}

	return "Remove hardcoded secrets from code. Use environment variables or a secret management solution."
}

// shouldScanGitHistory checks if git history scanning is enabled
func (s *Scanner) shouldScanGitHistory(path string) bool {
	if s.config.Git.ScanHistory || s.config.Scanners.Secrets.ScanGitHistory {
		gitDir := filepath.Join(path, ".git")
		if _, err := os.Stat(gitDir); err == nil {
			return true
		}
	}
	return false
}

// scanGitHistory scans past commits for secrets using patch hunks (added lines only).
func (s *Scanner) scanGitHistory(ctx context.Context, path string) ([]api.Finding, error) {
	depth := secretsHistoryDepth(s.config)
	if depth <= 0 {
		depth = 50
	}

	cmd := exec.CommandContext(ctx, "git", "-C", path, "log", "-p", "--pretty=format:COMMIT:%H", "--unified=0", "-n", strconv.Itoa(depth))
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log failed: %w", err)
	}

	const maxPatchBytes = 2 * 1024 * 1024
	truncated := false
	if len(output) > maxPatchBytes {
		output = output[:maxPatchBytes]
		truncated = true
	}

	var findings []api.Finding
	seen := make(map[string]bool)
	commit := ""
	file := ""
	lineNum := 0

	scanner := bufio.NewScanner(bytes.NewReader(output))
	// Allow large diff lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "COMMIT:"):
			commit = strings.TrimPrefix(line, "COMMIT:")
			file = ""
			lineNum = 0
		case strings.HasPrefix(line, "+++ b/"):
			file = strings.TrimPrefix(line, "+++ b/")
			if file == "/dev/null" {
				file = ""
			}
			lineNum = 0
		case strings.HasPrefix(line, "@@"):
			// @@ -a,b +c,d @@
			lineNum = parseDiffNewLine(line)
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			if file == "" || !s.Supports(file) || filter.ShouldSkip(file, s.config.Scanners.Secrets.Allowlist) {
				continue
			}
			content := line[1:]
			lineNum++
			virtualPath := file
			if len(commit) >= 8 {
				virtualPath = fmt.Sprintf("%s@%s", file, commit[:8])
			}
			fileFindings, _ := s.scanReader(ctx, strings.NewReader(content+"\n"), virtualPath, "")
			for i := range fileFindings {
				fileFindings[i].Location.StartLine = lineNum
				fileFindings[i].Location.EndLine = lineNum
				// scanReader sees a one-line buffer so IDs end in -1; remint with the hunk line.
				fileFindings[i].ID = fmt.Sprintf("SEC-%s-%s-%d-%d", fileFindings[i].RuleID, pathToken(virtualPath), lineNum, fileFindings[i].Location.StartCol)
				fileFindings[i].Metadata = map[string]any{
					"git_commit": commit,
					"git_file":   file,
				}
				fileFindings[i].Description += fmt.Sprintf(" (found in commit %s)", shortCommit(commit))
				key := fileFindings[i].RuleID + "|" + file + "|" + fileFindings[i].Location.Snippet
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, fileFindings[i])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return findings, err
	}
	if truncated {
		return findings, fmt.Errorf("git history patch truncated at %d bytes; results may be incomplete", maxPatchBytes)
	}
	return findings, nil
}

func shortCommit(commit string) string {
	if len(commit) >= 8 {
		return commit[:8]
	}
	return commit
}

func parseDiffNewLine(hunk string) int {
	// @@ -old +new @@ or @@ -old +new,count @@
	parts := strings.Split(hunk, " ")
	for _, p := range parts {
		if strings.HasPrefix(p, "+") {
			num := strings.TrimPrefix(p, "+")
			if idx := strings.IndexByte(num, ','); idx >= 0 {
				num = num[:idx]
			}
			n, err := strconv.Atoi(num)
			if err == nil {
				return n - 1 // incremented when consuming added lines
			}
		}
	}
	return 0
}

func containsAnyKeyword(lineLower string, keywords []string) bool {
	for _, kw := range keywords {
		if kw == "" {
			continue
		}
		if strings.Contains(lineLower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// customPatternFile represents the .sentinelflow/patterns.yaml format
type customPatternFile struct {
	Patterns []customPatternEntry `yaml:"patterns"`
}

type customPatternEntry struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Regex       string `yaml:"regex"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

// loadCustomPatterns loads patterns from .sentinelflow/patterns.yaml
func (s *Scanner) loadCustomPatterns() []*SecretPattern {
	patterns, _ := s.loadFilePatterns(".")
	configPatterns, _ := s.loadConfigPatternsStrict()
	return append(patterns, configPatterns...)
}

// loadFilePatterns loads .sentinelflow/patterns.yaml from the scan root.
// Missing files are OK; invalid YAML or regexes return an error (no silent skip).
func (s *Scanner) loadFilePatterns(scanRoot string) ([]*SecretPattern, error) {
	paths := []string{
		filepath.Join(scanRoot, ".sentinelflow", "patterns.yaml"),
		filepath.Join(scanRoot, ".sentinelflow", "patterns.yml"),
	}
	var patterns []*SecretPattern

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read patterns file %s: %w", p, err)
		}

		var file customPatternFile
		if err := yaml.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("invalid patterns file %s: %w", p, err)
		}

		for _, entry := range file.Patterns {
			if entry.Regex == "" {
				continue
			}
			re, err := regexp.Compile(entry.Regex)
			if err != nil {
				id := entry.ID
				if id == "" {
					id = entry.Name
				}
				return nil, fmt.Errorf("invalid pattern %q in %s: %w", id, p, err)
			}
			id := entry.ID
			if id == "" {
				id = fmt.Sprintf("custom-file-%d", len(patterns)+1)
			}
			patterns = append(patterns, &SecretPattern{
				ID:          id,
				Name:        entry.Name,
				Pattern:     re,
				Severity:    api.ParseSeverity(entry.Severity),
				Description: entry.Description,
			})
		}
		return patterns, nil // first file wins
	}
	return patterns, nil
}

// loadConfigPatterns compiles scanners.secrets.patterns (best-effort for NewScanner).
func (s *Scanner) loadConfigPatterns() []*SecretPattern {
	patterns, _ := s.loadConfigPatternsStrict()
	return patterns
}

func (s *Scanner) loadConfigPatternsStrict() ([]*SecretPattern, error) {
	var patterns []*SecretPattern
	for i, pat := range s.config.Scanners.Secrets.Patterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("invalid scanners.secrets.patterns[%d]: %w", i, err)
		}
		patterns = append(patterns, &SecretPattern{
			ID:          fmt.Sprintf("custom-%d", len(patterns)+1),
			Name:        "Custom Pattern",
			Pattern:     re,
			Severity:    api.SeverityHigh,
			Description: "Custom secret pattern from configuration",
		})
	}
	return patterns, nil
}

func pathToken(relPath string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(filepath.ToSlash(relPath)))
	return fmt.Sprintf("%08x", h.Sum32())
}

func secretsHistoryDepth(cfg *config.Config) int {
	if cfg == nil {
		return 50
	}
	// Prefer secrets.max_history_depth when secrets.scan_git_history is the enabler.
	if cfg.Scanners.Secrets.ScanGitHistory && cfg.Scanners.Secrets.MaxHistoryDepth > 0 {
		if !cfg.Git.ScanHistory {
			return cfg.Scanners.Secrets.MaxHistoryDepth
		}
	}
	if cfg.Git.HistoryDepth > 0 {
		return cfg.Git.HistoryDepth
	}
	if cfg.Scanners.Secrets.MaxHistoryDepth > 0 {
		return cfg.Scanners.Secrets.MaxHistoryDepth
	}
	return 50
}
