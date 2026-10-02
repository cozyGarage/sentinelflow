package secrets

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/testutil"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Helper to scan string content
func (s *Scanner) scanContent(content, filename string, _ int) []api.Finding {
	findings, _ := s.scanReader(context.Background(), strings.NewReader(content), filename, "")
	return findings
}

func TestKeywordPrefilterSkipsIrrelevantLines(t *testing.T) {
	scanner := NewScanner(&config.Config{})
	// Line with high-entropy-looking value but no password/secret keyword should not match generic-secret
	content := `normal_config = "abcdefghijklmnop"`
	findings := scanner.scanContent(content, "cfg.env", 1)
	for _, f := range findings {
		if f.RuleID == "generic-secret" {
			t.Fatalf("generic-secret should require keyword prefilter, got %+v", f)
		}
	}

	content = `password = "Kx9#mP2$vL8@nQ4wZr"`
	findings = scanner.scanContent(content, "cfg.env", 1)
	found := false
	for _, f := range findings {
		if f.RuleID == "generic-secret" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected generic-secret when keyword present")
	}
}

func TestParseDiffNewLine(t *testing.T) {
	if got := parseDiffNewLine("@@ -10,0 +42,2 @@"); got != 41 {
		t.Fatalf("got %d", got)
	}
}

func TestDetectAWSKeys(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewScanner(cfg)

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "AWS access key",
			content:  "AKIA" + "IOSFODNN7REALKEY",
			expected: true,
		},
		{
			name:     "AWS secret key",
			content:  "aws_secret_access_key" + "=\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYREALKEY123\"",
			expected: true,
		},
		{
			name:     "No secret",
			content:  "this is just normal text",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.scanContent(tt.content, "test.txt", 0)
			found := len(findings) > 0

			if found != tt.expected {
				t.Errorf("Expected %v findings, got %v for %s", tt.expected, found, tt.content)
			}
		})
	}
}

func TestGitHubToken(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewScanner(cfg)

	content := "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz12"
	findings := scanner.scanContent(content, "test.txt", 0)

	if len(findings) == 0 {
		t.Error("Expected to detect GitHub token")
	} else {
		if findings[0].Type != api.FindingTypeSecret {
			t.Errorf("Expected FindingTypeSecret, got %s", findings[0].Type)
		}

		if findings[0].Severity != api.SeverityCritical {
			t.Errorf("Expected critical severity, got %s", findings[0].Severity)
		}
	}
}

func TestEntropyDetection(t *testing.T) {
	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{
				EntropyThreshold: 4.5,
			},
		},
	}
	scanner := NewScanner(cfg)

	// High entropy string that matches ONLY the high-entropy regex ([=:]["']...)
	// but DOES NOT trigger the specific ID rules (like generic-api-key)
	// Base64 must be at least 40 chars and NOT contain spaces.
	keyName := "random" + "Data"
	secretVal := "aGZnc2RmZ3NkZmc3ODY4NzZIZmRzYWZkczIxaEpsS0ptSzhsbE05TjlONjhCN0I2VjVWMzI="
	highEntropy := fmt.Sprintf("%s=\"%s\"", keyName, secretVal)

	findings := scanner.scanContent(highEntropy, "test.txt", 0)

	// Should detect based on entropy
	found := false
	for _, f := range findings {
		if f.RuleID == "high-entropy" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected to detect high-entropy string in: %s", highEntropy)
		for _, f := range findings {
			t.Logf("Found instead: %s (Rule: %s)", f.Title, f.RuleID)
		}
	}
}

func TestPlaceholderExclusion(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewScanner(cfg)

	// Common placeholders that should NOT be detected
	placeholders := []string{
		"YOUR_API_KEY_HERE",
		"example.com",
		"test@example.com",
		"<your-secret-key>",
		"xxx-xxx-xxxx",
	}

	for _, placeholder := range placeholders {
		findings := scanner.scanContent(placeholder, "test.txt", 0)

		for _, f := range findings {
			if f.Severity == api.SeverityCritical {
				t.Errorf("Placeholder '%s' should not be detected as critical: %s", placeholder, f.Title)
			}
		}
	}
}

func TestMasking(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewScanner(cfg)

	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	// Find the secret location to pass correct indices
	match := "AKIAIOSFODNN7EXAMPLE"
	start := 0
	end := len(match)

	masked := scanner.maskSecret(secret, start, end)

	// Should be masked
	if masked == secret {
		t.Error("Secret was not masked")
	}

	// Should contain asterisks
	if len(masked) == 0 {
		t.Error("Masked secret is empty")
	}

	// Should preserve some characters for context (or just be asterisks depending on impl)
	// The implementation masks with 8 asterisks max
	if !contains(masked, "*") {
		t.Error("Masked secret should contain asterisks")
	}
}

func TestSecretsFixtures(t *testing.T) {
	cfg := config.Default()
	scanner := NewScanner(cfg)

	tokens := string(testutil.ReadFixture(t, "secrets/leaked_tokens.env"))
	findings := scanner.scanContent(tokens, "leaked_tokens.env", 0)
	if len(findings) == 0 {
		t.Fatal("expected findings from leaked_tokens.env fixture")
	}
	found := false
	for _, f := range findings {
		if f.RuleID == "github-token" || f.RuleID == "generic-secret" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected github-token or generic-secret from fixture, got %+v", findings)
	}

	placeholders := string(testutil.ReadFixture(t, "secrets/placeholders.env"))
	for _, f := range scanner.scanContent(placeholders, "placeholders.env", 0) {
		if f.Severity == api.SeverityCritical {
			t.Errorf("placeholder fixture should not yield critical finding: %s", f.Title)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && strings.Contains(s, substr)
}

// Regressions from scanning SentinelFlow's own binary: printable-string runs of
// Go literals produced a "critical AWS key" and a fake DB URL.
func TestPatternsRejectConcatenatedLiterals(t *testing.T) {
	scanner := NewScanner(&config.Config{})
	hasRule := func(content, rule string) bool {
		for _, f := range scanner.scanContent(content, "test.txt", 0) {
			if f.RuleID == rule {
				return true
			}
		}
		return false
	}
	cases := []struct {
		content, rule string
		want          bool
	}{
		{"ArabianDiacriticalAcuteAccent", "aws-access-key", false},
		{"key = " + "akia" + "iosfodnn7realkey", "aws-access-key", false},
		{"key = " + "AKIA" + "IOSFODNN7REALKEY", "aws-access-key", true},
		{"mongodb://_authtokencloudflaregit_commitcache missstream end:x@y", "database-url", false},
		{"postgres://" + "app:s3cr3t@db.internal:5432/prod", "database-url", true},
	}
	for _, c := range cases {
		if got := hasRule(c.content, c.rule); got != c.want {
			t.Errorf("%s on %q: got %v, want %v", c.rule, c.content, got, c.want)
		}
	}
}
