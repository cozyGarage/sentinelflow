// Package config handles SentinelFlow configuration management
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// AINotAvailableMessage is the shared rejection text for --ai / scanners.ai.enabled.
const AINotAvailableMessage = "AI-powered code review is not available in this release (planned); omit --ai and keep scanners.ai.enabled: false"

// Config represents the SentinelFlow configuration
type Config struct {
	Version      string         `yaml:"version" mapstructure:"version"`
	ScanTimeout  string         `yaml:"scan_timeout" mapstructure:"scan_timeout"` // e.g. "10m", "90s"
	Scanners     ScannersConfig `yaml:"scanners" mapstructure:"scanners"`
	Policies     PoliciesConfig `yaml:"policies" mapstructure:"policies"`
	Reporting    ReportConfig   `yaml:"reporting" mapstructure:"reporting"`
	FailOn       FailOnConfig   `yaml:"fail_on" mapstructure:"fail_on"`
	Git          GitConfig      `yaml:"git" mapstructure:"git"`
	Baseline     BaselineConfig `yaml:"baseline" mapstructure:"baseline"`
}

// ScannersConfig contains settings for all scanners
type ScannersConfig struct {
	Concurrency  int                 `yaml:"concurrency" mapstructure:"concurrency"`
	// Exclude is a global path skip list applied by the engine (and shared walks).
	// Secrets-specific skips belong in scanners.secrets.allowlist.
	Exclude      []string            `yaml:"exclude" mapstructure:"exclude"`
	Secrets      SecretsConfig      `yaml:"secrets" mapstructure:"secrets"`
	IaC          IaCConfig          `yaml:"iac" mapstructure:"iac"`
	Dependencies DependenciesConfig `yaml:"dependencies" mapstructure:"dependencies"`
	SAST         SASTConfig         `yaml:"sast" mapstructure:"sast"`
	Container    ContainerConfig    `yaml:"container" mapstructure:"container"`
	License      LicenseConfig      `yaml:"license" mapstructure:"license"`
	AI           AIConfig           `yaml:"ai" mapstructure:"ai"`
}

// SecretsConfig configures the secret scanner
type SecretsConfig struct {
	Enabled          bool     `yaml:"enabled" mapstructure:"enabled"`
	Allowlist        []string `yaml:"allowlist" mapstructure:"allowlist"`
	Patterns         []string `yaml:"patterns" mapstructure:"patterns"`
	EntropyThreshold float64  `yaml:"entropy_threshold" mapstructure:"entropy_threshold"`
	ScanGitHistory   bool     `yaml:"scan_git_history" mapstructure:"scan_git_history"`
	MaxHistoryDepth  int      `yaml:"max_history_depth" mapstructure:"max_history_depth"`
	Concurrency      int      `yaml:"concurrency" mapstructure:"concurrency"`
}

// IaCConfig configures the Infrastructure-as-Code scanner
type IaCConfig struct {
	Enabled     bool     `yaml:"enabled" mapstructure:"enabled"`
	Frameworks  []string `yaml:"frameworks" mapstructure:"frameworks"`
	Severity    string   `yaml:"severity" mapstructure:"severity"`
	SkipRules   []string `yaml:"skip_rules" mapstructure:"skip_rules"`
	Concurrency int      `yaml:"concurrency" mapstructure:"concurrency"`
}

// DependenciesConfig configures the dependency vulnerability scanner
type DependenciesConfig struct {
	Enabled    bool     `yaml:"enabled" mapstructure:"enabled"`
	Ecosystems []string `yaml:"ecosystems" mapstructure:"ecosystems"`
	Severity   string   `yaml:"severity" mapstructure:"severity"`
	IgnoreDev  bool     `yaml:"ignore_dev" mapstructure:"ignore_dev"`
	IgnoreCVEs []string `yaml:"ignore_cves" mapstructure:"ignore_cves"`
	// FailOnError fails the scan CLI when the dependencies scanner returns an
	// error (e.g. OSV network blips). Default true. Set false to keep findings
	// and report ScannerRun.Error without failing CI solely for transport errors.
	FailOnError *bool `yaml:"fail_on_error" mapstructure:"fail_on_error"`
}

// DependenciesFailOnError returns whether dependency scanner errors should fail the CLI.
func (c *Config) DependenciesFailOnError() bool {
	if c.Scanners.Dependencies.FailOnError == nil {
		return true
	}
	return *c.Scanners.Dependencies.FailOnError
}

// SASTConfig configures static application security testing
type SASTConfig struct {
	Enabled     bool     `yaml:"enabled" mapstructure:"enabled"`
	Severity    string   `yaml:"severity" mapstructure:"severity"`
	SkipRules   []string `yaml:"skip_rules" mapstructure:"skip_rules"`
	Concurrency int      `yaml:"concurrency" mapstructure:"concurrency"`
}

// ContainerConfig configures container image scanning
type ContainerConfig struct {
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
	Image    string `yaml:"image" mapstructure:"image"`
	Severity string `yaml:"severity" mapstructure:"severity"`
}

// LicenseConfig configures license policy scanning
type LicenseConfig struct {
	Enabled bool     `yaml:"enabled" mapstructure:"enabled"`
	Denied  []string `yaml:"denied" mapstructure:"denied"`
	Allowed []string `yaml:"allowed" mapstructure:"allowed"`
}

// BaselineConfig configures finding baselines
type BaselineConfig struct {
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
	File    string `yaml:"file" mapstructure:"file"`
}

// AIConfig configures the AI-powered code review
type AIConfig struct {
	Enabled     bool     `yaml:"enabled" mapstructure:"enabled"`
	Provider    string   `yaml:"provider" mapstructure:"provider"`
	Model       string   `yaml:"model" mapstructure:"model"`
	APIKey      string   `yaml:"api_key" mapstructure:"api_key"`
	BaseURL     string   `yaml:"base_url" mapstructure:"base_url"`
	Focus       []string `yaml:"focus" mapstructure:"focus"`
	MaxFileSize int      `yaml:"max_file_size" mapstructure:"max_file_size"`
	Concurrency int      `yaml:"concurrency" mapstructure:"concurrency"`
}

// PoliciesConfig configures policy-as-code
type PoliciesConfig struct {
	Enabled bool     `yaml:"enabled" mapstructure:"enabled"`
	Files   []string `yaml:"files" mapstructure:"files"`
	Builtin []string `yaml:"builtin" mapstructure:"builtin"`
}

// ReportConfig configures report generation
type ReportConfig struct {
	Format string `yaml:"format" mapstructure:"format"`
}

// FailOnConfig configures when the scan should fail
type FailOnConfig struct {
	Severity         string `yaml:"severity" mapstructure:"severity"`
	Secrets          bool   `yaml:"secrets" mapstructure:"secrets"`
	PolicyViolations bool   `yaml:"policy_violations" mapstructure:"policy_violations"`
}

// GitConfig configures git-related settings
type GitConfig struct {
	ScanHistory  bool `yaml:"scan_history" mapstructure:"scan_history"`
	HistoryDepth int  `yaml:"history_depth" mapstructure:"history_depth"`
}

// LoadFile loads configuration from an explicit file path (--config).
func LoadFile(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.AutomaticEnv()
	v.SetEnvPrefix("SENTINELFLOW")
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}
	return unmarshalConfig(v)
}

// LoadFromDir loads .sentinelflow.yaml from dir (preferred), then falls back to
// the process working directory. Environment variables (SENTINELFLOW_*) still apply.
// Pass an absolute scan target directory so `sentinelflow scan /other/repo` uses
// that repo's config instead of only the caller's CWD.
func LoadFromDir(dir string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigName(".sentinelflow")
	if dir != "" {
		v.AddConfigPath(dir)
	}
	// Secondary search path so local overrides still work when scanning a subdir.
	v.AddConfigPath(".")
	v.AutomaticEnv()
	v.SetEnvPrefix("SENTINELFLOW")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok && !os.IsNotExist(err) {
			return nil, err
		}
	}

	return unmarshalConfig(v)
}

func unmarshalConfig(v *viper.Viper) (*Config, error) {
	cfg := Default()
	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}

	if cfg.Scanners.AI.APIKey == "" {
		cfg.Scanners.AI.APIKey = os.Getenv("SENTINELFLOW_AI_API_KEY")
		if cfg.Scanners.AI.APIKey == "" {
			cfg.Scanners.AI.APIKey = os.Getenv("OPENAI_API_KEY")
		}
	}

	return cfg, nil
}

// ConfigDirForTarget returns the directory that should own .sentinelflow.yaml
// for a scan target (directory itself, or parent of a file).
func ConfigDirForTarget(target string) string {
	info, err := os.Stat(target)
	if err != nil {
		return filepath.Clean(target)
	}
	if info.IsDir() {
		return filepath.Clean(target)
	}
	return filepath.Dir(target)
}

// Default returns the default configuration
func Default() *Config {
	return &Config{
		Version:     "1.0",
		ScanTimeout: "10m",
		Scanners: ScannersConfig{
			Concurrency: 8,
			Exclude: []string{
				"test/**",
				"**/testdata/**",
				"**/*_test.go",
				"**/*_bench_test.go",
			},
			Secrets: SecretsConfig{
				Enabled:          true,
				EntropyThreshold: 4.5,
				MaxHistoryDepth:  50,
				Concurrency:      10,
				Allowlist: []string{
					"**/*_test.go",
					"**/*.test.js",
					"**/*.spec.ts",
				},
			},
			IaC: IaCConfig{
				Enabled:     true,
				Severity:    "medium",
				Concurrency: 5,
				Frameworks:  []string{"terraform", "kubernetes", "dockerfile"},
			},
			Dependencies: DependenciesConfig{
				Enabled:    true,
				Ecosystems: []string{"auto"},
				Severity:   "medium",
				IgnoreDev:  false,
			},
			SAST: SASTConfig{
				Enabled:     false,
				Severity:    "medium",
				Concurrency: 8,
			},
			Container: ContainerConfig{
				Enabled:  false,
				Severity: "high",
			},
			License: LicenseConfig{
				Enabled: false,
				Denied:  []string{"GPL-3.0", "AGPL-3.0", "SSPL-1.0"},
			},
			AI: AIConfig{
				Enabled:     false,
				Provider:    "openai",
				Model:       "gpt-4",
				MaxFileSize: 100000,
				Concurrency: 3,
				Focus:       []string{"injection", "authentication", "authorization", "cryptography"},
			},
		},
		Policies: PoliciesConfig{
			Enabled: true,
			Files:   []string{"policies/*.rego", ".sentinelflow/policies/*.rego"},
			Builtin: []string{
				"no-public-s3-buckets",
				"no-privileged-containers",
				"require-https",
				"enforce-encryption",
			},
		},
		Reporting: ReportConfig{
			Format: "text",
		},
		FailOn: FailOnConfig{
			Severity:         "high",
			Secrets:          true,
			PolicyViolations: true,
		},
		Git: GitConfig{
			ScanHistory:  false,
			HistoryDepth: 50,
		},
		Baseline: BaselineConfig{
			Enabled: false,
			File:    ".sentinelflow/baseline.yaml",
		},
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	validSeverities := map[string]bool{
		"": true, "critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	validFormats := map[string]bool{
		"": true, "text": true, "json": true, "sarif": true, "markdown": true, "html": true,
	}

	c.FailOn.Severity = strings.ToLower(strings.TrimSpace(c.FailOn.Severity))
	c.Scanners.IaC.Severity = strings.ToLower(strings.TrimSpace(c.Scanners.IaC.Severity))
	c.Scanners.Dependencies.Severity = strings.ToLower(strings.TrimSpace(c.Scanners.Dependencies.Severity))
	c.Scanners.SAST.Severity = strings.ToLower(strings.TrimSpace(c.Scanners.SAST.Severity))
	c.Scanners.Container.Severity = strings.ToLower(strings.TrimSpace(c.Scanners.Container.Severity))
	c.Reporting.Format = strings.ToLower(strings.TrimSpace(c.Reporting.Format))

	if !validSeverities[c.FailOn.Severity] {
		return fmt.Errorf("invalid fail_on.severity %q (expected critical, high, medium, low, or info)", c.FailOn.Severity)
	}
	if !validSeverities[c.Scanners.IaC.Severity] {
		return fmt.Errorf("invalid scanners.iac.severity %q", c.Scanners.IaC.Severity)
	}
	if !validSeverities[c.Scanners.Dependencies.Severity] {
		return fmt.Errorf("invalid scanners.dependencies.severity %q", c.Scanners.Dependencies.Severity)
	}
	if !validSeverities[c.Scanners.SAST.Severity] {
		return fmt.Errorf("invalid scanners.sast.severity %q", c.Scanners.SAST.Severity)
	}
	if !validSeverities[c.Scanners.Container.Severity] {
		return fmt.Errorf("invalid scanners.container.severity %q", c.Scanners.Container.Severity)
	}
	if !validFormats[c.Reporting.Format] {
		return fmt.Errorf("invalid reporting.format %q (expected text, json, sarif, markdown, or html)", c.Reporting.Format)
	}
	if c.Scanners.Secrets.EntropyThreshold < 0 {
		return fmt.Errorf("scanners.secrets.entropy_threshold must be >= 0")
	}
	if c.Scanners.Secrets.MaxHistoryDepth < 0 {
		return fmt.Errorf("scanners.secrets.max_history_depth must be >= 0")
	}
	if c.Git.HistoryDepth < 0 {
		return fmt.Errorf("git.history_depth must be >= 0")
	}
	if c.Scanners.Concurrency < 0 || c.Scanners.Secrets.Concurrency < 0 ||
		c.Scanners.SAST.Concurrency < 0 || c.Scanners.IaC.Concurrency < 0 {
		return fmt.Errorf("scanner concurrency must be >= 0")
	}
	if c.Scanners.AI.Enabled {
		return fmt.Errorf("%s", AINotAvailableMessage)
	}
	if _, err := c.ScanTimeoutDuration(); err != nil {
		return err
	}

	knownFrameworks := map[string]bool{
		"terraform": true, "kubernetes": true, "dockerfile": true,
	}
	for _, fw := range c.Scanners.IaC.Frameworks {
		name := strings.ToLower(strings.TrimSpace(fw))
		if name == "" {
			continue
		}
		if !knownFrameworks[name] {
			return fmt.Errorf("unsupported scanners.iac.frameworks value %q (supported: terraform, kubernetes, dockerfile)", fw)
		}
	}

	return nil
}

// ScanTimeoutDuration parses scan_timeout (default 10m).
func (c *Config) ScanTimeoutDuration() (time.Duration, error) {
	raw := strings.TrimSpace(c.ScanTimeout)
	if raw == "" {
		return 10 * time.Minute, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid scan_timeout %q (use Go duration, e.g. 10m, 90s)", c.ScanTimeout)
	}
	if d <= 0 {
		return 0, fmt.Errorf("scan_timeout must be > 0")
	}
	return d, nil
}
