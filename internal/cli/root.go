// Package cli provides the command-line interface for SentinelFlow
package cli

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile      string
	verbose      bool
	outputFormat string

	// Version info
	versionInfo struct {
		Version string
		Commit  string
		Date    string
	}
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "sentinelflow",
	Short: "CI/CD Security Gatekeeper",
	Long: `SentinelFlow is a comprehensive security scanning tool that integrates
with CI/CD pipelines to automatically detect security vulnerabilities,
leaked secrets, insecure configurations, and more.

Features:
  • Secret scanning (API keys, tokens, credentials)
  • Infrastructure-as-Code scanning (Terraform, K8s, Docker)
  • Dependency vulnerability analysis
  • Policy-as-code enforcement
  • Automated security reports

AI-powered code review is planned; --ai / scanners.ai.enabled are rejected in this release.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			fmt.Println(color.CyanString("🛡️  SentinelFlow - Security Scanner"))
			fmt.Println()
		}
	},
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

// GetVersion returns the application version string.
func GetVersion() string {
	if versionInfo.Version == "" {
		return "dev"
	}
	return versionInfo.Version
}

// SetVersionInfo sets version information from build flags
func SetVersionInfo(version, commit, date string) {
	versionInfo.Version = version
	versionInfo.Commit = commit
	versionInfo.Date = date
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is .sentinelflow.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "text", "output format (text, json, sarif, markdown, html)")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(hookCmd)
	rootCmd.AddCommand(baselineCmd)
	rootCmd.AddCommand(sbomCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in current directory
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".sentinelflow")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("SENTINELFLOW")

	if err := viper.ReadInConfig(); err != nil {
		// Missing config is fine; malformed config is not.
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return
		}
		if cfgFile == "" && os.IsNotExist(err) {
			return
		}
		fmt.Fprintf(os.Stderr, "error: failed to read config file: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

// versionCmd shows version information
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("SentinelFlow %s\n", versionInfo.Version)
		fmt.Printf("  Commit: %s\n", versionInfo.Commit)
		fmt.Printf("  Built:  %s\n", versionInfo.Date)
	},
}

// initCmd initializes a new configuration
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize SentinelFlow configuration",
	Long:  "Creates a .sentinelflow.yaml configuration file with default settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := ".sentinelflow.yaml"

		if _, err := os.Stat(configPath); err == nil {
			return fmt.Errorf("configuration file already exists: %s", configPath)
		}

		defaultConfig := `# SentinelFlow Configuration
# Documentation: https://github.com/cozygarage/sentinelflow

version: "1.0"

# Overall scan deadline (Go duration). Override with --timeout.
scan_timeout: 10m

scanners:
  # Global path skips for the engine walk (all scanners).
  exclude:
    - "test/**"
    - "**/testdata/**"
  secrets:
    enabled: true
    # Secrets-only skips (does not hide paths from IaC/SAST).
    allowlist:
      - "**/*_test.go"
    entropy_threshold: 4.5
  
  iac:
    enabled: true
    frameworks:
      - terraform
      - kubernetes
      - dockerfile
    severity: medium
  
  dependencies:
    enabled: true
    ecosystems:
      - auto  # Auto-detect based on project files
    severity: medium
    ignore_dev: false
  
  # AI review is planned; leave enabled false (rejected if true).
  ai:
    enabled: false
    provider: openai
    model: gpt-4
    focus:
      - injection
      - authentication
      - authorization
      - cryptography

policies:
  enabled: true
  files:
    - .sentinelflow/policies/*.rego
  builtin:
    - no-public-s3-buckets
    - no-privileged-containers
    - require-https
    - enforce-encryption

reporting:
  format: markdown

fail_on:
  severity: high
  secrets: true
  policy_violations: true

git:
  scan_history: false
  history_depth: 50
`
		if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}

		// Create policies directory
		if err := os.MkdirAll(".sentinelflow/policies", 0755); err != nil {
			return fmt.Errorf("failed to create policies directory: %w", err)
		}

		fmt.Println(color.GreenString("✓ Created .sentinelflow.yaml"))
		fmt.Println(color.GreenString("✓ Created .sentinelflow/policies/"))
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Println("  1. Review and customize .sentinelflow.yaml")
		fmt.Println("  2. Run: sentinelflow scan")
		fmt.Println("  3. Add to your CI/CD pipeline")

		return nil
	},
}
