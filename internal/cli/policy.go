package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/cozygarage/sentinelflow/internal/scanner/policy"
	policiespkg "github.com/cozygarage/sentinelflow/policies"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage security policies",
	Long:  "Commands for managing and testing policy-as-code rules",
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available policies",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(color.CyanString("Built-in Policies:"))
		fmt.Println()

		for _, p := range policiespkg.List() {
			fmt.Printf("  • %s\n", color.GreenString(p.Name))
			fmt.Printf("    %s\n", p.Description)
			fmt.Printf("    Severity: %s | Category: %s\n\n", p.Severity, p.Category)
		}

		// List custom policies if they exist
		customDir := ".sentinelflow/policies"
		if _, err := os.Stat(customDir); err == nil {
			entries, _ := os.ReadDir(customDir)
			if len(entries) > 0 {
				fmt.Println(color.CyanString("Custom Policies:"))
				fmt.Println()
				for _, e := range entries {
					if filepath.Ext(e.Name()) == ".rego" {
						fmt.Printf("  • %s\n", color.YellowString(e.Name()))
					}
				}
			}
		}

		return nil
	},
}

// policyValidateCmd validates a Rego policy file
var policyValidateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Validate a policy file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		policyFile := args[0]

		content, err := os.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("failed to read policy file: %w", err)
		}

		engine := policy.NewOPAEngine()
		if err := engine.ValidatePolicy(string(content)); err != nil {
			return fmt.Errorf("policy validation failed: %w", err)
		}

		fmt.Printf("%s Policy is valid: %s\n", color.GreenString("✓"), policyFile)
		return nil
	},
}

// policyTestCmd tests a policy against sample input
var policyTestCmd = &cobra.Command{
	Use:   "test [policy] [input-file]",
	Short: "Test a policy against sample input",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		policyFile := args[0]
		inputFile := args[1]

		content, err := os.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("failed to read policy file: %w", err)
		}

		inputData, err := os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		var input interface{}
		if err := json.Unmarshal(inputData, &input); err != nil {
			return fmt.Errorf("failed to parse input JSON: %w", err)
		}

		engine := policy.NewOPAEngine()
		policyName := strings.TrimSuffix(filepath.Base(policyFile), ".rego")
		if err := engine.LoadPolicy(policyName, string(content)); err != nil {
			return fmt.Errorf("failed to load policy: %w", err)
		}

		result, err := engine.EvaluatePolicy(cmd.Context(), policyName, input)
		if err != nil {
			return fmt.Errorf("policy evaluation failed: %w", err)
		}

		if len(result.Violations) == 0 {
			fmt.Printf("%s No policy violations found\n", color.GreenString("✓"))
			return nil
		}

		fmt.Printf("%s %d policy violation(s) found:\n", color.RedString("✗"), len(result.Violations))
		for _, v := range result.Violations {
			fmt.Printf("  • %s", v.Message)
			if v.Resource != "" {
				fmt.Printf(" (resource: %s)", v.Resource)
			}
			fmt.Println()
		}

		return fmt.Errorf("policy test failed with %d violation(s)", len(result.Violations))
	},
}

var policyGenerateCmd = &cobra.Command{
	Use:   "generate [name]",
	Short: "Generate a new policy template",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := validatePolicyName(name); err != nil {
			return err
		}

		template := fmt.Sprintf(`package sentinelflow.%s

# %s Policy
# Description: Add your policy description here
# Severity: high

default allow = false

# Define your policy rules here
allow {
    # Add conditions
    input.resource.secure == true
}

# Violations are reported when allow is false
violation[msg] {
    not allow
    msg := "Policy violation: %s check failed"
}
`, name, name, name)

		// Ensure directory exists
		policyDir := ".sentinelflow/policies"
		if err := os.MkdirAll(policyDir, 0755); err != nil {
			return fmt.Errorf("failed to create policies directory: %w", err)
		}

		policyPath, err := safePolicyPath(policyDir, name)
		if err != nil {
			return err
		}

		f, err := os.OpenFile(policyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("policy already exists: %s", policyPath)
			}
			return fmt.Errorf("failed to write policy file: %w", err)
		}
		defer f.Close()

		if _, err := f.WriteString(template); err != nil {
			return fmt.Errorf("failed to write policy file: %w", err)
		}

		fmt.Printf("%s Created policy template: %s\n", color.GreenString("✓"), policyPath)
		return nil
	},
}

func validatePolicyName(name string) error {
	if name == "" {
		return fmt.Errorf("policy name cannot be empty")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return fmt.Errorf("policy name must not contain path separators or '..'")
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("policy name %q is invalid; use only letters, numbers, '_' and '-'", name)
	}
	return nil
}

func safePolicyPath(policyDir, name string) (string, error) {
	absDir, err := filepath.Abs(policyDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve policy directory: %w", err)
	}
	candidate := filepath.Join(absDir, name+".rego")
	cleaned := filepath.Clean(candidate)
	rel, err := filepath.Rel(absDir, cleaned)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", fmt.Errorf("policy path escapes policies directory")
	}
	return cleaned, nil
}

func init() {
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyTestCmd)
	policyCmd.AddCommand(policyGenerateCmd)
}
