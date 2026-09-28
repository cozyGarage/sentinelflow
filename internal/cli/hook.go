package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	hookMarker      = "# sentinelflow-pre-commit-hook"
	hookBeginMarker = "# >>> sentinelflow-pre-commit-hook"
	hookEndMarker   = "# <<< sentinelflow-pre-commit-hook"
)

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Manage git hooks",
	Long:  "Install or uninstall SentinelFlow pre-commit hooks for shift-left security scanning",
}

var hookInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install pre-commit hook",
	RunE: func(cmd *cobra.Command, args []string) error {
		gitDir, err := findGitDir()
		if err != nil {
			return err
		}

		hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to resolve executable: %w", err)
		}

		block := fmt.Sprintf(`%s
%s
exec "%s" scan --secrets --iac --staged --fail-on high
%s
`, hookBeginMarker, hookMarker, exe, hookEndMarker)

		if err := os.MkdirAll(filepath.Dir(hookPath), 0755); err != nil {
			return fmt.Errorf("failed to create hooks directory: %w", err)
		}

		existing := ""
		if data, err := os.ReadFile(hookPath); err == nil {
			existing = string(data)
			if containsMarker(existing) {
				fmt.Println(color.YellowString("Pre-commit hook already installed"))
				return nil
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read existing hook: %w", err)
		}

		var content string
		if existing == "" {
			content = "#!/bin/sh\n" + block
		} else {
			content = strings.TrimRight(existing, "\n") + "\n\n" + block
		}

		if err := os.WriteFile(hookPath, []byte(content), 0755); err != nil {
			return fmt.Errorf("failed to write hook: %w", err)
		}

		fmt.Printf("%s Installed pre-commit hook at %s\n", color.GreenString("✓"), hookPath)
		return nil
	},
}

var hookUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall pre-commit hook",
	RunE: func(cmd *cobra.Command, args []string) error {
		gitDir, err := findGitDir()
		if err != nil {
			return err
		}

		hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
		data, err := os.ReadFile(hookPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println(color.YellowString("No pre-commit hook found"))
				return nil
			}
			return fmt.Errorf("failed to read hook: %w", err)
		}

		content := string(data)
		if !containsMarker(content) {
			fmt.Println(color.YellowString("Pre-commit hook was not installed by SentinelFlow"))
			return nil
		}

		updated, removed := removeHookBlock(content)
		if !removed {
			return fmt.Errorf("failed to locate SentinelFlow hook block for removal")
		}

		trimmed := strings.TrimSpace(updated)
		if trimmed == "" || trimmed == "#!/bin/sh" || trimmed == "#!/bin/bash" {
			if err := os.Remove(hookPath); err != nil {
				return fmt.Errorf("failed to remove hook: %w", err)
			}
		} else {
			if err := os.WriteFile(hookPath, []byte(updated), 0755); err != nil {
				return fmt.Errorf("failed to update hook: %w", err)
			}
		}

		fmt.Printf("%s Removed SentinelFlow pre-commit hook from %s\n", color.GreenString("✓"), hookPath)
		return nil
	},
}

func findGitDir() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not a git repository: run this command from within a git repo")
	}
	return filepath.Clean(strings.TrimSpace(string(output))), nil
}

func containsMarker(content string) bool {
	return strings.Contains(content, hookMarker) || strings.Contains(content, hookBeginMarker)
}

func removeHookBlock(content string) (string, bool) {
	if begin := strings.Index(content, hookBeginMarker); begin >= 0 {
		end := strings.Index(content[begin:], hookEndMarker)
		if end >= 0 {
			end = begin + end + len(hookEndMarker)
			for end < len(content) && (content[end] == '\n' || content[end] == '\r') {
				end++
			}
			return content[:begin] + content[end:], true
		}
	}

	// Legacy single-marker format: remove marker line and following exec line if present
	lines := strings.Split(content, "\n")
	var out []string
	removed := false
	for i := 0; i < len(lines); i++ {
		if strings.Contains(lines[i], hookMarker) {
			removed = true
			if i+1 < len(lines) && strings.Contains(lines[i+1], "sentinelflow") && strings.Contains(lines[i+1], "scan") {
				i++
			}
			continue
		}
		out = append(out, lines[i])
	}
	return strings.Join(out, "\n"), removed
}

func init() {
	hookCmd.AddCommand(hookInstallCmd)
	hookCmd.AddCommand(hookUninstallCmd)
}
