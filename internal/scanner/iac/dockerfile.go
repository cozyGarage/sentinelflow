package iac

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/redact"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// DockerfileScanner scans Dockerfiles for security issues
type DockerfileScanner struct {
	config *config.Config
	rules  []*DockerfileRule
}

// DockerfileRule defines a Dockerfile security rule
type DockerfileRule struct {
	ID          string
	Name        string
	Description string
	Severity    api.Severity
	Pattern     *regexp.Regexp
	Check       func(inst instruction, all []instruction) bool
	FileCheck   func(all []instruction) bool
	Remediation string
}

type instruction struct {
	Cmd     string
	Args    string
	Raw     string
	Line    int
	EndLine int
}

// NewDockerfileScanner creates a new Dockerfile scanner
func NewDockerfileScanner(cfg *config.Config) *DockerfileScanner {
	s := &DockerfileScanner{config: cfg}
	s.rules = s.loadRules()
	return s
}

// ScanFile scans a Dockerfile
func (s *DockerfileScanner) ScanFile(ctx context.Context, filePath, basePath string) []api.Finding {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	relPath, _ := filepath.Rel(basePath, filePath)
	instructions := parseDockerfileInstructions(string(content))

	var findings []api.Finding

	for _, inst := range instructions {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, rule := range s.rules {
			if rule.FileCheck != nil {
				continue
			}
			matches := false
			if rule.Pattern != nil {
				matches = rule.Pattern.MatchString(inst.Raw)
			}
			if rule.Check != nil {
				matches = rule.Check(inst, instructions)
			}
			if !matches {
				continue
			}
			findings = append(findings, api.Finding{
				ID:          fmt.Sprintf("IAC-DOCKER-%s-%s-%d", rule.ID, pathToken(relPath), inst.Line),
				Type:        api.FindingTypeMisconfiguration,
				Severity:    rule.Severity,
				Title:       rule.Name,
				Description: rule.Description,
				Location: api.Location{
					File:      relPath,
					StartLine: inst.Line,
					EndLine:   inst.EndLine,
					Snippet:   redact.Snippet(inst.Raw),
				},
				Remediation: rule.Remediation,
				Scanner:     "iac",
				RuleID:      rule.ID,
				Confidence:  0.9,
			})
		}
	}

	// File-level checks once (missing USER / HEALTHCHECK on final stage)
	for _, rule := range s.rules {
		if rule.FileCheck == nil || !rule.FileCheck(instructions) {
			continue
		}
		line := 1
		if len(instructions) > 0 {
			line = instructions[len(instructions)-1].EndLine
		}
		findings = append(findings, api.Finding{
			ID:          fmt.Sprintf("IAC-DOCKER-%s-%s-%d", rule.ID, pathToken(relPath), line),
			Type:        api.FindingTypeMisconfiguration,
			Severity:    rule.Severity,
			Title:       rule.Name,
			Description: rule.Description,
			Location: api.Location{
				File:      relPath,
				StartLine: line,
				EndLine:   line,
			},
			Remediation: rule.Remediation,
			Scanner:     "iac",
			RuleID:      rule.ID,
			Confidence:  0.9,
		})
	}

	return findings
}

func parseDockerfileInstructions(content string) []instruction {
	rawLines := strings.Split(content, "\n")
	var logical []struct {
		text     string
		start    int
		end      int
	}

	for i := 0; i < len(rawLines); {
		line := rawLines[i]
		trimmed := strings.TrimRight(line, " \t\r")
		if strings.TrimSpace(trimmed) == "" || strings.HasPrefix(strings.TrimSpace(trimmed), "#") {
			i++
			continue
		}

		start := i + 1
		end := i + 1
		text := trimmed
		for strings.HasSuffix(strings.TrimRight(text, " \t"), "\\") {
			text = strings.TrimRight(text, " \t")
			text = strings.TrimSuffix(text, "\\")
			i++
			if i >= len(rawLines) {
				break
			}
			next := strings.TrimRight(rawLines[i], " \t\r")
			text += " " + strings.TrimSpace(next)
			end = i + 1
		}
		logical = append(logical, struct {
			text  string
			start int
			end   int
		}{text: text, start: start, end: end})
		i++
	}

	var out []instruction
	for _, l := range logical {
		fields := strings.Fields(l.text)
		if len(fields) == 0 {
			continue
		}
		cmd := strings.ToUpper(fields[0])
		args := strings.TrimSpace(l.text[len(fields[0]):])
		out = append(out, instruction{
			Cmd:     cmd,
			Args:    args,
			Raw:     l.text,
			Line:    l.start,
			EndLine: l.end,
		})
	}
	return out
}

func finalStageInstructions(all []instruction) []instruction {
	start := 0
	for i, inst := range all {
		if inst.Cmd == "FROM" {
			start = i
		}
	}
	return all[start:]
}

func finalStageHasUser(all []instruction) bool {
	for _, inst := range finalStageInstructions(all) {
		if inst.Cmd == "USER" {
			user := strings.Fields(inst.Args)
			if len(user) == 0 {
				continue
			}
			u := strings.ToLower(user[0])
			if u != "root" && u != "0" {
				return true
			}
		}
	}
	return false
}

func hasHealthcheck(all []instruction) bool {
	for _, inst := range finalStageInstructions(all) {
		if inst.Cmd == "HEALTHCHECK" {
			return true
		}
	}
	return false
}

func (s *DockerfileScanner) loadRules() []*DockerfileRule {
	return []*DockerfileRule{
		{
			ID:          "latest-tag",
			Name:        "Using 'latest' Tag",
			Description: "Dockerfile uses 'latest' tag which can lead to unpredictable builds",
			Severity:    api.SeverityMedium,
			Check: func(inst instruction, _ []instruction) bool {
				if inst.Cmd != "FROM" {
					return false
				}
				return regexp.MustCompile(`(?i)^[^\s:]+:latest(?:\s|$)`).MatchString(strings.TrimSpace(inst.Args))
			},
			Remediation: "Use specific version tags instead of 'latest'",
		},
		{
			ID:          "no-tag",
			Name:        "No Image Tag Specified",
			Description: "Dockerfile base image has no tag (defaults to 'latest')",
			Severity:    api.SeverityMedium,
			Check: func(inst instruction, _ []instruction) bool {
				if inst.Cmd != "FROM" {
					return false
				}
				args := strings.Fields(inst.Args)
				if len(args) == 0 {
					return false
				}
				image := args[0]
				if strings.EqualFold(image, "scratch") {
					return false
				}
				// FROM image AS name
				return !strings.Contains(image, ":") && !strings.Contains(image, "@")
			},
			Remediation: "Specify a version tag for the base image",
		},
		{
			ID:          "missing-user",
			Name:        "Missing USER Instruction",
			Description: "Final image stage does not switch to a non-root user",
			Severity:    api.SeverityHigh,
			FileCheck: func(all []instruction) bool {
				return !finalStageHasUser(all)
			},
			Remediation: "Add USER instruction to run container as non-root user in the final stage",
		},
		{
			ID:          "user-root",
			Name:        "Explicit Root User",
			Description: "Dockerfile explicitly sets USER to root",
			Severity:    api.SeverityHigh,
			Check: func(inst instruction, _ []instruction) bool {
				if inst.Cmd != "USER" {
					return false
				}
				fields := strings.Fields(inst.Args)
				if len(fields) == 0 {
					return false
				}
				u := strings.ToLower(fields[0])
				return u == "root" || u == "0"
			},
			Remediation: "Use a non-root user instead",
		},
		{
			ID:          "hardcoded-secret",
			Name:        "Hardcoded Secret in ENV",
			Description: "Environment variable appears to contain hardcoded secret",
			Severity:    api.SeverityCritical,
			Pattern:     regexp.MustCompile(`(?i)^ENV\s+.*(PASSWORD|SECRET|TOKEN|KEY)=["']?[^$\{]`),
			Remediation: "Use build arguments or runtime secrets instead of hardcoding",
		},
		{
			ID:          "exposed-port-22",
			Name:        "SSH Port Exposed",
			Description: "Dockerfile exposes SSH port 22",
			Severity:    api.SeverityMedium,
			Check: func(inst instruction, _ []instruction) bool {
				return inst.Cmd == "EXPOSE" && regexp.MustCompile(`(?:^|\s)22(?:/|\s|$)`).MatchString(inst.Args)
			},
			Remediation: "Avoid exposing SSH in containers, use exec instead",
		},
		{
			ID:          "apt-no-cleanup",
			Name:        "APT Cache Not Cleaned",
			Description: "apt-get install without cleanup increases image size",
			Severity:    api.SeverityLow,
			Check: func(inst instruction, _ []instruction) bool {
				if inst.Cmd != "RUN" {
					return false
				}
				lower := strings.ToLower(inst.Args)
				if !strings.Contains(lower, "apt-get install") && !strings.Contains(lower, "apt install") {
					return false
				}
				return !strings.Contains(lower, "rm -rf /var/lib/apt/lists")
			},
			Remediation: "Add 'rm -rf /var/lib/apt/lists/*' after apt-get install",
		},
		{
			ID:          "sudo-usage",
			Name:        "Using sudo in Container",
			Description: "Dockerfile uses sudo which is unnecessary in containers",
			Severity:    api.SeverityLow,
			Check: func(inst instruction, _ []instruction) bool {
				return inst.Cmd == "RUN" && regexp.MustCompile(`(?i)\bsudo\b`).MatchString(inst.Args)
			},
			Remediation: "Remove sudo usage; run commands directly or use USER",
		},
		{
			ID:          "curl-to-bash",
			Name:        "Piping curl to bash",
			Description: "Downloading and executing scripts directly is dangerous",
			Severity:    api.SeverityHigh,
			Check: func(inst instruction, _ []instruction) bool {
				return inst.Cmd == "RUN" && regexp.MustCompile(`(?i)curl.*\|\s*(ba)?sh`).MatchString(inst.Args)
			},
			Remediation: "Download scripts, verify them, then execute",
		},
		{
			ID:          "wget-to-bash",
			Name:        "Piping wget to bash",
			Description: "Downloading and executing scripts directly is dangerous",
			Severity:    api.SeverityHigh,
			Check: func(inst instruction, _ []instruction) bool {
				return inst.Cmd == "RUN" && regexp.MustCompile(`(?i)wget.*\|\s*(ba)?sh`).MatchString(inst.Args)
			},
			Remediation: "Download scripts, verify them, then execute",
		},
		{
			ID:          "add-archive-extraction",
			Name:        "Using ADD for Remote Files",
			Description: "ADD automatically extracts archives which can be dangerous",
			Severity:    api.SeverityMedium,
			Check: func(inst instruction, _ []instruction) bool {
				return inst.Cmd == "ADD" && regexp.MustCompile(`(?i)^https?://`).MatchString(strings.TrimSpace(inst.Args))
			},
			Remediation: "Use COPY instead of ADD, or RUN curl/wget for remote files",
		},
		{
			ID:          "no-healthcheck",
			Name:        "Missing HEALTHCHECK",
			Description: "Final image stage does not define a HEALTHCHECK",
			Severity:    api.SeverityLow,
			FileCheck:   func(all []instruction) bool { return !hasHealthcheck(all) },
			Remediation: "Add HEALTHCHECK instruction for container health monitoring",
		},
		{
			ID:          "update-alone",
			Name:        "apt-get update Alone",
			Description: "apt-get update should be combined with install to avoid cache issues",
			Severity:    api.SeverityLow,
			Check: func(inst instruction, _ []instruction) bool {
				if inst.Cmd != "RUN" {
					return false
				}
				lower := strings.ToLower(inst.Args)
				if !strings.Contains(lower, "apt-get update") && !strings.Contains(lower, "apt update") {
					return false
				}
				return !strings.Contains(lower, "install")
			},
			Remediation: "Combine apt-get update && apt-get install in single RUN",
		},
	}
}
