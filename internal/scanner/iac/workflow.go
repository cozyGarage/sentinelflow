package iac

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/scanner/redact"
	"github.com/cozygarage/sentinelflow/pkg/api"
	"gopkg.in/yaml.v3"
)

// isWorkflowFile reports whether path is a GitHub Actions workflow.
func isWorkflowFile(path string) bool {
	p := filepath.ToSlash(path)
	ext := strings.ToLower(filepath.Ext(p))
	return (ext == ".yml" || ext == ".yaml") && strings.Contains(p, ".github/workflows/")
}

var (
	shaRef = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// Attacker-controllable event fields; interpolating them into a shell is script injection.
	untrustedExpr = regexp.MustCompile(`\$\{\{\s*(github\.event\.(issue\.title|issue\.body|pull_request\.title|pull_request\.body|pull_request\.head\.ref|pull_request\.head\.label|comment\.body|review\.body|review_comment\.body|discussion\.title|discussion\.body|pages\.[^}]*\.page_name|commits\.[^}]*\.(message|author\.(name|email))|head_commit\.(message|author\.(name|email))|workflow_run\.(head_branch|head_commit\.message))|github\.head_ref)\s*\}\}`)
	headCheckout  = regexp.MustCompile(`github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/`)
)

// scanWorkflow checks a GitHub Actions workflow for the common supply-chain and injection mistakes.
func scanWorkflow(ctx context.Context, filePath, basePath string) []api.Finding {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	var doc yaml.Node
	if yaml.Unmarshal(content, &doc) != nil || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	rel, _ := filepath.Rel(basePath, filePath)
	rel = filepath.ToSlash(rel)

	var findings []api.Finding
	add := func(ruleID, title, desc string, sev api.Severity, n *yaml.Node, remediation string) {
		line := 1
		if n != nil {
			line = n.Line
		}
		findings = append(findings, api.Finding{
			ID:          fmt.Sprintf("IAC-GHA-%s-%s-%d", ruleID, pathToken(rel), line),
			Type:        api.FindingTypeMisconfiguration,
			Severity:    sev,
			Title:       title,
			Description: desc,
			Location:    api.Location{File: rel, StartLine: line, EndLine: line, Snippet: redact.Snippet(lineAt(content, line))},
			Remediation: remediation,
			Scanner:     "iac",
			RuleID:      ruleID,
			Confidence:  0.9,
		})
	}

	on := mapGet(root, "on")
	if on == nil {
		on = mapGet(root, "true") // YAML 1.1 parsers read a bare `on:` key as boolean true
	}
	privileged := hasTrigger(on, "pull_request_target") || hasTrigger(on, "workflow_run")

	topPerms := mapGet(root, "permissions")
	if topPerms != nil && topPerms.Value == "write-all" {
		add("gha-permissions-write-all", "Workflow Grants write-all Permissions",
			"The GITHUB_TOKEN can write to every scope, so any compromised step can push code or tamper with releases",
			api.SeverityMedium, topPerms, "Set `permissions:` to the minimum scopes each job needs, e.g. `contents: read`")
	}

	jobs := mapGet(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return findings
	}
	for i := 1; i < len(jobs.Content); i += 2 {
		if ctx.Err() != nil {
			return findings
		}
		job := jobs.Content[i]
		if topPerms == nil && mapGet(job, "permissions") == nil {
			add("gha-permissions-missing", "Job Runs With Default Token Permissions",
				fmt.Sprintf("Job %q has no `permissions:` and the workflow sets none, so the GITHUB_TOKEN gets the repository default (often read/write)", jobs.Content[i-1].Value),
				api.SeverityLow, jobs.Content[i-1], "Add `permissions: contents: read` at the top level and widen per job only where needed")
		}
		if p := mapGet(job, "permissions"); p != nil && p.Value == "write-all" {
			add("gha-permissions-write-all", "Job Grants write-all Permissions",
				fmt.Sprintf("Job %q gives the GITHUB_TOKEN write access to every scope", jobs.Content[i-1].Value),
				api.SeverityMedium, p, "List only the scopes the job needs")
		}
		if uses := mapGet(job, "uses"); uses != nil { // reusable workflow call
			checkUses(uses, add)
		}
		steps := mapGet(job, "steps")
		if steps == nil {
			continue
		}
		for _, step := range steps.Content {
			uses := mapGet(step, "uses")
			if uses != nil {
				checkUses(uses, add)
			}
			if run := mapGet(step, "run"); run != nil {
				checkInjection(run, "run", add)
			}
			if uses != nil && strings.HasPrefix(uses.Value, "actions/github-script@") {
				if script := mapGet(mapGet(step, "with"), "script"); script != nil {
					checkInjection(script, "github-script", add)
				}
			}
			if privileged && uses != nil && strings.HasPrefix(uses.Value, "actions/checkout@") {
				if ref := mapGet(mapGet(step, "with"), "ref"); ref != nil && headCheckout.MatchString(ref.Value) {
					add("gha-pwn-request", "Untrusted PR Code Checked Out in Privileged Workflow",
						"pull_request_target/workflow_run runs with a write token and secrets; checking out the PR head lets a fork run its own code with them",
						api.SeverityCritical, ref, "Use `pull_request` for untrusted code, or never build/run the checked-out head in this workflow")
				}
			}
		}
	}
	return findings
}

func checkUses(uses *yaml.Node, add func(string, string, string, api.Severity, *yaml.Node, string)) {
	v := uses.Value
	if strings.HasPrefix(v, "./") || strings.HasPrefix(v, "docker://") {
		return
	}
	_, ref, ok := strings.Cut(v, "@")
	if ok && shaRef.MatchString(ref) {
		return
	}
	sev := api.SeverityMedium
	if strings.HasPrefix(v, "actions/") || strings.HasPrefix(v, "github/") {
		sev = api.SeverityLow // first-party, but tags are still mutable
	}
	add("gha-unpinned-action", "Action Not Pinned to a Commit SHA",
		fmt.Sprintf("%q uses a mutable ref; whoever controls the tag controls code running with your token and secrets", v),
		sev, uses, "Pin to a full 40-character commit SHA (keep the tag in a comment) and let Dependabot update it")
}

func checkInjection(n *yaml.Node, where string, add func(string, string, string, api.Severity, *yaml.Node, string)) {
	if m := untrustedExpr.FindString(n.Value); m != "" {
		add("gha-script-injection", "Untrusted Input Interpolated Into Script",
			fmt.Sprintf("%s expands %s directly into code; a crafted title, branch name or comment can run arbitrary commands", where, m),
			api.SeverityHigh, n, "Pass the value through `env:` (e.g. `TITLE: ${{ github.event.issue.title }}`) and reference \"$TITLE\" in the script")
	}
}

func hasTrigger(on *yaml.Node, name string) bool {
	if on == nil {
		return false
	}
	switch on.Kind {
	case yaml.ScalarNode:
		return on.Value == name
	case yaml.SequenceNode:
		for _, c := range on.Content {
			if c.Value == name {
				return true
			}
		}
	case yaml.MappingNode:
		return mapGet(on, name) != nil
	}
	return false
}

// mapGet returns the value node for key in a YAML mapping, or nil.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func lineAt(content []byte, line int) string {
	lines := strings.Split(string(content), "\n")
	if line < 1 || line > len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[line-1])
}
