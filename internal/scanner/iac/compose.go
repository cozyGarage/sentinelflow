package iac

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/scanner/redact"
	"github.com/cozygarage/sentinelflow/pkg/api"
	"gopkg.in/yaml.v3"
)

// isComposeFile matches docker-compose*.y(a)ml and compose*.y(a)ml.
func isComposeFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	ext := filepath.Ext(base)
	return (ext == ".yml" || ext == ".yaml") &&
		(strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose"))
}

// scanCompose flags services that hand the host to the container.
func scanCompose(ctx context.Context, filePath, basePath string) []api.Finding {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	var doc yaml.Node
	if yaml.Unmarshal(content, &doc) != nil || len(doc.Content) == 0 {
		return nil
	}
	services := mapGet(doc.Content[0], "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil
	}
	rel, _ := filepath.Rel(basePath, filePath)
	rel = filepath.ToSlash(rel)

	var findings []api.Finding
	for i := 1; i < len(services.Content); i += 2 {
		if ctx.Err() != nil {
			return findings
		}
		name, svc := services.Content[i-1].Value, services.Content[i]
		add := func(ruleID, title, desc string, sev api.Severity, n *yaml.Node, remediation string) {
			findings = append(findings, api.Finding{
				ID:          fmt.Sprintf("IAC-COMPOSE-%s-%s-%s-%d", ruleID, name, fingerprint.Token(rel), n.Line),
				Type:        api.FindingTypeMisconfiguration,
				Severity:    sev,
				Title:       title,
				Description: fmt.Sprintf("Service %q: %s", name, desc),
				Location:    api.Location{File: rel, StartLine: n.Line, EndLine: n.Line, Snippet: redact.Snippet(lineAt(content, n.Line))},
				Remediation: remediation,
				Scanner:     "iac",
				RuleID:      ruleID,
				Confidence:  0.95,
			})
		}

		if n := mapGet(svc, "privileged"); n != nil {
			if b, ok := asBool(n.Value); ok && b {
				add("compose-privileged", "Privileged Container", "runs with all host capabilities and device access",
					api.SeverityHigh, n, "Remove `privileged: true`; grant specific `cap_add` entries if needed")
			}
		}
		for _, key := range []string{"network_mode", "pid", "ipc"} {
			if n := mapGet(svc, key); n != nil && n.Value == "host" {
				add("compose-host-"+strings.ReplaceAll(key, "_mode", ""), "Host Namespace Shared",
					fmt.Sprintf("shares the host %s namespace (`%s: host`)", strings.TrimSuffix(key, "_mode"), key),
					api.SeverityMedium, n, fmt.Sprintf("Remove `%s: host`", key))
			}
		}
		if caps := mapGet(svc, "cap_add"); caps != nil {
			for _, c := range caps.Content {
				if v := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(c.Value), "CAP_")); v == "ALL" || v == "SYS_ADMIN" {
					add("compose-dangerous-capability", "Dangerous Capability Added",
						fmt.Sprintf("adds %s, which is close to full root on the host", c.Value),
						api.SeverityHigh, c, "Drop the capability and add only the narrow ones the service needs")
				}
			}
		}
		if vols := mapGet(svc, "volumes"); vols != nil {
			for _, v := range vols.Content {
				src := v.Value
				if v.Kind == yaml.MappingNode {
					if s := mapGet(v, "source"); s != nil {
						src = s.Value
					}
				}
				if strings.Contains(src, "docker.sock") {
					add("compose-docker-socket", "Docker Socket Mounted",
						"mounts the Docker socket, which gives the container root on the host",
						api.SeverityHigh, v, "Do not mount docker.sock; use a socket proxy with a read-only allowlist if the API is required")
				}
			}
		}
	}
	return findings
}
