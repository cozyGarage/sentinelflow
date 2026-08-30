// Package policies embeds the built-in Rego policy files shipped with SentinelFlow.
package policies

import (
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed *.rego
var files embed.FS

// Builtin describes a shipped policy.
type Builtin struct {
	Name        string
	Description string
	Severity    string
	Category    string
	Content     string
}

var catalog = map[string]Builtin{
	"no-public-s3-buckets": {
		Name:        "no-public-s3-buckets",
		Description: "Prevents S3 buckets from being publicly accessible",
		Severity:    "critical",
		Category:    "storage",
	},
	"no-privileged-containers": {
		Name:        "no-privileged-containers",
		Description: "Prevents deployment of privileged containers",
		Severity:    "critical",
		Category:    "kubernetes",
	},
	"require-https": {
		Name:        "require-https",
		Description: "Ensures all endpoints use HTTPS",
		Severity:    "high",
		Category:    "network",
	},
	"enforce-encryption": {
		Name:        "enforce-encryption",
		Description: "Requires encryption at rest for storage",
		Severity:    "high",
		Category:    "storage",
	},
}

// Names returns all built-in policy names in stable order.
func Names() []string {
	names := make([]string, 0, len(catalog))
	for name := range catalog {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Get returns a built-in policy by name, including its Rego source.
func Get(name string) (Builtin, error) {
	meta, ok := catalog[name]
	if !ok {
		return Builtin{}, fmt.Errorf("unknown built-in policy %q", name)
	}
	content, err := files.ReadFile(name + ".rego")
	if err != nil {
		return Builtin{}, fmt.Errorf("built-in policy %q missing: %w", name, err)
	}
	meta.Content = string(content)
	if meta.Severity == "" {
		meta.Severity = severityFromContent(meta.Content)
	}
	if meta.Description == "" {
		meta.Description = descriptionFromContent(meta.Content)
	}
	return meta, nil
}

// List returns metadata for all built-in policies.
func List() []Builtin {
	out := make([]Builtin, 0, len(catalog))
	for _, name := range Names() {
		b, err := Get(name)
		if err != nil {
			continue
		}
		out = append(out, b)
	}
	return out
}

// LoadSelected returns Rego content for the requested built-in names.
// Unknown names produce an error.
func LoadSelected(names []string) (map[string]string, error) {
	selected := make(map[string]string, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		b, err := Get(name)
		if err != nil {
			return nil, err
		}
		selected[name] = b.Content
	}
	return selected, nil
}

func severityFromContent(content string) string {
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "# severity:") {
			parts := strings.SplitN(line, "severity:", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "medium"
}

func descriptionFromContent(content string) string {
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "# description:") {
			parts := strings.SplitN(line, "description:", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
