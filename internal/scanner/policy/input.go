package policy

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/scanner/filter"
	"gopkg.in/yaml.v3"
)

type policyInput struct {
	Data     map[string]interface{}
	FilePath string
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".terraform": true,
	"__pycache__": true, ".venv": true, "dist": true, "build": true, ".cache": true,
	// Go convention for local test assets
	"testdata": true,
}

func collectPolicyInputs(root string) ([]policyInput, error) {
	var inputs []policyInput

	k8sInputs, err := collectKubernetesInputs(root)
	if err != nil {
		return nil, err
	}
	inputs = append(inputs, k8sInputs...)

	tfInput, err := collectTerraformInput(root)
	if err != nil {
		return nil, err
	}
	if tfInput != nil {
		inputs = append(inputs, *tfInput)
	}

	return inputs, nil
}

func collectKubernetesInputs(root string) ([]policyInput, error) {
	var inputs []policyInput
	root = filepath.Clean(root)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if filepath.Clean(path) != root && (skipDirs[info.Name()] || filter.IsBundledSampleDir(root, path)) {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if !strings.Contains(string(content), "apiVersion:") {
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		docs, err := decodeYAMLDocuments(content)
		if err != nil {
			return nil
		}

		for i, doc := range docs {
			if len(doc) == 0 {
				continue
			}
			if _, ok := doc["apiVersion"]; !ok {
				continue
			}
			doc["_file"] = rel
			filePath := rel
			if len(docs) > 1 {
				filePath = rel + "#" + strconv.Itoa(i+1)
			}
			inputs = append(inputs, policyInput{Data: doc, FilePath: filePath})
		}

		return nil
	})

	return inputs, err
}

func decodeYAMLDocuments(content []byte) ([]map[string]interface{}, error) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var docs []map[string]interface{}
	for {
		var doc map[string]interface{}
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if doc == nil {
			continue
		}
		docs = append(docs, doc)
	}
	return docs, nil
}

var tfResourcePattern = regexp.MustCompile(`resource\s+"([^"]+)"\s+"([^"]+)"\s*\{`)

func collectTerraformInput(root string) (*policyInput, error) {
	var changes []map[string]interface{}
	root = filepath.Clean(root)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if filepath.Clean(path) != root && (skipDirs[info.Name()] || filter.IsBundledSampleDir(root, path)) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".tf" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		fileChanges := parseTerraformResources(string(content), rel)
		changes = append(changes, fileChanges...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(changes) == 0 {
		return nil, nil
	}

	return &policyInput{
		Data: map[string]interface{}{
			"resource_changes": changes,
		},
		FilePath: root,
	}, nil
}

func parseTerraformResources(content, file string) []map[string]interface{} {
	var changes []map[string]interface{}

	matches := tfResourcePattern.FindAllStringSubmatchIndex(content, -1)
	for i, loc := range matches {
		resourceType := content[loc[2]:loc[3]]
		resourceName := content[loc[4]:loc[5]]

		bodyStart := loc[1]
		bodyEnd := len(content)
		if i+1 < len(matches) {
			bodyEnd = matches[i+1][0]
		}

		body := extractBalancedBlock(content, bodyStart-1, bodyEnd)
		after := parseTerraformAttributes(body)

		changes = append(changes, map[string]interface{}{
			"type": resourceType,
			"name": resourceName,
			"file": file,
			"change": map[string]interface{}{
				"after": after,
			},
		})
	}

	return changes
}

// extractBalancedBlock returns the body inside the resource `{...}` starting at openBrace.
func extractBalancedBlock(content string, openBrace, limit int) string {
	if openBrace < 0 || openBrace >= len(content) || content[openBrace] != '{' {
		if openBrace+1 < limit {
			return content[openBrace+1 : limit]
		}
		return content[openBrace+1:]
	}
	depth := 0
	for i := openBrace; i < len(content) && i < limit+1024; i++ {
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return content[openBrace+1 : i]
			}
		}
	}
	if openBrace+1 < limit {
		return content[openBrace+1 : limit]
	}
	return content[openBrace+1:]
}

var (
	tfAttrPattern   = regexp.MustCompile(`(?m)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$`)
	tfBlockPattern  = regexp.MustCompile(`(?m)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\{`)
	tfRefPattern    = regexp.MustCompile(`^([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)(?:\[[^\]]*\])?(?:\.id)?$`)
	tfListPattern   = regexp.MustCompile(`^\[(.*)\]$`)
)

func parseTerraformAttributes(body string) map[string]interface{} {
	attrs := make(map[string]interface{})

	// Parse nested blocks first so top-level attrs remain accurate.
	blockMatches := tfBlockPattern.FindAllStringSubmatchIndex(body, -1)
	for _, loc := range blockMatches {
		name := body[loc[2]:loc[3]]
		// Skip attribute-looking lines that also matched (rare); blocks have `{` after name.
		openIdx := strings.Index(body[loc[0]:loc[1]], "{")
		if openIdx < 0 {
			continue
		}
		absOpen := loc[0] + openIdx
		blockBody := extractBalancedBlock(body, absOpen, len(body))

		nested := parseTerraformAttributes(blockBody)
		if existing, ok := attrs[name]; ok {
			switch cur := existing.(type) {
			case []interface{}:
				attrs[name] = append(cur, nested)
			default:
				attrs[name] = []interface{}{cur, nested}
			}
		} else {
			attrs[name] = nested
		}
	}

	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.HasSuffix(trimmed, "{") {
			continue
		}

		match := tfAttrPattern.FindStringSubmatch(trimmed)
		if len(match) < 3 {
			continue
		}

		key := match[1]
		raw := strings.TrimSpace(match[2])
		// Nested blocks already occupy this key as a map/list.
		if _, exists := attrs[key]; exists {
			if _, isMap := attrs[key].(map[string]interface{}); isMap {
				continue
			}
			if _, isList := attrs[key].([]interface{}); isList {
				continue
			}
		}

		attrs[key] = normalizeTerraformValue(raw)
	}

	return attrs
}

func normalizeTerraformValue(raw string) interface{} {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, ",")

	switch raw {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}

	if m := tfListPattern.FindStringSubmatch(raw); len(m) == 2 {
		inner := strings.TrimSpace(m[1])
		if inner == "" {
			return []interface{}{}
		}
		parts := splitTerraformList(inner)
		out := make([]interface{}, 0, len(parts))
		for _, p := range parts {
			out = append(out, normalizeTerraformValue(p))
		}
		return out
	}

	if strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) && len(raw) >= 2 {
		return strings.ReplaceAll(raw[1:len(raw)-1], `\"`, `"`)
	}

	// Resolve aws_s3_bucket.example.id / aws_s3_bucket.example[0].id -> example
	if m := tfRefPattern.FindStringSubmatch(raw); len(m) == 3 {
		return m[2]
	}

	return raw
}

func splitTerraformList(inner string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(inner); i++ {
		ch := inner[i]
		switch {
		case ch == '"' && (i == 0 || inner[i-1] != '\\'):
			inQuote = !inQuote
			cur.WriteByte(ch)
		case ch == ',' && !inQuote:
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		parts = append(parts, s)
	}
	return parts
}
