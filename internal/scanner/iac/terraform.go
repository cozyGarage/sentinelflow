package iac

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/redact"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// TerraformScanner scans Terraform files for security issues
type TerraformScanner struct {
	config *config.Config
	rules  []*TerraformRule
}

// TerraformRule defines a Terraform security rule
type TerraformRule struct {
	ID          string
	Name        string
	Description string
	Severity    api.Severity
	Pattern     *regexp.Regexp
	Check       func(content string) bool
	Remediation string
	// ResourceScoped marks rules handled by per-resource analysis instead of line patterns.
	ResourceScoped bool
}

type tfResource struct {
	Type    string
	Name    string
	Body    string
	Line    int
	Attrs   map[string]interface{}
}

var tfResourcePattern = regexp.MustCompile(`(?m)^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{`)

// NewTerraformScanner creates a new Terraform scanner
func NewTerraformScanner(cfg *config.Config) *TerraformScanner {
	s := &TerraformScanner{config: cfg}
	s.rules = s.loadRules()
	return s
}

// ScanFile scans a Terraform file
func (s *TerraformScanner) ScanFile(ctx context.Context, filePath, basePath string) []api.Finding {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	fileContent := string(content)
	relPath, _ := filepath.Rel(basePath, filePath)
	resources := parseTFResources(fileContent)

	var findings []api.Finding
	findings = append(findings, s.scanLineRules(ctx, fileContent, relPath)...)
	findings = append(findings, s.scanResourceRules(resources, relPath)...)
	return findings
}

func (s *TerraformScanner) scanLineRules(ctx context.Context, fileContent, relPath string) []api.Finding {
	var findings []api.Finding
	lines := strings.Split(fileContent, "\n")

	for i, line := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		lineNum := i + 1
		for _, rule := range s.rules {
			if rule.ResourceScoped || rule.Pattern == nil {
				continue
			}
			if !rule.Pattern.MatchString(line) {
				continue
			}
			if rule.Check != nil && !rule.Check(fileContent) {
				continue
			}
			findings = append(findings, api.Finding{
				ID:          fmt.Sprintf("IAC-TF-%s-%s-%d", rule.ID, pathToken(relPath), lineNum),
				Type:        api.FindingTypeMisconfiguration,
				Severity:    rule.Severity,
				Title:       rule.Name,
				Description: rule.Description,
				Location: api.Location{
					File:      relPath,
					StartLine: lineNum,
					EndLine:   lineNum,
					Snippet:   redact.Snippet(line),
				},
				Remediation: rule.Remediation,
				Scanner:     "iac",
				RuleID:      rule.ID,
				Confidence:  0.85,
			})
		}
	}
	return findings
}

func (s *TerraformScanner) scanResourceRules(resources []tfResource, relPath string) []api.Finding {
	var findings []api.Finding

	buckets := map[string]tfResource{}
	encryptionFor := map[string]bool{}
	publicBlockFor := map[string]bool{}

	for _, res := range resources {
		switch res.Type {
		case "aws_s3_bucket":
			buckets[res.Name] = res
			if acl, _ := res.Attrs["acl"].(string); acl == "public-read" || acl == "public-read-write" {
				findings = append(findings, tfFinding("aws-s3-public-acl", res.Line, relPath, res,
					"S3 Bucket with Public ACL",
					fmt.Sprintf("S3 bucket %q has public ACL %q", res.Name, acl),
					api.SeverityCritical,
					"Set ACL to 'private' and use bucket policies for controlled access"))
			}
		case "aws_s3_bucket_server_side_encryption_configuration":
			if target := resolveTFBucketRef(res.Attrs["bucket"]); target != "" {
				encryptionFor[target] = true
			}
		case "aws_s3_bucket_public_access_block":
			if target := resolveTFBucketRef(res.Attrs["bucket"]); target != "" {
				publicBlockFor[target] = true
			}
		case "aws_security_group":
			findings = append(findings, checkSecurityGroup(res, relPath)...)
		case "aws_security_group_rule":
			findings = append(findings, checkSecurityGroup(res, relPath)...)
		}
	}

	for name, bucket := range buckets {
		if !bucketHasProtection(bucket, name, encryptionFor) && !resourceBodyHas(bucket.Body, "server_side_encryption_configuration") {
			findings = append(findings, tfFinding("aws-s3-no-encryption", bucket.Line, relPath, bucket,
				"S3 Bucket Without Encryption",
				fmt.Sprintf("S3 bucket %q does not have server-side encryption enabled", name),
				api.SeverityHigh,
				"Enable server-side encryption with KMS or AES256"))
		}
		if !bucketHasProtection(bucket, name, publicBlockFor) {
			findings = append(findings, tfFinding("aws-s3-public-block-disabled", bucket.Line, relPath, bucket,
				"S3 Public Access Block Disabled",
				fmt.Sprintf("S3 bucket %q is missing public access block configuration", name),
				api.SeverityHigh,
				"Add aws_s3_bucket_public_access_block resource to prevent public access"))
		}
	}

	return findings
}

func checkSecurityGroup(res tfResource, relPath string) []api.Finding {
	var findings []api.Finding

	inspectIngress := func(block map[string]interface{}, line int) {
		cidrs := block["cidr_blocks"]
		if cidrs == nil {
			cidrs = block["cidr_block"]
		}
		ipv6 := block["ipv6_cidr_blocks"]
		if ipv6 == nil {
			ipv6 = block["ipv6_cidr_block"]
		}
		openV4 := openCIDR(cidrs)
		openV6 := openCIDR(ipv6)
		if !openV4 && !openV6 {
			return
		}
		from := asTFInt(block["from_port"])
		to := asTFInt(block["to_port"])
		scope := "0.0.0.0/0"
		if openV6 && !openV4 {
			scope = "::/0"
		} else if openV4 && openV6 {
			scope = "0.0.0.0/0 and ::/0"
		}
		findings = append(findings, tfFinding("aws-sg-open-to-world", line, relPath, res,
			"Security Group Open to Internet",
			fmt.Sprintf("Security group %q allows ingress from %s", res.Name, scope),
			api.SeverityHigh,
			"Restrict ingress to specific IP ranges or security groups"))
		if portInRange(22, from, to) {
			findings = append(findings, tfFinding("aws-sg-ssh-open", line, relPath, res,
				"SSH Port Open to Internet",
				fmt.Sprintf("Security group %q allows SSH (port 22) from %s", res.Name, scope),
				api.SeverityCritical,
				"Restrict SSH access to specific IP addresses or use bastion hosts"))
		}
		if portInRange(3389, from, to) {
			findings = append(findings, tfFinding("aws-sg-rdp-open", line, relPath, res,
				"RDP Port Open to Internet",
				fmt.Sprintf("Security group %q allows RDP (port 3389) from %s", res.Name, scope),
				api.SeverityCritical,
				"Restrict RDP access to specific IP addresses"))
		}
	}

	if res.Type == "aws_security_group_rule" {
		if t, _ := res.Attrs["type"].(string); t == "" || t == "ingress" {
			inspectIngress(res.Attrs, res.Line)
		}
		return findings
	}

	switch v := res.Attrs["ingress"].(type) {
	case map[string]interface{}:
		inspectIngress(v, res.Line)
	case []interface{}:
		for _, item := range v {
			if block, ok := item.(map[string]interface{}); ok {
				inspectIngress(block, res.Line)
			}
		}
	}

	return findings
}

func openCIDR(v interface{}) bool {
	switch t := v.(type) {
	case string:
		return t == "0.0.0.0/0" || t == "::/0"
	case []interface{}:
		for _, item := range t {
			if s, ok := item.(string); ok && (s == "0.0.0.0/0" || s == "::/0") {
				return true
			}
		}
	}
	return false
}

func resolveTFBucketRef(v interface{}) string {
	switch t := v.(type) {
	case string:
		s := strings.Trim(strings.TrimSpace(t), "\"")
		if strings.HasPrefix(s, "aws_s3_bucket.") {
			rest := strings.TrimPrefix(s, "aws_s3_bucket.")
			parts := strings.Split(rest, ".")
			if len(parts) >= 1 && parts[0] != "" {
				return parts[0]
			}
		}
		return s
	default:
		return ""
	}
}

func bucketHasProtection(bucket tfResource, name string, protected map[string]bool) bool {
	if protected[name] {
		return true
	}
	if bucketAttr, _ := bucket.Attrs["bucket"].(string); bucketAttr != "" && protected[bucketAttr] {
		return true
	}
	return false
}

func portInRange(port, from, to int) bool {
	if from == 0 && to == 0 {
		return false
	}
	if to == 0 {
		to = from
	}
	return port >= from && port <= to
}

func asTFInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	default:
		return 0
	}
}

func resourceBodyHas(body, needle string) bool {
	return strings.Contains(body, needle)
}

func tfFinding(ruleID string, line int, file string, res tfResource, title, desc string, sev api.Severity, remediation string) api.Finding {
	if line <= 0 {
		line = 1
	}
	return api.Finding{
		ID:          fmt.Sprintf("IAC-TF-%s-%s-%s-%d", ruleID, res.Name, pathToken(file), line),
		Type:        api.FindingTypeMisconfiguration,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Location: api.Location{
			File:      file,
			StartLine: line,
			EndLine:   line,
			Snippet:   redact.Snippet(fmt.Sprintf(`resource "%s" "%s"`, res.Type, res.Name)),
		},
		Remediation: remediation,
		Scanner:     "iac",
		RuleID:      ruleID,
		Confidence:  0.9,
	}
}

func parseTFResources(content string) []tfResource {
	matches := tfResourcePattern.FindAllStringSubmatchIndex(content, -1)
	var resources []tfResource
	for i, loc := range matches {
		resType := content[loc[2]:loc[3]]
		resName := content[loc[4]:loc[5]]
		open := loc[1] - 1
		for open > 0 && content[open] != '{' {
			open--
		}
		limit := len(content)
		if i+1 < len(matches) {
			limit = matches[i+1][0]
		}
		body := extractTFBlock(content, open, limit)
		line := 1 + strings.Count(content[:loc[0]], "\n")
		resources = append(resources, tfResource{
			Type:  resType,
			Name:  resName,
			Body:  body,
			Line:  line,
			Attrs: parseTFAttrs(body),
		})
	}
	return resources
}

func extractTFBlock(content string, openBrace, limit int) string {
	if openBrace < 0 || openBrace >= len(content) || content[openBrace] != '{' {
		if openBrace+1 < limit {
			return content[openBrace+1 : limit]
		}
		return ""
	}
	depth := 0
	for i := openBrace; i < len(content); i++ {
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
	tfAttrPattern  = regexp.MustCompile(`(?m)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$`)
	tfBlockPattern = regexp.MustCompile(`(?m)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\{`)
	tfRefPattern   = regexp.MustCompile(`^([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)(?:\.[a-zA-Z0-9_]+)?$`)
	tfListPattern  = regexp.MustCompile(`^\[(.*)\]$`)
)

func parseTFAttrs(body string) map[string]interface{} {
	attrs := map[string]interface{}{}

	for _, loc := range tfBlockPattern.FindAllStringSubmatchIndex(body, -1) {
		name := body[loc[2]:loc[3]]
		openIdx := strings.Index(body[loc[0]:loc[1]], "{")
		if openIdx < 0 {
			continue
		}
		absOpen := loc[0] + openIdx
		blockBody := extractTFBlock(body, absOpen, len(body))
		nested := parseTFAttrs(blockBody)
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
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasSuffix(trimmed, "{") {
			continue
		}
		m := tfAttrPattern.FindStringSubmatch(trimmed)
		if len(m) < 3 {
			continue
		}
		key := m[1]
		if _, exists := attrs[key]; exists {
			if _, isMap := attrs[key].(map[string]interface{}); isMap {
				continue
			}
			if _, isList := attrs[key].([]interface{}); isList {
				continue
			}
		}
		attrs[key] = normalizeTFValue(strings.TrimSpace(m[2]))
	}
	return attrs
}

func normalizeTFValue(raw string) interface{} {
	raw = strings.TrimSuffix(strings.TrimSpace(raw), ",")
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
		parts := splitTFList(inner)
		out := make([]interface{}, 0, len(parts))
		for _, p := range parts {
			out = append(out, normalizeTFValue(p))
		}
		return out
	}
	if strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) && len(raw) >= 2 {
		return strings.ReplaceAll(raw[1:len(raw)-1], `\"`, `"`)
	}
	if m := tfRefPattern.FindStringSubmatch(raw); len(m) == 3 {
		return m[1] + "." + m[2]
	}
	if n, err := strconv.Atoi(raw); err == nil {
		return n
	}
	return raw
}

func splitTFList(inner string) []string {
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

func (s *TerraformScanner) loadRules() []*TerraformRule {
	return []*TerraformRule{
		// Resource-scoped S3 / SG rules are evaluated in scanResourceRules.
		{ID: "aws-s3-public-acl", ResourceScoped: true},
		{ID: "aws-s3-no-encryption", ResourceScoped: true},
		{ID: "aws-s3-public-block-disabled", ResourceScoped: true},
		{ID: "aws-sg-open-to-world", ResourceScoped: true},
		{ID: "aws-sg-ssh-open", ResourceScoped: true},
		{ID: "aws-sg-rdp-open", ResourceScoped: true},

		{
			ID:          "aws-rds-public",
			Name:        "RDS Instance Publicly Accessible",
			Description: "RDS database instance is publicly accessible",
			Severity:    api.SeverityCritical,
			Pattern:     regexp.MustCompile(`publicly_accessible\s*=\s*true`),
			Remediation: "Set publicly_accessible to false",
		},
		{
			ID:          "aws-rds-no-encryption",
			Name:        "RDS Instance Without Encryption",
			Description: "RDS instance does not have encryption at rest enabled",
			Severity:    api.SeverityHigh,
			Pattern:     regexp.MustCompile(`storage_encrypted\s*=\s*false`),
			Remediation: "Enable storage_encrypted and specify kms_key_id",
		},
		{
			ID:          "aws-iam-wildcard-resource",
			Name:        "IAM Policy with Wildcard Resource",
			Description: "IAM policy allows actions on all resources (*)",
			Severity:    api.SeverityMedium,
			Pattern:     regexp.MustCompile(`"Resource":\s*"\*"`),
			Remediation: "Specify exact resource ARNs instead of using wildcards",
		},
		{
			ID:          "aws-ebs-no-encryption",
			Name:        "EBS Volume Without Encryption",
			Description: "EBS volume does not have encryption enabled",
			Severity:    api.SeverityHigh,
			Pattern:     regexp.MustCompile(`encrypted\s*=\s*false`),
			Remediation: "Enable encryption for EBS volumes",
		},
		{
			ID:          "gcp-storage-public",
			Name:        "GCP Storage Bucket Public Access",
			Description: "GCP storage bucket allows public access",
			Severity:    api.SeverityCritical,
			Pattern:     regexp.MustCompile(`member\s*=\s*"allUsers"`),
			Remediation: "Remove allUsers from IAM bindings",
		},
		{
			ID:          "azure-storage-public",
			Name:        "Azure Storage Account Public Access",
			Description: "Azure storage account allows public blob access",
			Severity:    api.SeverityHigh,
			Pattern:     regexp.MustCompile(`allow_blob_public_access\s*=\s*true`),
			Remediation: "Set allow_blob_public_access to false",
		},
		{
			ID:          "hardcoded-password",
			Name:        "Hardcoded Password in Terraform",
			Description: "Password appears to be hardcoded in configuration",
			Severity:    api.SeverityCritical,
			Pattern:     regexp.MustCompile(`(?i)password\s*=\s*"[^$\{]`),
			Remediation: "Use variables or secrets manager instead of hardcoding passwords",
		},
		{
			ID:          "http-endpoint",
			Name:        "HTTP Endpoint (Insecure)",
			Description: "HTTP endpoint detected, should use HTTPS",
			Severity:    api.SeverityMedium,
			Pattern:     regexp.MustCompile(`"http://`),
			Remediation: "Use HTTPS instead of HTTP for secure communication",
		},
	}
}
