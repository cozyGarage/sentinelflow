package policy

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// OPAEngine wraps the OPA policy engine
type OPAEngine struct {
	policies map[string]*rego.PreparedEvalQuery
	modules  map[string]string
}

// NewOPAEngine creates a new OPA engine
func NewOPAEngine() *OPAEngine {
	return &OPAEngine{
		policies: make(map[string]*rego.PreparedEvalQuery),
		modules:  make(map[string]string),
	}
}

// LoadPolicy loads a single Rego policy
func (e *OPAEngine) LoadPolicy(name, content string) error {
	query, err := rego.New(
		rego.Query("data"),
		rego.Module(name+".rego", content),
	).PrepareForEval(context.Background())

	if err != nil {
		return fmt.Errorf("failed to compile policy %s: %w", name, err)
	}

	e.policies[name] = &query
	e.modules[name] = content

	return nil
}

// LoadPoliciesFromDir loads all .rego files from a directory
func (e *OPAEngine) LoadPoliciesFromDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read policy %s: %w", path, err)
		}

		name := strings.TrimSuffix(filepath.Base(path), ".rego")
		return e.LoadPolicy(name, string(content))
	})
}

// EvaluatePolicy evaluates a policy against input data
func (e *OPAEngine) EvaluatePolicy(policyName string, input interface{}) (*PolicyResult, error) {
	query, ok := e.policies[policyName]
	if !ok {
		return nil, fmt.Errorf("policy %s not found", policyName)
	}

	results, err := query.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	result := &PolicyResult{
		PolicyName: policyName,
		Violations: []PolicyViolation{},
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return result, nil
	}

	// Walk the data tree to collect violation messages from any rule
	data, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return result, nil
	}

	collectViolations(data, &result.Violations)
	return result, nil
}

// collectViolations recursively searches for violation messages in OPA output
func collectViolations(data map[string]interface{}, violations *[]PolicyViolation) {
	for _, v := range data {
		switch val := v.(type) {
		case map[string]interface{}:
			collectViolations(val, violations)
		case []interface{}:
			for _, item := range val {
				switch msg := item.(type) {
				case string:
					*violations = append(*violations, PolicyViolation{Message: msg})
				case map[string]interface{}:
					violation := PolicyViolation{
						Message:  getString(msg, "msg"),
						Resource: getString(msg, "resource"),
					}
					if violation.Message != "" {
						*violations = append(*violations, violation)
					}
				}
			}
		}
	}
}

// ValidatePolicy validates policy syntax without evaluating
func (e *OPAEngine) ValidatePolicy(content string) error {
	_, err := rego.New(
		rego.Query("data"),
		rego.Module("test.rego", content),
	).PrepareForEval(context.Background())

	return err
}

// ListPolicies returns all loaded policy names
func (e *OPAEngine) ListPolicies() []string {
	names := make([]string, 0, len(e.policies))
	for name := range e.policies {
		names = append(names, name)
	}
	return names
}

// PolicyCount returns the number of loaded policies.
func (e *OPAEngine) PolicyCount() int {
	return len(e.policies)
}

// PolicyResult contains the result of policy evaluation
type PolicyResult struct {
	PolicyName string
	Violations []PolicyViolation
}

// PolicyViolation represents a single policy violation
type PolicyViolation struct {
	Message  string
	Resource string
}

// helper to extract string from map
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ConvertToFindings converts policy violations to API findings
func ConvertToFindings(result *PolicyResult, severity api.Severity) []api.Finding {
	var findings []api.Finding

	for i, violation := range result.Violations {
		finding := api.Finding{
			ID:          fmt.Sprintf("POLICY-%s-%s-%d", result.PolicyName, pathToken(violation.Resource), i),
			Type:        api.FindingTypePolicyViolation,
			Severity:    severity,
			Title:       fmt.Sprintf("Policy Violation: %s", result.PolicyName),
			Description: violation.Message,
			Scanner:     "policy",
			RuleID:      result.PolicyName,
			Confidence:  1.0,
		}

		if violation.Resource != "" {
			finding.Location.File = violation.Resource
		}

		findings = append(findings, finding)
	}

	return findings
}

func pathToken(relPath string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(filepath.ToSlash(relPath)))
	return fmt.Sprintf("%08x", h.Sum32())
}
