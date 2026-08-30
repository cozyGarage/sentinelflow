package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/iac"
	"github.com/cozygarage/sentinelflow/internal/scanner/policy"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// TestPolicyAndIaCAgreeOnPrivilegedPod is the Wave E drift fixture:
// both the regex IaC scanner and OPA policy path must flag the same privileged case.
func TestPolicyAndIaCAgreeOnPrivilegedPod(t *testing.T) {
	root := t.TempDir()
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: drift-pod
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        privileged: true
`
	if err := os.WriteFile(filepath.Join(root, "pod.yaml"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}

	iacFindings := iac.NewKubernetesScanner(config.Default()).ScanFile(context.Background(), filepath.Join(root, "pod.yaml"), root)
	iacHit := false
	for _, f := range iacFindings {
		if f.RuleID == "k8s-privileged" {
			iacHit = true
			break
		}
	}
	if !iacHit {
		t.Fatal("IaC scanner missed privileged container")
	}

	policyDir := filepath.Join(root, "policies")
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		t.Fatal(err)
	}
	rego := `# METADATA
# title: No Privileged Containers
# severity: critical
package sentinelflow.kubernetes
deny_privileged[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  c.securityContext.privileged == true
  msg := sprintf("Container '%s' is running in privileged mode", [c.name])
}
`
	if err := os.WriteFile(filepath.Join(policyDir, "no-privileged.rego"), []byte(rego), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Policies.Enabled = true
	cfg.Policies.Files = []string{filepath.Join(policyDir, "*.rego")}
	cfg.Policies.Builtin = nil
	ps := policy.NewScanner(cfg)
	result, err := ps.Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("policy scan: %v", err)
	}
	policyHit := false
	for _, f := range result.Findings {
		if f.Type == api.FindingTypePolicyViolation {
			policyHit = true
			break
		}
	}
	if !policyHit {
		t.Fatal("policy scanner missed privileged container that IaC found")
	}
}
