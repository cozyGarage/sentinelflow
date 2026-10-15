package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

const testPrivilegedPolicy = `# METADATA
# title: No Privileged Containers
# severity: critical

package sentinelflow.kubernetes

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}

deny_privileged[msg] {
	input.kind == "Pod"
	container := input.spec.containers[_]
	container.securityContext.privileged == true
	msg := sprintf("Container '%s' is running in privileged mode", [container.name])
}
`

func TestScannerDetectsPrivilegedContainer(t *testing.T) {
	root := t.TempDir()

	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
`
	if err := os.WriteFile(filepath.Join(root, "pod.yaml"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}

	policyDir := filepath.Join(root, "policies")
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "no-privileged-containers.rego"), []byte(testPrivilegedPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(&config.Config{Policies: config.PoliciesConfig{Enabled: true}})
	result, err := scanner.Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected policy violation for privileged container")
	}

	found := false
	for _, f := range result.Findings {
		if f.Type == api.FindingTypePolicyViolation {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected policy violation finding, got %+v", result.Findings)
	}
}

func TestBrokenCustomPolicySurfacesError(t *testing.T) {
	root := t.TempDir()
	policyDir := filepath.Join(root, ".sentinelflow", "policies")
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Invalid Rego — must not be silently ignored when builtins also load.
	if err := os.WriteFile(filepath.Join(policyDir, "broken.rego"), []byte("package broken\n{ this is not rego }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Policies.Enabled = true
	cfg.Policies.Builtin = []string{"no-privileged-containers"}
	_, err := NewScanner(cfg).Scan(context.Background(), root, nil)
	if err == nil {
		t.Fatal("expected broken custom policy to fail the policy scanner")
	}
	if !strings.Contains(err.Error(), "failed to load policies") {
		t.Fatalf("expected load failure message, got %v", err)
	}
}

func TestConvertToFindingsIDsIndependentOfPosition(t *testing.T) {
	a := PolicyViolation{Message: "a", Resource: "pod.yaml"}
	b := PolicyViolation{Message: "b", Resource: "pod.yaml"}
	alone := ConvertToFindings(&PolicyResult{PolicyName: "p", Violations: []PolicyViolation{b}}, api.SeverityHigh)
	both := ConvertToFindings(&PolicyResult{PolicyName: "p", Violations: []PolicyViolation{a, b}}, api.SeverityHigh)
	if alone[0].ID != both[1].ID {
		t.Fatalf("ID of violation b changed when a appeared: %s vs %s", alone[0].ID, both[1].ID)
	}
}

func TestScannerHonorsEngineFileList(t *testing.T) {
	root := t.TempDir()
	manifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: app\n      securityContext:\n        privileged: true\n"
	if err := os.WriteFile(filepath.Join(root, "pod.yaml"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	policyDir := filepath.Join(root, "policies")
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "no-privileged-containers.rego"), []byte(testPrivilegedPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	// The engine excluded pod.yaml, so the policy scanner must not walk the tree and find it.
	scanner := NewScanner(&config.Config{Policies: config.PoliciesConfig{Enabled: true}})
	result, err := scanner.Scan(context.Background(), root, types.ScanOptions{Files: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("excluded file was scanned: %+v", result.Findings)
	}
}

func TestScannerAcceptsV0AndOptInV1Rego(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pod.yaml"), []byte("apiVersion: v1\nkind: Pod\nbad: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	policyDir := filepath.Join(root, "policies")
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		t.Fatal(err)
	}
	policies := map[string]string{
		"v0.rego": "package sentinelflow.v0\n\ndeny[msg] {\n  input.bad\n  msg := \"v0\"\n}\n",
		"v1.rego": "package sentinelflow.v1\n\nimport rego.v1\n\ndeny contains msg if {\n  input.bad\n  msg := \"v1\"\n}\n",
	}
	for name, src := range policies {
		if err := os.WriteFile(filepath.Join(policyDir, name), []byte(src), 0644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := NewScanner(&config.Config{Policies: config.PoliciesConfig{Enabled: true}}).Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Description] = true
	}
	if !got["v0"] || !got["v1"] {
		t.Fatalf("want violations from both syntaxes, got %+v", res.Findings)
	}
}
