package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
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
