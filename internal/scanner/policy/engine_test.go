package policy

import (
	"testing"
)

func TestValidatePolicy(t *testing.T) {
	engine := NewOPAEngine()
	validPolicy := `package test

allow {
    input.secure == true
}
`
	if err := engine.ValidatePolicy(validPolicy); err != nil {
		t.Fatalf("expected valid policy, got error: %v", err)
	}
}

func TestValidatePolicyInvalid(t *testing.T) {
	engine := NewOPAEngine()
	invalidPolicy := `package test

allow {
    input.secure ====
}
`
	if err := engine.ValidatePolicy(invalidPolicy); err == nil {
		t.Error("expected validation error for invalid policy")
	}
}

func TestEvaluatePolicy(t *testing.T) {
	engine := NewOPAEngine()
	policy := `package sentinelflow.test

violation[msg] {
    input.insecure == true
    msg := "Resource is insecure"
}
`
	if err := engine.LoadPolicy("test", policy); err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	result, err := engine.EvaluatePolicy("test", map[string]interface{}{"insecure": true})
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations")
	}
}

func TestEvaluatePolicyIgnoresHelperSets(t *testing.T) {
	engine := NewOPAEngine()
	policy := `package sentinelflow.kubernetes

workload_kinds := {"Deployment", "StatefulSet"}

deny_privileged[msg] {
	input.kind == "Pod"
	input.spec.containers[_].securityContext.privileged == true
	msg := "privileged container"
}
`
	if err := engine.LoadPolicy("no-priv", policy); err != nil {
		t.Fatalf("load: %v", err)
	}

	// Non-violating input still exposes workload_kinds as a string set in OPA data.
	result, err := engine.EvaluatePolicy("no-priv", map[string]interface{}{
		"kind": "ConfigMap",
		"metadata": map[string]interface{}{"name": "x"},
	})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Fatalf("helper set must not become violations, got %+v", result.Violations)
	}

	result, err = engine.EvaluatePolicy("no-priv", map[string]interface{}{
		"kind": "Pod",
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name": "app",
					"securityContext": map[string]interface{}{
						"privileged": true,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("eval privileged: %v", err)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 deny violation, got %+v", result.Violations)
	}
}

func TestIsViolationRuleKey(t *testing.T) {
	cases := map[string]bool{
		"deny":           true,
		"deny_privileged": true,
		"violation":      true,
		"violation_msg":  true,
		"violations":     true,
		"workload_kinds": false,
		"allow":          false,
		"is_true":        false,
	}
	for k, want := range cases {
		if got := isViolationRuleKey(k); got != want {
			t.Errorf("isViolationRuleKey(%q)=%v want %v", k, got, want)
		}
	}
}
