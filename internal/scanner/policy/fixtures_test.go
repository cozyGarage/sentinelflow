package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/testutil"
	policiespkg "github.com/cozygarage/sentinelflow/policies"
)

func TestBuiltinPoliciesAgainstFixtures(t *testing.T) {
	cases := []struct {
		policy  string
		fixture string
	}{
		{"no-privileged-containers", "policy/k8s-privileged-pod.json"},
		{"no-privileged-containers", "policy/k8s-privileged-init.json"},
		{"no-public-s3-buckets", "policy/terraform-public-s3.json"},
	}

	for _, tc := range cases {
		t.Run(tc.policy+"/"+tc.fixture, func(t *testing.T) {
			builtin, err := policiespkg.Get(tc.policy)
			if err != nil {
				t.Fatalf("load builtin: %v", err)
			}

			var input interface{}
			if err := json.Unmarshal(testutil.ReadFixture(t, tc.fixture), &input); err != nil {
				t.Fatalf("parse fixture: %v", err)
			}

			engine := NewOPAEngine()
			if err := engine.LoadPolicy(tc.policy, builtin.Content); err != nil {
				t.Fatalf("load policy: %v", err)
			}
			result, err := engine.EvaluatePolicy(context.Background(), tc.policy, input)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if len(result.Violations) == 0 {
				t.Fatalf("expected violations for fixture %s", tc.fixture)
			}
		})
	}
}
