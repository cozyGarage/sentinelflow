package secrets

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestApplyLiveVerifyDropsRejected(t *testing.T) {
	prev := verifyHTTP
	t.Cleanup(func() { verifyHTTP = prev })
	verifyHTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer ghp_testtoken" {
			t.Errorf("unexpected auth %q", r.Header.Get("Authorization"))
		}
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}

	f := api.Finding{RuleID: "github-token", Confidence: 0.9}
	keep, warn := applyLiveVerify(context.Background(), &f, "ghp_testtoken")
	if warn != "" {
		t.Fatalf("warn: %s", warn)
	}
	if keep {
		t.Fatal("expected rejected token to be dropped")
	}
}

func TestApplyLiveVerifyConfirmsValid(t *testing.T) {
	prev := verifyHTTP
	t.Cleanup(func() { verifyHTTP = prev })
	verifyHTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"login":"x"}`)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}

	f := api.Finding{RuleID: "github-token", Confidence: 0.9}
	keep, warn := applyLiveVerify(context.Background(), &f, "ghp_testtoken")
	if !keep || warn != "" {
		t.Fatalf("keep=%v warn=%s", keep, warn)
	}
	if f.Confidence != 1.0 || f.Metadata["verified"] != true {
		t.Fatalf("%+v", f)
	}
}

func TestApplyLiveVerifySkipsUnknownRule(t *testing.T) {
	f := api.Finding{RuleID: "aws-access-key"}
	keep, warn := applyLiveVerify(context.Background(), &f, "AKIATEST")
	if !keep || warn != "" {
		t.Fatalf("aws keys are not live-verified: keep=%v warn=%s", keep, warn)
	}
}
