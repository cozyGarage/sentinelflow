package secrets

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// verifyHTTP is swapped in tests. Live verification is opt-in (--verify-secrets).
var verifyHTTP = &http.Client{Timeout: 5 * time.Second}

// applyLiveVerify checks a provider endpoint when scanners.secrets.verify is on.
// Returns keep=false when the provider rejects the credential (false positive).
// Network errors keep the finding and append a warning.
func applyLiveVerify(ctx context.Context, f *api.Finding, secret string) (keep bool, warning string) {
	endpoint, header, value := verifyProvider(f.RuleID, secret)
	if endpoint == "" {
		return true, ""
	}
	ok, err := checkEndpoint(ctx, endpoint, header, value)
	if err != nil {
		if f.Metadata == nil {
			f.Metadata = map[string]any{}
		}
		f.Metadata["verified"] = "error"
		return true, fmt.Sprintf("verify %s: %v", f.RuleID, err)
	}
	if !ok {
		return false, ""
	}
	f.Confidence = 1.0
	if f.Metadata == nil {
		f.Metadata = map[string]any{}
	}
	f.Metadata["verified"] = true
	return true, ""
}

func checkEndpoint(ctx context.Context, endpoint, header, value string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	if header != "" {
		req.Header.Set(header, value)
	}
	resp, err := verifyHTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
}

func verifyProvider(ruleID, token string) (endpoint, header, value string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", "", ""
	}
	switch ruleID {
	case "github-token", "github-app-token":
		return "https://api.github.com/user", "Authorization", "Bearer " + token
	case "gitlab-token":
		return "https://gitlab.com/api/v4/user", "PRIVATE-TOKEN", token
	case "slack-token":
		return "https://slack.com/api/auth.test", "Authorization", "Bearer " + token
	case "stripe-secret-key":
		return "https://api.stripe.com/v1/balance", "Authorization", "Bearer " + token
	case "openai-api-key":
		return "https://api.openai.com/v1/models", "Authorization", "Bearer " + token
	default:
		return "", "", ""
	}
}
