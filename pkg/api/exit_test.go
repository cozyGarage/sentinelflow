package api

import (
	"errors"
	"testing"
)

func TestExitErrorCodes(t *testing.T) {
	cases := []struct {
		err  error
		code int
	}{
		{ErrFindings("gate"), ExitFindings},
		{ErrTool("boom"), ExitTool},
		{ErrTimeout("late"), ExitTimeout},
	}
	for _, tc := range cases {
		var ee *ExitError
		if !errors.As(tc.err, &ee) {
			t.Fatalf("expected ExitError for %v", tc.err)
		}
		if ee.ExitCode() != tc.code {
			t.Fatalf("%v: code %d want %d", tc.err, ee.ExitCode(), tc.code)
		}
	}
}
