package api

import (
	"errors"
	"testing"
)

func TestSC003_ExitCodeContract(t *testing.T) {
	if ExitOK != 0 || ExitFindings != 1 || ExitTool != 2 || ExitTimeout != 3 {
		t.Fatalf("CI exit contract changed: ok=%d findings=%d tool=%d timeout=%d", ExitOK, ExitFindings, ExitTool, ExitTimeout)
	}
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
