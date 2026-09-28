package api

import "fmt"

// Process exit codes for CI gates.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitTool     = 2
	ExitTimeout  = 3
)

// ExitError is a typed error that maps to a process exit code.
type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("exit %d", e.Code)
}

func (e *ExitError) ExitCode() int {
	if e == nil {
		return ExitTool
	}
	return e.Code
}

func ErrFindings(msg string) error {
	return &ExitError{Code: ExitFindings, Message: msg}
}

func ErrTool(msg string) error {
	return &ExitError{Code: ExitTool, Message: msg}
}

func ErrTimeout(msg string) error {
	return &ExitError{Code: ExitTimeout, Message: msg}
}
