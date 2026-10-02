// SentinelFlow - CI/CD Security Gatekeeper
// Main entry point for the CLI application

package main

import (
	"errors"
	"os"

	"github.com/cozygarage/sentinelflow/internal/buildinfo"
	"github.com/cozygarage/sentinelflow/internal/cli"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

// Version information (set by build flags)
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	buildinfo.Set(version, commit, date)
	cli.SetVersionInfo(version, commit, date)

	if err := cli.Execute(); err != nil {
		var ee *api.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		os.Exit(api.ExitTool)
	}
}
