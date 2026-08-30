// SentinelFlow - CI/CD Security Gatekeeper
// Main entry point for the CLI application

package main

import (
	"os"

	"github.com/cozygarage/sentinelflow/internal/buildinfo"
	"github.com/cozygarage/sentinelflow/internal/cli"
)

// Version information (set by build flags)
var (
	version = "1.0.0"
	commit  = "none"
	date    = "unknown"
)

func main() {
	buildinfo.Set(version, commit, date)
	cli.SetVersionInfo(version, commit, date)

	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
