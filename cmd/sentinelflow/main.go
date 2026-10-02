// SentinelFlow - CI/CD Security Gatekeeper
// Main entry point for the CLI application

package main

import (
	"errors"
	"os"
	"runtime/debug"
	"strings"

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
	// `go install …@vX.Y.Z` has no ldflags; use the module version instead of "dev".
	if bi, ok := debug.ReadBuildInfo(); ok && version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = strings.TrimPrefix(bi.Main.Version, "v")
	}
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
