// Package buildinfo holds version metadata set at link time / process start.
package buildinfo

// Version is the product version embedded in scan reports (overridden by ldflags).
var Version = "1.0.0"

// Set updates version metadata from main/ldflags.
// commit and date are accepted for ldflag compatibility but unused in reports
// (CLI version output uses internal/cli.SetVersionInfo instead).
func Set(version, _, _ string) {
	if version != "" {
		Version = version
	}
}
