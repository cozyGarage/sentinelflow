// Package buildinfo holds version metadata set at link time / process start.
package buildinfo

// Version is the product version embedded in scan reports (overridden by ldflags).
var Version = "1.0.0"

// Commit is the git commit (optional).
var Commit = "none"

// Date is the build date (optional).
var Date = "unknown"

// Set updates version metadata from main/ldflags.
func Set(version, commit, date string) {
	if version != "" {
		Version = version
	}
	if commit != "" {
		Commit = commit
	}
	if date != "" {
		Date = date
	}
}
