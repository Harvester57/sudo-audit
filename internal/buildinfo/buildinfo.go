// Package buildinfo holds build-time version metadata injected via ldflags.
// It exists as a separate package to avoid import cycles between cmd and report.
package buildinfo

// Build-time variables. Set by main.go via Set().
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Set updates the build-time metadata. Called once by main().
func Set(version, commit, date string) {
	Version = version
	Commit = commit
	Date = date
}
