package main

import (
	"sudo-check/cmd"
	"sudo-check/internal/buildinfo"
)

// Build-time variables injected via -ldflags.
// Example: go build -ldflags="-X main.version=1.0.0 -X main.commit=$(git rev-parse HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	buildinfo.Set(version, commit, date)
	cmd.Execute()
}
