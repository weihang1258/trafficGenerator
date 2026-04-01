package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the semantic version.
	Version = "1.0.0"
	// GitCommit is the git commit hash.
	GitCommit = "unknown"
	// BuildDate is the build date.
	BuildDate = "unknown"
	// GoVersion is the Go version.
	GoVersion = runtime.Version()
)

// Info returns version information.
func Info() map[string]string {
	return map[string]string{
		"version":    Version,
		"git_commit": GitCommit,
		"build_date": BuildDate,
		"go_version": GoVersion,
		"platform":   fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// String returns a formatted version string.
func String() string {
	return fmt.Sprintf("Traffic Generator v%s (git: %s, built: %s, go: %s)",
		Version, GitCommit, BuildDate, GoVersion)
}
