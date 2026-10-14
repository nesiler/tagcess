// Package version holds the build version. Release builds override both values:
//
//	go build -ldflags "-X github.com/nesiler/tagcess/internal/version.Version=v1.2.3 \
//	                   -X github.com/nesiler/tagcess/internal/version.Commit=abc1234"
package version

import "fmt"

var (
	// Version is the release version, or a development placeholder.
	Version = "0.1.0-dev"
	// Commit is the source revision the binary was built from.
	Commit = "unknown"
)

// String returns "<name> <version> (<commit>)".
func String(name string) string { return format(name, Version, Commit) }

func format(name, version, commit string) string {
	if version == "" {
		version = "unknown"
	}
	if commit == "" {
		commit = "unknown"
	}
	return fmt.Sprintf("%s %s (%s)", name, version, commit)
}

// IsVersionFlag reports whether args is exactly a single -version or --version flag.
func IsVersionFlag(args []string) bool {
	return len(args) == 1 && (args[0] == "-version" || args[0] == "--version")
}
