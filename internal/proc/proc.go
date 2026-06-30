// Package proc discovers and stops running Interceptor processes by image name.
package proc

import (
	"path/filepath"
	"strings"
)

const (
	unixBinaryName    = "interceptor"
	windowsBinaryName = "interceptor.exe"
)

// Proc is a discovered interceptor process.
type Proc struct {
	PID  int
	Path string // absolute path to the binary, if known
}

// matchesInterceptor reports whether baseName is an Interceptor executable.
func matchesInterceptor(baseName string) bool {
	baseName = strings.TrimSpace(baseName)
	return baseName == unixBinaryName || baseName == windowsBinaryName
}

// baseFromPath returns the executable base name from path, or "" when empty.
func baseFromPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}
