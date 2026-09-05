package hostmanifest

import (
	"path/filepath"
	"strings"
)

// SafeAbsolutePath admits canonical absolute paths for manifests and host roots.
func SafeAbsolutePath(value string) bool {
	if value == "" || !filepath.IsAbs(value) || strings.ContainsAny(value, " \t\x00\r\n\\") {
		return false
	}
	clean := filepath.Clean(value)
	if clean == "." || clean == string(filepath.Separator) || clean != value {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(value), "/") {
		if part == ".." {
			return false
		}
	}
	return true
}
