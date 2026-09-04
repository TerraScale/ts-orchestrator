//go:build !linux

package security

import "os"

// unixMode is a no-op off Linux: every caller fails closed before reaching it
// because secret file handling requires Linux permissions.
func unixMode(info os.FileInfo) uint32 {
	return 0
}
