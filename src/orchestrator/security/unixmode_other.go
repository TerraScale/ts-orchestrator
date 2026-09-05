//go:build !linux

package security

import (
	"errors"
	"os"
)

// unixMode is a no-op off Linux: every caller fails closed before reaching it
// because secret file handling requires Linux permissions.
func unixMode(info os.FileInfo) uint32 {
	return 0
}

func openCommandSigningCredential(path string) (*os.File, error) {
	return nil, errors.New("command signing credential files require Linux")
}
