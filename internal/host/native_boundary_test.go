//go:build linux

package host

import (
	"errors"
	"os"

	"syscall"
)

func nativeTestCgroupUnavailable(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) || errors.Is(err, errNativeSubgroupRequired)
}
