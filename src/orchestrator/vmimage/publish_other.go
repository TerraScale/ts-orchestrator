//go:build !linux

package vmimage

import "errors"

func publishDirectory(_, _ string) error {
	return errors.New("vmimage: atomic no-replace publication requires Linux")
}
