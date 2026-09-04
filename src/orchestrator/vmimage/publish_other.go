//go:build !linux

package vmimage

import (
	"errors"
	"os"
)

func publishDirectory(_, _ string) error {
	return errors.New("vmimage: atomic no-replace publication requires Linux")
}

func publishDownload(staging, target string) error {
	if err := os.Link(staging, target); err != nil {
		return err
	}
	return os.Remove(staging)
}
