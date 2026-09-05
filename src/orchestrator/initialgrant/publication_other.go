//go:build !linux

package initialgrant

import "errors"

func renamePublishedProof(int, string) error {
	return errors.New("initialgrant: host proof publication requires Linux")
}
