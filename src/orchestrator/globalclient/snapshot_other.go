//go:build !unix

package globalclient

import (
	"context"
	"errors"
)

var errIdentityFiles = errors.New("global worker identity files require Unix descriptor admission")

func readIdentityFile(context.Context, string, int64, bool) ([]byte, error) {
	return nil, errIdentityFiles
}
