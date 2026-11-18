package appregistry

import (
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

func SameDigest(first, second string) bool {
	a, err := name.NewDigest(first)
	if err != nil || !strings.HasPrefix(a.DigestStr(), "sha256:") {
		return false
	}
	b, err := name.NewDigest(second)
	return err == nil && a.DigestStr() == b.DigestStr()
}
