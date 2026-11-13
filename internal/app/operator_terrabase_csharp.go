package app

import (
	"errors"
)

// errBadRelease is evidence against a release itself: a replica reported it
// failed, or its canary failed the gate. A timeout or a lost lease is not.
var errBadRelease = errors.New("the release is bad")
