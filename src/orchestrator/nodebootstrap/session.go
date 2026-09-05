package nodebootstrap

import (
	"context"
	"time"
)

// InitialSession is an authenticated manifest snapshot with only its finite
// journaled initial actions. Close releases receiver ownership; after Retired
// the caller must not execute initial actions. M is the consumer's typed host
// manifest so this leaf package does not depend on lifecycle implementation.
type InitialSession[M any] struct {
	Manifest  M
	ExpiresAt time.Time
	Retired   bool
	Execute   func(context.Context, int) error
	Ready     func(context.Context) (bool, error)
	Close     func() error
}
