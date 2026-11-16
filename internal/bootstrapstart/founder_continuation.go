package bootstrapstart

import (
	"errors"
	"time"
)

var ErrFounderPeerContinuation = errors.New("current founder peer continuation is unavailable")

// FounderPeerContinuation verifies a current selected plan against an already
// accepted, historically completed peer. It grants no OCI or ledger effects.
type FounderPeerContinuation struct {
	reader     *CurrentFounderAuthorityReader
	floor      *FounderSelectionFloorStore
	serviceUID uint32
	serviceGID uint32
	now        func() time.Time
}
