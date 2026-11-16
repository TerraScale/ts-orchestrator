package manager

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

// Loop lets the cell's leading controller keep the manager reconciled. It
// never returns an error and recovers from panics: NetBird trouble is logged
// and retried with backoff, and never affects the controller.
type Loop struct {
	// Authority is the GRU account authority. Each cycle pins its owner and epoch.
	Authority authority.Fencer
	// Leader reports whether this controller currently holds cell authority.
	// Older callers use Leader until their authority wiring is migrated.
	Leader func() bool
	// Token reads the current admin PAT; the loop clears it after use.
	Token         func(context.Context) ([]byte, error)
	ManagementURL string
	Desired       Desired
	Interval      time.Duration // default 5m, jittered by up to +-20%
	OfflineFor    time.Duration // default DefaultOfflineFor
	Logf          func(format string, args ...any)
	// Test seams.
	newAPI       func(managementURL, token string) (*API, error)
	initialDelay time.Duration
}
