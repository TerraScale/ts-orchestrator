package membership

import (
	"context"
	"time"
)

// LedgerSource reads every slot's historically verified current HEAD.
type LedgerSource interface {
	Slots(context.Context, []string) (map[string]LedgerSlot, error)
}

// RetirementRequest describes a lost slot whose exact prior instance needs
// offline root-signed retirement evidence before it can be replaced.
type RetirementRequest struct {
	Slot         string
	Attempt      uint64
	InstanceOCID string
	Lifecycle    string
	MetaLeader   string
	OfflineSince time.Time
	ObservedAt   time.Time
	Epoch        uint64
}
