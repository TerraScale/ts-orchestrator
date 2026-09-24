// Package authority provides regional leadership, fencing, and the ordered
// control log shared by authority changes and host mutations.
package authority

import (
	"context"
	"errors"
	"time"
)

const (
	controlStreamName    = "TS_CONTROL_LOG"
	controlSubjectRoot   = "ts.control"
	defaultLeaseDuration = 15 * time.Second
	defaultRenewInterval = 3 * time.Second
	defaultReplicas      = 3
	maxControlPayload    = 1 << 20
	maxPlacementIntents  = 10_000
)

var (
	ErrNotLeader         = errors.New("authority is not the current leader")
	ErrFenced            = errors.New("authority epoch has been fenced")
	ErrLeaseCorrupt      = errors.New("authority lease record is corrupt")
	ErrConflict          = errors.New("control log compare-and-set conflict")
	ErrNotFound          = errors.New("control log entry not found")
	ErrOperationConflict = errors.New("operation ID is already bound to different content")
	ErrOutcomeUnknown    = errors.New("control log publish outcome is unknown")
	ErrInvalidTransition = errors.New("invalid operation journal transition")
	ErrProofConsumed     = errors.New("operation proof has already been consumed")
	ErrListTooLarge      = errors.New("placement intent count exceeds the configured bound")
)

// Config identifies this candidate within one regional or global control log.
// Scope and CandidateID must be lowercase NATS tokens. The runtime adds a
// random process ID so restarting or duplicating a candidate cannot adopt its
// previous incarnation's lease.
type Config struct {
	Scope         string
	CandidateID   string
	LeaseDuration time.Duration
	RenewInterval time.Duration
	Replicas      int
}

// Snapshot is the latest lease observation made by this runtime.
type Snapshot struct {
	Scope       string
	CandidateID string
	OwnerID     string
	Leader      bool
	Ready       bool
	Epoch       uint64
	Revision    uint64
	ExpiresAt   time.Time
	ObservedAt  time.Time
	Reason      string
}

// CanMutate reports whether this snapshot grants the local candidate a live
// lease. Mutating consumers must still call Guard immediately before effects.
func (s Snapshot) CanMutate() bool {
	return s.Ready && s.Leader && s.Epoch > 0 && s.Revision > 0 &&
		!s.ExpiresAt.IsZero() && time.Now().Before(s.ExpiresAt)
}

// Fencer is the narrow consumer contract for mutation paths.
type Fencer interface {
	Current() Snapshot
	Guard(context.Context, uint64) error
}

// HostMutationKind selects a restricted family of host state records in the
// ordered control log.
type HostMutationKind string

const (
	MutationRegistration    HostMutationKind = "registration"
	MutationDesired         HostMutationKind = "desired"
	MutationPlacementIntent HostMutationKind = "placement-intent"
)

// LogEntry is a host mutation committed to the shared ordered control log.
type LogEntry struct {
	Kind        HostMutationKind
	SubjectKey  string
	OperationID string
	Epoch       uint64
	Sequence    uint64
	CreatedAt   time.Time
	Payload     []byte
}

// HostMutationStore exposes the fenced host record log to the host feature.
type HostMutationStore interface {
	CommitHostMutation(context.Context, uint64, HostMutationKind, string, string, uint64, []byte) (uint64, error)
	ReadHostMutation(context.Context, HostMutationKind, string) (LogEntry, error)
}

// PlacementIntentStore shares the ordered authority stream for admitted
// placement records so a new lease epoch cannot race an older placement write.
type PlacementIntentStore interface {
	CommitPlacementIntent(context.Context, uint64, string, string, string, uint64, []byte) (uint64, error)
	ReadPlacementIntent(context.Context, string, string) (LogEntry, error)
	ListPlacementIntents(context.Context) ([]LogEntry, error)
}
