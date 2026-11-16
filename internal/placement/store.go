package placement

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

var (
	ErrStoreConflict  = errors.New("placement state compare-and-swap conflict")
	ErrStoreCorrupt   = errors.New("placement state is corrupt")
	ErrMemberNotFound = errors.New("placement member state not found")
)

// AdmittedIntentReader returns only placement intents committed by the
// regional authority path. It must not expose operator drafts or unauthenticated
// values from a mutable local file.
type AdmittedIntentReader interface {
	ListPlacementIntents(context.Context, string) ([]Intent, error)
	ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error)
}

type VersionedMemberState struct {
	State    MemberState
	Revision uint64
}

// MemberPinReader looks up one exact durable Go placement seat. It must not
// scan the state bucket or substitute a different member when the key is absent.
type MemberPinReader interface {
	ReadMember(context.Context, string, string, string) (VersionedMemberState, error)
}
