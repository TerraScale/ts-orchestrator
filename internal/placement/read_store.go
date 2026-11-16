package placement

import (
	"context"
)

// ListingReader exposes admitted placement and retained seats without writes.
type ListingReader interface {
	ListIntents(context.Context) ([]Intent, error)
	ListMembers(context.Context, string, string) ([]VersionedMemberState, error)
}
