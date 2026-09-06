package hostremoval

import (
	"context"
	"errors"
	"testing"
)

type removalMemory struct{ state state }

func (m *removalMemory) Transact(_ context.Context, _ bool, fn func(*state) error) error {
	return fn(&m.state)
}

func TestRemovalRetainsInventoryAndResumesOnlyTerminationAfterUnknownOutcome(t *testing.T) {
	journal := &Journal{journal: &removalMemory{state: state{Operations: map[string]Operation{}}}}
	member := MemberObservation{Identity: "spiffe://member", ResourceID: "ocid1.instance.original", Generation: 7}
	var inventory, replace, revalidate, fence, observe, terminate int
	unknown := errors.New("unknown provider outcome")
	owner := &Owner{Journal: journal,
		Inventory: func(context.Context, RemovalRequest, []Replacement) (uint64, []Replacement, error) {
			inventory++
			return 1, []Replacement{{DatabaseID: "db", IssuerOperationID: "replace", ProposalDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, nil
		},
		Replace:    func(context.Context, Replacement) error { replace++; return nil },
		Revalidate: func(context.Context, string, string, uint64) error { revalidate++; return nil },
		Fence:      func(context.Context, string, string, []Replacement) error { fence++; return nil },
		Observe:    func(context.Context, string) (bool, error) { observe++; return true, nil },
		Terminate: func(context.Context, string) error {
			terminate++
			if terminate == 1 {
				return unknown
			}
			return nil
		},
	}
	if err := owner.RemoveMember(t.Context(), "remove", member, 7); !errors.Is(err, unknown) {
		t.Fatalf("first attempt: %v", err)
	}
	replacementResource := member
	replacementResource.ResourceID = "ocid1.instance.replacement"
	if err := owner.RemoveMember(t.Context(), "remove", replacementResource, 7); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed OCI resource: %v", err)
	}
	if err := owner.RemoveMember(t.Context(), "remove", member, 7); err != nil {
		t.Fatal(err)
	}
	if err := owner.RemoveMember(t.Context(), "remove", member, 7); err != nil {
		t.Fatal(err)
	}
	if inventory != 1 || replace != 1 || revalidate != 1 || fence != 1 || observe != 2 || terminate != 2 {
		t.Fatalf("effects replayed: inventory=%d replace=%d revalidate=%d fence=%d observe=%d terminate=%d", inventory, replace, revalidate, fence, observe, terminate)
	}
}
