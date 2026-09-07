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
	member := MemberObservation{ProviderETag: "etag", Identity: "spiffe://member", ResourceID: "ocid1.instance.original", Generation: 7}
	var inventory, replace, revalidate, fence, observe, terminate int
	unknown := errors.New("unknown provider outcome")
	owner := &Owner{Journal: journal, ReconcileTermination: func(context.Context, string) error { return nil },
		Inventory: func(context.Context, RemovalRequest, []Replacement) (uint64, []Replacement, error) {
			inventory++
			return 1, []Replacement{{DatabaseID: "db", IssuerOperationID: "replace", ProposalDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, nil
		},
		Replace:    func(context.Context, Replacement) error { replace++; return nil },
		Revalidate: func(context.Context, string, string, uint64) error { revalidate++; return nil },
		Fence:      func(context.Context, string, string, []Replacement) error { fence++; return nil },
		Observe:    func(context.Context, string) (bool, error) { observe++; return terminate < 2, nil },
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
	if inventory != 1 || replace != 1 || revalidate != 1 || fence != 1 || observe != 3 || terminate != 2 {
		t.Fatalf("effects replayed: inventory=%d replace=%d revalidate=%d fence=%d observe=%d terminate=%d", inventory, replace, revalidate, fence, observe, terminate)
	}
}

func TestRemovalLostTerminationAcknowledgementCompletesFromAuthoritativeAbsence(t *testing.T) {
	journal := &Journal{journal: &removalMemory{state: state{Operations: map[string]Operation{}}}}
	member := MemberObservation{ProviderETag: "etag", Identity: "spiffe://member", ResourceID: "ocid1.instance.original", Generation: 7}
	exists := true
	calls := 0
	unknown := errors.New("response lost")
	owner := &Owner{Journal: journal, ReconcileTermination: func(context.Context, string) error { return nil },
		Inventory: func(context.Context, RemovalRequest, []Replacement) (uint64, []Replacement, error) {
			return 1, nil, nil
		},
		Replace:    func(context.Context, Replacement) error { return nil },
		Revalidate: func(context.Context, string, string, uint64) error { return nil },
		Fence:      func(context.Context, string, string, []Replacement) error { return nil },
		Observe:    func(context.Context, string) (bool, error) { return exists, nil },
		Terminate:  func(context.Context, string) error { calls++; exists = false; return unknown },
	}
	if err := owner.RemoveMember(t.Context(), "remove", member, 7); !errors.Is(err, unknown) {
		t.Fatal(err)
	}
	successor := *owner
	if err := successor.RemoveMember(t.Context(), "remove", member, 7); err != nil {
		t.Fatal(err)
	}
	record, err := journal.Load(t.Context(), "remove")
	if err != nil || record.Stage != StageComplete || calls != 1 {
		t.Fatalf("lost response recovery record=%+v calls=%d err=%v", record, calls, err)
	}
}

func TestRemovalNilTerminationAcknowledgementDoesNotComplete(t *testing.T) {
	journal := &Journal{journal: &removalMemory{state: state{Operations: map[string]Operation{}}}}
	member := MemberObservation{Identity: "spiffe://member", ResourceID: "ocid1.instance.original", ProviderETag: "etag", Generation: 7}
	owner := &Owner{Journal: journal, Inventory: func(context.Context, RemovalRequest, []Replacement) (uint64, []Replacement, error) {
		return 1, nil, nil
	}, Replace: func(context.Context, Replacement) error { return nil }, Revalidate: func(context.Context, string, string, uint64) error { return nil }, Fence: func(context.Context, string, string, []Replacement) error { return nil }, Observe: func(context.Context, string) (bool, error) { return true, nil }, Terminate: func(context.Context, string) error { return nil }, ReconcileTermination: func(context.Context, string) error { t.Fatal("unconfirmed terminal reconciliation"); return nil }}
	if err := owner.RemoveMember(t.Context(), "remove", member, 7); !errors.Is(err, ErrPending) {
		t.Fatalf("nil provider acknowledgement completed: %v", err)
	}
	record, err := journal.Load(t.Context(), "remove")
	if err != nil || record.Stage != StageFenced {
		t.Fatalf("unconfirmed stage=%s err=%v", record.Stage, err)
	}
}
