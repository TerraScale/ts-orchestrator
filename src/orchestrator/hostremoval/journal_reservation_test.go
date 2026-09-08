package hostremoval

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
)

type reservationMemory struct {
	mu            sync.Mutex
	state         state
	loseNextWrite bool
}

var reservationUnknown = errors.New("journal committed but acknowledgement lost")

func (m *reservationMemory) Transact(_ context.Context, write bool, change func(*state) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	encoded, _ := json.Marshal(m.state)
	var candidate state
	if err := json.Unmarshal(encoded, &candidate); err != nil {
		return err
	}
	if err := change(&candidate); err != nil {
		return err
	}
	if !write {
		return nil
	}
	m.state = candidate
	if m.loseNextWrite {
		m.loseNextWrite = false
		return reservationUnknown
	}
	return nil
}
func reservationMember() MemberObservation {
	return MemberObservation{Identity: "spiffe://member", ResourceID: "instance-original", ProviderETag: "etag", Region: "GRU", Slot: 3, Generation: 7}
}
func reservationReferences() []Replacement {
	return []Replacement{{DatabaseID: "database", IssuerOperationID: "remove/placement", ProposalDigest: strings.Repeat("a", 64)}}
}

func TestReservationExcludesConcurrentInventoryBeforeEffects(t *testing.T) {
	memory := &reservationMemory{state: state{Operations: map[string]Operation{}}}
	journal := &Journal{journal: memory}
	member := reservationMember()
	start := make(chan struct{})
	outcomes := make(chan struct {
		id  string
		err error
	}, 2)
	var workers sync.WaitGroup
	for _, id := range []string{"remove-a", "remove-b"} {
		workers.Go(func() {
			<-start
			_, err := journal.Reserve(t.Context(), id, member, 7, nil)
			outcomes <- struct {
				id  string
				err error
			}{id, err}
		})
	}
	close(start)
	workers.Wait()
	close(outcomes)
	winner, loser := "", ""
	for outcome := range outcomes {
		if outcome.err == nil {
			if winner != "" {
				t.Fatal("two concurrent capacity owners")
			}
			winner = outcome.id
		} else if errors.Is(outcome.err, ErrConflict) {
			loser = outcome.id
		} else {
			t.Fatal(outcome.err)
		}
	}
	if winner == "" || loser == "" {
		t.Fatal("missing reservation winner or rejection")
	}
	if err := journal.CheckFill(t.Context(), winner, member, 7, 1, reservationReferences(), nil); err != nil {
		t.Fatal(err)
	}
	current, err := journal.Load(t.Context(), winner)
	if err != nil || current.Stage != StageInventoryPending || current.InventoryRevision != 0 {
		t.Fatal("preflight wrote inventory", current, err)
	}
	if _, err := journal.Advance(t.Context(), winner, StageInventoryCaptured); !errors.Is(err, ErrConflict) {
		t.Fatal("Advance bypassed exact inventory fill", err)
	}
	if _, err := journal.Begin(t.Context(), loser, member, 7, 1, reservationReferences(), nil); !errors.Is(err, ErrMissing) {
		t.Fatal("unreserved writer consumed capacity", err)
	}
	if _, err := journal.Begin(t.Context(), winner, member, 7, 1, reservationReferences(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Reserve(t.Context(), loser, member, 7, nil); err != nil {
		t.Fatal("filled reservation retained exclusive slot", err)
	}
}

func TestReservationUnknownReserveAndFillRetainExactIntent(t *testing.T) {
	memory := &reservationMemory{state: state{Operations: map[string]Operation{}}, loseNextWrite: true}
	journal := &Journal{journal: memory}
	member := reservationMember()
	survivors := []MemberObservation{{Identity: "spiffe://survivor", Region: "GRU", Slot: 1, Generation: 7, EvidenceRefs: []string{"original-evidence"}}}
	if _, err := journal.Reserve(t.Context(), "remove", member, 7, survivors); !errors.Is(err, reservationUnknown) {
		t.Fatal(err)
	}
	restarted := &Journal{journal: memory}
	if _, err := restarted.Reserve(t.Context(), "remove", member, 7, survivors); err != nil {
		t.Fatal(err)
	}
	changed := member
	changed.Slot++
	if _, err := restarted.Reserve(t.Context(), "remove", changed, 7, survivors); !errors.Is(err, ErrConflict) {
		t.Fatal("changed observed slot accepted", err)
	}
	current, err := restarted.Load(t.Context(), "remove")
	if err != nil {
		t.Fatal(err)
	}
	current.PendingRequest.Survivors[0].EvidenceRefs[0] = "mutated"
	if err := restarted.CheckFill(t.Context(), "remove", member, 7, 2, reservationReferences(), survivors); err != nil {
		t.Fatal("read result mutation altered retained reservation", err)
	}
	memory.loseNextWrite = true
	if _, err := restarted.Begin(t.Context(), "remove", member, 7, 2, reservationReferences(), survivors); !errors.Is(err, reservationUnknown) {
		t.Fatal(err)
	}
	restarted = &Journal{journal: memory}
	if _, err := restarted.Begin(t.Context(), "remove", member, 7, 2, reservationReferences(), survivors); err != nil {
		t.Fatal("unknown fill changed replay", err)
	}
	current, err = restarted.Load(t.Context(), "remove")
	if err != nil || current.Stage != StageInventoryCaptured || current.PendingRequest != nil {
		t.Fatal("fill state not retained", current, err)
	}
}

func TestOwnerCaptureRetryKeepsReservedSnapshotAndSkipsUnknownFill(t *testing.T) {
	memory := &reservationMemory{state: state{Operations: map[string]Operation{}}}
	journal := &Journal{journal: memory}
	member := reservationMember()
	survivor := MemberObservation{Identity: "spiffe://survivor", Region: "GRU", Slot: 1, Generation: 7}
	captures, replacements, terminations := 0, 0, 0
	exists := true
	captureErr := errors.New("inventory authority unavailable")
	owner := &Owner{Journal: journal, Inventory: func(_ context.Context, r RemovalRequest, _ []Replacement) (uint64, []Replacement, error) {
		captures++
		if len(r.Survivors) != 1 || r.Survivors[0].Generation != 7 || r.Member.Slot != 3 {
			t.Fatal("retry replanned against changed observations")
		}
		if captures == 1 {
			return 0, nil, captureErr
		}
		memory.loseNextWrite = true
		return 2, reservationReferences(), nil
	}, Replace: func(context.Context, Replacement) error { replacements++; return nil }, Revalidate: func(context.Context, string, string, uint64) error { return nil }, Fence: func(context.Context, string, string, []Replacement) error { return nil }, Observe: func(context.Context, string) (bool, error) { return exists, nil }, Terminate: func(context.Context, string) error { terminations++; exists = false; return nil }, ReconcileTermination: func(context.Context, string) error { return nil }}
	if err := owner.RemoveMember(t.Context(), "remove", member, 7, survivor); !errors.Is(err, captureErr) {
		t.Fatal(err)
	}
	current, err := journal.Load(t.Context(), "remove")
	if err != nil || current.Stage != StageInventoryPending {
		t.Fatal("capture failure lost reservation", err)
	}
	survivor.Generation = 9
	if err := owner.RemoveMember(t.Context(), "remove", member, 7, survivor); !errors.Is(err, reservationUnknown) {
		t.Fatal(err)
	}
	restarted := *owner
	restarted.Journal = &Journal{journal: memory}
	if err := restarted.RemoveMember(t.Context(), "remove", member, 7, survivor); err != nil {
		t.Fatal(err)
	}
	if captures != 2 || replacements != 1 || terminations != 1 {
		t.Fatalf("unexpected replay: captures=%d replacements=%d terminations=%d", captures, replacements, terminations)
	}
}

func TestReservationRejectsCountAndExactInventoryByteExhaustion(t *testing.T) {
	member := reservationMember()
	operations := map[string]Operation{}
	for n := range 512 {
		id := fmt.Sprintf("completed-%d", n)
		operations[id] = Operation{OperationID: id, MemberIdentity: member.Identity, ResourceID: member.ResourceID, ProviderETag: member.ProviderETag, Generation: 7, InventoryRevision: 1, Stage: StageComplete}
	}
	memory := &reservationMemory{state: state{Operations: operations}}
	journal := &Journal{journal: memory}
	if _, err := journal.Reserve(t.Context(), "remove", member, 7, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("count exhaustion accepted", err)
	}
	if len(memory.state.Operations) != 512 {
		t.Fatal("rejected reserve mutated journal")
	}
	memory.state.Operations = map[string]Operation{}
	if _, err := journal.Reserve(t.Context(), "remove", member, 7, nil); err != nil {
		t.Fatal(err)
	}
	tooLarge := make([]Replacement, 2000)
	for n := range tooLarge {
		tooLarge[n] = Replacement{DatabaseID: fmt.Sprintf("database-%d", n), IssuerOperationID: strings.Repeat("i", 256), ProposalDigest: strings.Repeat("a", 64)}
	}
	if err := journal.CheckFill(t.Context(), "remove", member, 7, 1, tooLarge, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("unretainable inventory accepted", err)
	}
	current, err := journal.Load(t.Context(), "remove")
	if err != nil || current.Stage != StageInventoryPending || len(current.Replacements) != 0 {
		t.Fatal("rejected fill lost retryable intent", err)
	}
	if err := journal.CheckFill(t.Context(), "remove", member, 7, 1, reservationReferences(), nil); err != nil {
		t.Fatal("bounded retry rejected", err)
	}
}

func TestReservationCapacityAccountsForFencedCompletionGrowth(t *testing.T) {
	member := reservationMember()
	survivor := MemberObservation{Identity: "spiffe://survivor", Region: "GRU", Generation: 7, EvidenceRefs: []string{""}}
	operation := Operation{OperationID: "older", MemberIdentity: member.Identity, ResourceID: member.ResourceID, ProviderETag: member.ProviderETag, Generation: 7, InventoryRevision: 1, Stage: StageFenced, Survivors: []MemberObservation{survivor}}
	operations := map[string]Operation{"older": operation}
	encoded, err := json.Marshal(operations)
	if err != nil {
		t.Fatal(err)
	}
	operation.Survivors[0].EvidenceRefs[0] = strings.Repeat("x", authorityjournal.MaximumStateBytes-len(encoded)-1)
	operations["older"] = operation
	if err := capacityFits(operations); !errors.Is(err, ErrInvalid) {
		t.Fatal("fenced completion growth consumed unreserved bytes", err)
	}
	operation.Survivors[0].EvidenceRefs[0] = operation.Survivors[0].EvidenceRefs[0][1:]
	operations["older"] = operation
	if err := capacityFits(operations); err != nil {
		t.Fatal("exact future-stage capacity rejected", err)
	}
}
