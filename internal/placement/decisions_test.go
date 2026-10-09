package placement

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

type journalTestStore struct {
	Store
	members map[string]VersionedMemberState
	fail    bool
}

func (store *journalTestStore) ListMembers(context.Context, string, string) ([]VersionedMemberState, error) {
	var out []VersionedMemberState
	for _, member := range store.members {
		out = append(out, member)
	}
	return out, nil
}

func (store *journalTestStore) CompareAndSwap(_ context.Context, expected uint64, state MemberState) (uint64, error) {
	if store.fail {
		return 0, ErrStoreConflict
	}
	store.members[state.MemberID] = VersionedMemberState{State: state, Revision: expected + 1}
	return expected + 1, nil
}

func TestJournaledStoreRecordsTransitions(t *testing.T) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	t.Cleanup(decisionlog.SetDefault(journal))
	inner := &journalTestStore{members: map[string]VersionedMemberState{}}
	store := JournaledStore(inner, "gru")
	ctx := t.Context()
	state := MemberState{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", MemberID: "0000000000E53AR49PEP1CY8VB", Stage: StagePreparedHost, WriterEpoch: 3}
	mustCAS := func(expected uint64, state MemberState) {
		t.Helper()
		if _, err := store.CompareAndSwap(ctx, expected, state); err != nil {
			t.Fatal(err)
		}
	}
	mustCAS(0, state)
	state.Stage = StageAwaitingHost
	mustCAS(1, state)
	mustCAS(2, state) // unchanged stage: no decision
	state.Stage = StageServing
	mustCAS(3, state)

	admission := decisionlog.Record(ctx, decisionlog.Decision{Kind: decisionlog.KindReleaseAdmitted})
	decisionlog.Correlate(ManagedUpdateCorrelation("0000000000T8H7NEY8XQ530245", "00000000003K6TBW31R91GBDRD", "0000000000M44BFMMJRNPNN6BB"), admission)
	state.ManagedRuntimeTarget = ManagedRuntimeTarget{OperationID: "0000000000M44BFMMJRNPNN6BB", Phase: ManagedUpdateSeatPrepared}
	mustCAS(4, state)
	state.ManagedRuntimeTarget.Phase = ManagedUpdateSeatCanaryServing
	state.ManagedRuntimeTarget.Outcome = "canary-serving"
	mustCAS(5, state)

	inner.fail = true
	state.Stage = StageCordoned
	if _, err := store.CompareAndSwap(ctx, 6, state); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("err = %v", err)
	}

	result, _ := journal.Query(ctx, decisionlog.Query{Actors: []string{"placement"}})
	kinds := []decisionlog.Kind{}
	for index := len(result.Decisions) - 1; index >= 0; index-- {
		kinds = append(kinds, result.Decisions[index].Kind)
	}
	want := []decisionlog.Kind{decisionlog.KindStageChanged, decisionlog.KindHostLaunched,
		decisionlog.KindStageChanged, decisionlog.KindUpgradeStarted, decisionlog.KindCanaryPromoted}
	if len(kinds) != len(want) {
		t.Fatalf("kinds = %v", kinds)
	}
	for index := range want {
		if kinds[index] != want[index] {
			t.Fatalf("kinds = %v", kinds)
		}
	}
	newest := result.Decisions[0]
	if newest.ParentID != admission || newest.Epoch != 3 || newest.Region != "gru" {
		t.Fatalf("promotion = %+v", newest)
	}
	chain, err := journal.Chain(ctx, newest.ID)
	if err != nil || chain.Root.ID != admission || len(chain.Decisions) != 3 {
		t.Fatalf("chain = %+v err=%v", chain, err)
	}
	// A seat first seen through a listing reports where it came from.
	inner.fail = false
	inner.members["m2"] = VersionedMemberState{State: MemberState{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", MemberID: "00000000001VZK2HQDVVKV22S3",
		Stage: StageAwaitingAttach}, Revision: 9}
	if _, err := store.ListMembers(ctx, "0000000000T8H7NEY8XQ530245", "00000000003K6TBW31R91GBDRD"); err != nil {
		t.Fatal(err)
	}
	mustCAS(9, MemberState{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", MemberID: "00000000001VZK2HQDVVKV22S3", Stage: StagePreparedDesired})
	latest, _ := journal.Query(ctx, decisionlog.Query{SubjectID: memberStateKey("0000000000T8H7NEY8XQ530245", "00000000003K6TBW31R91GBDRD", "00000000001VZK2HQDVVKV22S3")})
	if len(latest.Decisions) != 1 || latest.Decisions[0].Reason != "The reconciler committed prepared-desired after awaiting-attach." {
		t.Fatalf("m2 = %+v", latest.Decisions)
	}
}

// Seat IDs repeat across partitions; journal subjects do not.
func TestJournaledSeatSubjectsAreQualified(t *testing.T) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	t.Cleanup(decisionlog.SetDefault(journal))
	store := JournaledStore(&journalTestStore{members: map[string]VersionedMemberState{}}, "gru")
	for _, partition := range []string{"00000000003K6TBW31R91GBDRD", "00000000009WTTZWVWDNSXXPA0"} {
		if _, err := store.CompareAndSwap(t.Context(), 0, MemberState{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: partition,
			MemberID: "000000000082AXF7GZQT1D126Y", Stage: StagePreparedHost}); err != nil {
			t.Fatal(err)
		}
	}
	one, _ := journal.Query(t.Context(), decisionlog.Query{SubjectKind: "seat", SubjectID: memberStateKey("0000000000T8H7NEY8XQ530245", "00000000003K6TBW31R91GBDRD", "000000000082AXF7GZQT1D126Y")})
	if len(one.Decisions) != 1 {
		t.Fatalf("seat history mixes partitions: %+v", one.Decisions)
	}
}

// A read racing the compare-and-swap (the admission lists members while the
// reconciler commits) cannot hide the committed transition: the predecessor
// is the state at the expected revision.
func TestConcurrentReadDoesNotHideATransition(t *testing.T) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	t.Cleanup(decisionlog.SetDefault(journal))
	inner := &journalTestStore{members: map[string]VersionedMemberState{}}
	store := JournaledStore(inner, "gru").(*journaledStore)
	state := MemberState{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", MemberID: "0000000000E53AR49PEP1CY8VB", Stage: StageAwaitingHost}
	if _, err := store.CompareAndSwap(t.Context(), 0, state); err != nil {
		t.Fatal(err)
	}
	// The admission reads the newly committed state at revision 2 before
	// the reconciler's swap from revision 1 is journaled.
	state.Stage = StageServing
	store.remember(state, 2)
	if _, err := store.CompareAndSwap(t.Context(), 1, state); err != nil {
		t.Fatal(err)
	}
	serving, _ := journal.Query(t.Context(), decisionlog.Query{SubjectID: memberStateKey("0000000000T8H7NEY8XQ530245", "00000000003K6TBW31R91GBDRD", "0000000000E53AR49PEP1CY8VB")})
	if len(serving.Decisions) != 2 || serving.Decisions[0].Reason != "The reconciler committed serving after awaiting-host." {
		t.Fatalf("decisions = %+v", serving.Decisions)
	}
}

// A forgotten predecessor does not journal an unchanged phase again.
func TestUnknownPredecessorDoesNotRepeatAPhase(t *testing.T) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	t.Cleanup(decisionlog.SetDefault(journal))
	store := JournaledStore(&journalTestStore{members: map[string]VersionedMemberState{}}, "gru").(*journaledStore)
	state := MemberState{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", MemberID: "0000000000E53AR49PEP1CY8VB", Stage: StageServing,
		ManagedRuntimeTarget: ManagedRuntimeTarget{OperationID: "0000000000C8KM8N5ZFHV5BEXT", Phase: ManagedUpdateSeatPrepared}}
	if _, err := store.CompareAndSwap(t.Context(), 0, state); err != nil {
		t.Fatal(err)
	}
	clear(store.seats) // eviction
	state.Stage = StageCordoned
	if _, err := store.CompareAndSwap(t.Context(), 1, state); err != nil {
		t.Fatal(err)
	}
	started, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindUpgradeStarted}})
	if len(started.Decisions) != 1 {
		t.Fatalf("upgrade_started journaled %d times", len(started.Decisions))
	}
}

// A controller that resumes a managed update after a leader change has no
// in-memory correlation; its canary phases still link to the admission.
func TestResumedUpdateLinksToTheAdmissionWithoutCorrelation(t *testing.T) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	t.Cleanup(decisionlog.SetDefault(journal))
	store := JournaledStore(&journalTestStore{members: map[string]VersionedMemberState{}}, "gru")
	state := MemberState{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", MemberID: "0000000000E53AR49PEP1CY8VB", Stage: StageServing,
		ManagedRuntimeTarget: ManagedRuntimeTarget{OperationID: "0000000000V6DTRPBF1X97QFBR", Phase: ManagedUpdateSeatCanaryServing}}
	if _, err := store.CompareAndSwap(t.Context(), 0, state); err != nil {
		t.Fatal(err)
	}
	result, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindCanaryPromoted}})
	if len(result.Decisions) != 1 || result.Decisions[0].ParentID != ManagedUpdateAdmissionID("gru", "0000000000T8H7NEY8XQ530245", "00000000003K6TBW31R91GBDRD", "0000000000V6DTRPBF1X97QFBR") {
		t.Fatalf("promotion = %+v", result.Decisions)
	}
	if id := ManagedUpdateAdmissionID("gru", "0000000000T8H7NEY8XQ530245", "00000000003K6TBW31R91GBDRD", "0000000000V6DTRPBF1X97QFBR"); id != ManagedUpdateAdmissionID("gru", "0000000000T8H7NEY8XQ530245", "00000000003K6TBW31R91GBDRD", "0000000000V6DTRPBF1X97QFBR") ||
		id == ManagedUpdateAdmissionID("gru", "0000000000T8H7NEY8XQ530245", "00000000009WTTZWVWDNSXXPA0", "0000000000V6DTRPBF1X97QFBR") {
		t.Fatal("admission IDs are not a function of the partition-scoped operation")
	}
	if _, ok := decisionlog.IDTime(ManagedUpdateAdmissionID("gru", "0000000000T8H7NEY8XQ530245", "00000000003K6TBW31R91GBDRD", "0000000000V6DTRPBF1X97QFBR")); ok {
		t.Fatal("an admission ID reads as a time-ordered ID")
	}
}

// The phase deduplication keeps only each seat's current operation, so a
// stable roster running many updates does not grow it.
func TestJournaledPhasesStayBoundedPerSeat(t *testing.T) {
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	t.Cleanup(decisionlog.SetDefault(journal))
	store := JournaledStore(&journalTestStore{members: map[string]VersionedMemberState{}}, "gru").(*journaledStore)
	state := MemberState{DatabaseID: "0000000000T8H7NEY8XQ530245", PartitionID: "00000000003K6TBW31R91GBDRD", MemberID: "0000000000E53AR49PEP1CY8VB", Stage: StageServing}
	revision := uint64(0)
	for index := range 50 {
		state.ManagedRuntimeTarget = ManagedRuntimeTarget{OperationID: fmt.Sprintf("op-%d", index),
			Phase: ManagedUpdateSeatPrepared}
		next, err := store.CompareAndSwap(t.Context(), revision, state)
		if err != nil {
			t.Fatal(err)
		}
		revision = next
	}
	if len(store.phases) != 1 {
		t.Fatalf("phase memory holds %d seats, want 1", len(store.phases))
	}
	started, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindUpgradeStarted}})
	if len(started.Decisions) != 50 {
		t.Fatalf("upgrade_started journaled %d times, want once per operation", len(started.Decisions))
	}
}
