package placement

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
)

// maxJournaledSeats bounds the remembered seat states. A regional cell has
// far fewer seats; exceeding it only forgets "from" stages.
const maxJournaledSeats = 4096

// ManagedUpdateCorrelation is the decisionlog correlation key under which
// the managed update admission records its decision, so the seat phase
// decisions chain under it.
func ManagedUpdateCorrelation(operationID string) string { return "managed_update:" + operationID }

// JournaledStore wraps the reconciler's store and journals every seat stage
// and managed update phase transition the reconciler commits. It remembers
// the last stage it read or wrote per seat to tell what changed; recording is
// best effort and never affects the compare-and-swap result.
func JournaledStore(store Store, cell string) Store {
	return &journaledStore{Store: store, cell: cell, seats: map[string]seatMark{}}
}

type journaledStore struct {
	Store
	cell  string
	mu    sync.Mutex
	seats map[string]seatMark
}

type seatMark struct {
	stage     MemberStage
	operation string
	phase     ManagedUpdateSeatPhase
}

func seatKey(state MemberState) string {
	return state.DatabaseID + "/" + state.PartitionID + "/" + state.MemberID
}

func markOf(state MemberState) seatMark {
	return seatMark{stage: state.Stage, operation: state.ManagedRuntimeTarget.OperationID,
		phase: state.ManagedRuntimeTarget.Phase}
}

func (store *journaledStore) remember(state MemberState) (seatMark, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := seatKey(state)
	previous, known := store.seats[key]
	if !known && len(store.seats) >= maxJournaledSeats {
		clear(store.seats)
	}
	store.seats[key] = markOf(state)
	return previous, known
}

func (store *journaledStore) ReadMember(ctx context.Context, databaseID, partitionID, memberID string) (VersionedMemberState, error) {
	member, err := store.Store.ReadMember(ctx, databaseID, partitionID, memberID)
	if err == nil {
		store.remember(member.State)
	}
	return member, err
}

func (store *journaledStore) ListMembers(ctx context.Context, databaseID, partitionID string) ([]VersionedMemberState, error) {
	members, err := store.Store.ListMembers(ctx, databaseID, partitionID)
	if err == nil {
		for _, member := range members {
			store.remember(member.State)
		}
	}
	return members, err
}

func (store *journaledStore) CompareAndSwap(ctx context.Context, expected uint64, state MemberState) (uint64, error) {
	revision, err := store.Store.CompareAndSwap(ctx, expected, state)
	if err != nil {
		return revision, err
	}
	previous, known := store.remember(state)
	if expected == 0 {
		known, previous = true, seatMark{}
	}
	store.journal(ctx, previous, known, state)
	return revision, nil
}

func (store *journaledStore) journal(ctx context.Context, previous seatMark, known bool, state MemberState) {
	current := markOf(state)
	subject := decisionlog.Subject{Kind: "seat", ID: state.MemberID,
		Name: fmt.Sprintf("%s/%s %s", state.DatabaseID, state.PartitionID, state.MemberID)}
	signals := []decisionlog.Signal{
		{Name: "intent_generation", Value: float64(state.IntentGeneration)},
		{Name: "desired_generation", Value: float64(state.DesiredGeneration)},
		{Name: "host_attempt", Value: float64(state.HostAttempt)},
	}
	attrs := map[string]string{"database_id": state.DatabaseID, "partition_id": state.PartitionID,
		"failure_domain": state.FailureDomain}
	if state.HostNode != "" {
		attrs["host_node"] = state.HostNode
	}
	if state.VolumeID != "" {
		attrs["volume_id"] = state.VolumeID
	}
	if !known || previous.stage != current.stage {
		kind, status, summary := stageDecision(state)
		var reason string
		switch {
		case known && previous.stage == "":
			reason = fmt.Sprintf("The reconciler admitted the seat at %s.", current.stage)
		case known:
			reason = fmt.Sprintf("The reconciler committed %s after %s.", current.stage, previous.stage)
		default:
			reason = fmt.Sprintf("The reconciler committed %s.", current.stage)
		}
		stageSignals := slices.Concat(signals, []decisionlog.Signal{{Name: "stage", Text: string(current.stage)}})
		decisionlog.Record(ctx, decisionlog.Decision{Region: store.cell, Actor: decisionlog.Actor{Slice: "placement"},
			Kind: kind, Subject: subject, Summary: summary, Reason: reason, Rule: "placement stage machine",
			Signals: stageSignals, Status: status, Epoch: state.WriterEpoch, Attrs: attrs,
			Outcome: string(current.stage)})
	}
	if current.operation == "" || previous.operation == current.operation && previous.phase == current.phase {
		return
	}
	target := state.ManagedRuntimeTarget
	correlation := ManagedUpdateCorrelation(target.OperationID)
	updateSubject := decisionlog.Subject{Kind: "operation", ID: target.OperationID,
		Name: "managed update of " + subject.Name}
	updateAttrs := map[string]string{"artifact_digest": target.ArtifactDigest,
		"previous_artifact_digest": target.PreviousArtifactDigest, "canary_seat": target.CanarySeatID,
		"database_id": state.DatabaseID, "partition_id": state.PartitionID}
	decision := decisionlog.Decision{Region: store.cell, Actor: decisionlog.Actor{Slice: "placement"},
		Subject: updateSubject, Epoch: state.WriterEpoch, Attrs: updateAttrs, Rule: "managed TerraBase canary update",
		ParentID: decisionlog.Correlated(correlation),
		Signals: slices.Concat(signals, []decisionlog.Signal{
			{Name: "authority_sequence", Value: float64(target.AuthoritySequence)},
			{Name: "phase", Text: string(target.Phase)}})}
	switch target.Phase {
	case ManagedUpdateSeatPrepared:
		decision.Kind, decision.Status = decisionlog.KindUpgradeStarted, decisionlog.StatusInProgress
		decision.Summary = "Managed update started on canary seat " + state.MemberID
		decision.Reason = "A signed managed update was admitted and its canary target was durably prepared."
		decision.Alternatives = []decisionlog.Alternative{{Option: "update every seat at once",
			Reason: "the canary must prove serving before any peer changes"}}
	case ManagedUpdateSeatCanaryServing:
		decision.Kind, decision.Status = decisionlog.KindCanaryPromoted, decisionlog.StatusSucceeded
		decision.Summary = "Canary seat " + state.MemberID + " is serving the new runtime"
		decision.Reason = "The canary produced current, independent TerraBase serving proof before its deadline."
		decision.Outcome = target.Outcome
	case ManagedUpdateSeatHeld:
		decision.Kind, decision.Status = decisionlog.KindHeld, decisionlog.StatusFailed
		decision.Summary = "Managed update held on canary seat " + state.MemberID
		decision.Reason = "The canary did not prove serving (" + target.Outcome + "); the update is durably held " +
			"and no peer is promoted."
		decision.Outcome = target.Outcome
		decision.Alternatives = []decisionlog.Alternative{{Option: "promote peers",
			Reason: "the canary failed its serving gate"}}
	default:
		return
	}
	id := decisionlog.Record(ctx, decision)
	if decision.ParentID == "" {
		decisionlog.Correlate(correlation, id)
	}
}

func stageDecision(state MemberState) (decisionlog.Kind, decisionlog.Status, string) {
	seat := state.MemberID
	switch state.Stage {
	case StageAwaitingHost:
		return decisionlog.KindHostLaunched, decisionlog.StatusInProgress, "Host launch requested for seat " + seat
	case StageServing:
		return decisionlog.KindStageChanged, decisionlog.StatusSucceeded, "Seat " + seat + " is serving"
	case StageTerminated:
		return decisionlog.KindHostReclaimed, decisionlog.StatusSucceeded, "Host of seat " + seat + " terminated"
	case StageRemoved:
		return decisionlog.KindStageChanged, decisionlog.StatusSucceeded, "Seat " + seat + " removed"
	case StageAwaitingAttach, StagePreparedAttach:
		return decisionlog.KindStageChanged, decisionlog.StatusInProgress, "Volume attachment started for seat " + seat
	default:
		return decisionlog.KindStageChanged, decisionlog.StatusInProgress,
			fmt.Sprintf("Seat %s moved to %s", seat, state.Stage)
	}
}
