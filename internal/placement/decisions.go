package placement

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

// maxJournaledSeats bounds the remembered seat states. A regional cell has
// far fewer seats; exceeding it only forgets "from" stages.
const maxJournaledSeats = 4096

// ManagedUpdateCorrelation is the decisionlog correlation key under which
// the managed update admission records its decision, so the seat phase
// decisions chain under it. Operation conflicts are enforced per database
// partition, so two partitions may admit the same operation ID: the key is
// scoped to the partition.
func ManagedUpdateCorrelation(databaseID, partitionID, operationID string) string {
	return "managed_update:" + databaseID + "/" + partitionID + ":" + operationID
}

// ManagedUpdateAdmissionID is the decision ID of an operation's admission in
// one cell and database partition. It is derived from that scope and the
// operation, so a replayed Prepare journals the same decision (the journal
// keeps one copy per ID) and a controller that resumes the update after a
// leader change links its canary phases to the admission without the
// admitting process's in-memory correlation. The "mu" prefix keeps it from
// being read as a time-ordered ID; Journal.Chain searches the archive's
// retention for such IDs.
func ManagedUpdateAdmissionID(cell, databaseID, partitionID, operationID string) string {
	digest := sha256.Sum256([]byte("managed update admission\x00" + cell + "\x00" + databaseID + "\x00" +
		partitionID + "\x00" + operationID))
	return "mu" + hex.EncodeToString(digest[:15])
}

// marksPerSeat bounds the revisions remembered per seat.
const marksPerSeat = 4

// JournaledStore wraps the reconciler's store and journals every seat stage
// and managed update phase transition the reconciler commits. It remembers
// the stage it read or wrote per seat and revision; a compare-and-swap's
// predecessor is the state at its expected revision, so a concurrent read
// (the managed-update admission lists members while the reconciler runs)
// can neither hide a transition nor stand in for an older one. Recording is
// best effort and never affects the compare-and-swap result.
func JournaledStore(store Store, cell string) Store {
	return &journaledStore{Store: store, cell: cell, seats: map[string]map[uint64]seatMark{},
		phases: map[string]seatPhases{}}
}

type journaledStore struct {
	Store
	cell  string
	mu    sync.Mutex
	seats map[string]map[uint64]seatMark
	// phases holds, per seat, the managed update phases already journaled
	// for the seat's current operation, so a forgotten predecessor never
	// journals the same phase twice. Only the current operation is kept per
	// seat, so the map is bounded by the seats, not by every operation the
	// controller ever ran.
	phases map[string]seatPhases
}

type seatPhases struct {
	operation string
	seen      map[ManagedUpdateSeatPhase]struct{}
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

// remember records the seat's state at revision.
func (store *journaledStore) remember(state MemberState, revision uint64) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := seatKey(state)
	marks := store.seats[key]
	if marks == nil {
		if len(store.seats) >= maxJournaledSeats {
			clear(store.seats)
			clear(store.phases)
		}
		marks = map[uint64]seatMark{}
		store.seats[key] = marks
	}
	marks[revision] = markOf(state)
	for len(marks) > marksPerSeat {
		oldest := revision
		for other := range marks {
			oldest = min(oldest, other)
		}
		delete(marks, oldest)
	}
}

// at returns the seat's state at revision, if it was read or written.
func (store *journaledStore) at(state MemberState, revision uint64) (seatMark, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	mark, known := store.seats[seatKey(state)][revision]
	return mark, known
}

// firstPhase reports whether the phase is journaled for the first time for
// this operation and seat.
func (store *journaledStore) firstPhase(state MemberState) bool {
	key := seatKey(state)
	target := state.ManagedRuntimeTarget
	store.mu.Lock()
	defer store.mu.Unlock()
	entry := store.phases[key]
	if entry.operation != target.OperationID || entry.seen == nil {
		if _, known := store.phases[key]; !known && len(store.phases) >= maxJournaledSeats {
			clear(store.phases)
		}
		entry = seatPhases{operation: target.OperationID, seen: map[ManagedUpdateSeatPhase]struct{}{}}
	}
	if _, seen := entry.seen[target.Phase]; seen {
		return false
	}
	entry.seen[target.Phase] = struct{}{}
	store.phases[key] = entry
	return true
}

func (store *journaledStore) ReadMember(ctx context.Context, databaseID, partitionID, memberID string) (VersionedMemberState, error) {
	member, err := store.Store.ReadMember(ctx, databaseID, partitionID, memberID)
	if err == nil {
		store.remember(member.State, member.Revision)
	}
	return member, err
}

func (store *journaledStore) ListMembers(ctx context.Context, databaseID, partitionID string) ([]VersionedMemberState, error) {
	members, err := store.Store.ListMembers(ctx, databaseID, partitionID)
	if err == nil {
		for _, member := range members {
			store.remember(member.State, member.Revision)
		}
	}
	return members, err
}

func (store *journaledStore) CompareAndSwap(ctx context.Context, expected uint64, state MemberState) (uint64, error) {
	revision, err := store.Store.CompareAndSwap(ctx, expected, state)
	if err != nil {
		return revision, err
	}
	previous, known := store.at(state, expected)
	if expected == 0 {
		known, previous = true, seatMark{}
	}
	store.remember(state, revision)
	store.journal(ctx, previous, known, state)
	return revision, nil
}

func (store *journaledStore) journal(ctx context.Context, previous seatMark, known bool, state MemberState) {
	current := markOf(state)
	// Seat IDs repeat across databases and partitions; the journal subject
	// is the fully qualified seat.
	subject := decisionlog.Subject{Kind: "seat", ID: seatKey(state),
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
	if current.operation == "" || known && previous.operation == current.operation && previous.phase == current.phase {
		return
	}
	// An unknown predecessor is not evidence of a phase change: journal a
	// phase only the first time it is seen for this operation and seat.
	if !store.firstPhase(state) {
		return
	}
	target := state.ManagedRuntimeTarget
	correlation := ManagedUpdateCorrelation(state.DatabaseID, state.PartitionID, target.OperationID)
	updateSubject := decisionlog.Subject{Kind: "operation", ID: target.OperationID,
		Name: "managed update of " + subject.Name}
	updateAttrs := map[string]string{"artifact_digest": target.ArtifactDigest,
		"previous_artifact_digest": target.PreviousArtifactDigest, "canary_seat": target.CanarySeatID,
		"database_id": state.DatabaseID, "partition_id": state.PartitionID}
	decision := decisionlog.Decision{Region: store.cell, Actor: decisionlog.Actor{Slice: "placement"},
		Subject: updateSubject, Epoch: state.WriterEpoch, Attrs: updateAttrs, Rule: "managed TerraBase canary update",
		ParentID: cmp.Or(decisionlog.Correlated(correlation),
			ManagedUpdateAdmissionID(store.cell, state.DatabaseID, state.PartitionID, target.OperationID)),
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
	decisionlog.Record(ctx, decision)
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

// recordVolumeResize journals a grow-only retained volume resize once per
// volume and target size; the fleet's resize is journaled and idempotent on
// the same pair.
func recordVolumeResize(ctx context.Context, cell string, epoch uint64, intent Intent, before, after oci.RetainedVolume) {
	if after.SizeGB <= before.SizeGB {
		return
	}
	key := fmt.Sprintf("volume_resize:%s:%d", after.ID, after.SizeGB)
	if decisionlog.Correlated(key) != "" {
		return
	}
	id := decisionlog.Record(ctx, decisionlog.Decision{
		Region:  cell,
		Actor:   decisionlog.Actor{Slice: "storage"},
		Kind:    decisionlog.KindVolumeResized,
		Subject: decisionlog.Subject{Kind: "volume", ID: after.ID, Name: intent.DatabaseID + "/" + intent.PartitionID},
		Summary: fmt.Sprintf("Grew volume %s from %d to %d GB", after.ID, before.SizeGB, after.SizeGB),
		Reason:  "The member's resource profile needs a larger retained volume than it was created with.",
		Rule:    "placement.auto_grow_volumes",
		Signals: []decisionlog.Signal{{Name: "size_gb", Value: float64(before.SizeGB), Unit: "GB", Comparison: ">=",
			Threshold: decisionlog.Threshold(float64(after.SizeGB)), Passed: decisionlog.Passed(false)}},
		Status: decisionlog.StatusSucceeded,
		Epoch:  epoch,
	})
	decisionlog.Correlate(key, id)
}
