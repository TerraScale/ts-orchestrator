package placement

import (
	"context"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

// DefaultLostMemberGrace is how long a member that lost its OCI host is held
// before a replacement attempt may start.
const DefaultLostMemberGrace = 10 * time.Minute

// instanceLifecycleTerminated is OCI's final instance lifecycle state.
const instanceLifecycleTerminated = "TERMINATED"

// LostMemberEvidence supplies independent proof about a member held without
// its host: the old writer is stopped, the retained volume is intact, and the
// surviving member has replicated the data. It returns false when no
// complete evidence exists yet.
type LostMemberEvidence func(context.Context, MemberState) (RetirementEvidence, bool, error)

// CanReplaceLostMember is the gate for starting the next host attempt of a
// still-desired seat whose host is gone. It reuses CanRetire's evidence
// checks for the lost attempt: replication health, quorum safety, writer stop
// with proof, and a retained volume. Unlike scale-in it does not require two
// other serving members, because replacement restores redundancy instead of
// removing it. It does require one current, healthy serving survivor on a
// different failure domain, so the replacement can only catch up from a
// member that holds the data.
func CanReplaceLostMember(intent Intent, lost MemberObservation, survivors []MemberObservation,
	evidence RetirementEvidence,
) (bool, string) {
	if err := intent.Validate(); err != nil {
		return false, "invalid-intent"
	}
	if lost.DatabaseID != intent.DatabaseID || lost.PartitionID != intent.PartitionID || lost.MemberID == "" ||
		!knownRegion(lost.Region) || lost.InstanceID == "" || lost.VolumeID == "" {
		return false, "candidate-identity-missing"
	}
	if lost.Stage != StageAwaitingRuntimeContract || lost.Healthy || lost.CurrentSession {
		return false, "candidate-not-lost"
	}
	if !desiredMember(intent, lost.Region, lost.MemberID) {
		return false, "candidate-not-desired"
	}
	survivor := false
	for _, member := range survivors {
		if member.DatabaseID != intent.DatabaseID || member.PartitionID != intent.PartitionID {
			return false, "survivor-identity-mismatch"
		}
		if member.MemberID == lost.MemberID || member.Region != lost.Region || member.Stage != StageServing ||
			!member.Healthy || !member.CurrentSession {
			continue
		}
		if member.FailureDomain == "" || member.FailureDomain == lost.FailureDomain {
			return false, "survivor-anti-affinity-violated"
		}
		survivor = true
	}
	if !survivor {
		return false, "no-serving-survivor"
	}
	if allowed, reason := retirementEvidenceSafe(evidence, lost, false); !allowed {
		return false, reason
	}
	return true, "safe-to-replace"
}

// replacementMemberState is the next host attempt for the same seat. It keeps
// the retained volume, roster, manifest and private IP, and clears every
// identity of the lost host so it can never be adopted again.
func replacementMemberState(intent Intent, seat Seat, state MemberState) (MemberState, error) {
	if state.HostAttempt == 0 || state.HostAttempt == ^uint64(0) || state.VolumeID == "" {
		return MemberState{}, fmt.Errorf("%w: lost member has no retained volume or attempt", ErrStoreCorrupt)
	}
	next := state
	next.HostAttempt = state.HostAttempt + 1
	next.CreateKey = hostCreateKey(intent, seat, next.HostAttempt)
	next.Stage = StagePreparedHost
	next.PreviousInstanceID = state.InstanceID
	next.HostNode, next.InstanceID, next.InstanceETag = "", "", ""
	next.AttachmentID, next.AttachmentDevice, next.AttachmentETag = "", "", ""
	next.HostGeneration, next.DesiredGeneration = 0, 0
	next.HostLostAt, next.AttachRequestedAt = time.Time{}, time.Time{}
	next.OperationID = memberOperationID(intent, seat.MemberID, next.HostAttempt, "replace")
	return next, nil
}

// replaceLostMember starts the next host attempt for a seat held without its
// OCI host once the grace passed and the evidence gate allows it. Without a
// configured evidence source the member stays held, as before.
func (controller *Controller) replaceLostMember(ctx context.Context, epoch uint64, intent Intent, seat Seat,
	versioned VersionedMemberState, seats []Seat, members map[string]VersionedMemberState,
	instances map[string]oci.Instance, statuses map[string]host.HostStatus,
) (bool, error) {
	state := versioned.State
	if controller.config.LostMemberEvidence == nil || state.Stage != StageAwaitingRuntimeContract ||
		state.ManagedRuntimeTarget.OperationID != "" {
		return false, nil
	}
	if state.InstanceID == "" {
		return false, nil
	}
	instance, observed := instances[state.InstanceID]
	// A host that is still observed may return and is never replaced; a
	// host OCI positively reports TERMINATED cannot return, even while the
	// historical instance still appears in the inventory.
	if observed && instance.State != instanceLifecycleTerminated {
		if state.HostLostAt.IsZero() {
			return false, nil
		}
		// The host came back: a later loss starts a fresh grace.
		next := state
		next.HostLostAt = time.Time{}
		if err := controller.guard(ctx, epoch); err != nil {
			return false, err
		}
		_, err := controller.persist(ctx, epoch, versioned.Revision, next)
		return true, err
	}
	now := controller.currentTime().UTC()
	if state.HostLostAt.IsZero() {
		// Record the first observation of the loss durably; the grace runs
		// from here, not from the member's last unrelated write.
		next := state
		next.HostLostAt = now
		if err := controller.guard(ctx, epoch); err != nil {
			return false, err
		}
		_, err := controller.persist(ctx, epoch, versioned.Revision, next)
		return true, err
	}
	grace := controller.config.LostMemberGrace
	if grace == 0 {
		grace = DefaultLostMemberGrace
	}
	if now.Sub(state.HostLostAt) < grace {
		return false, nil
	}
	evidence, complete, err := controller.config.LostMemberEvidence(ctx, state)
	if err != nil {
		return false, fmt.Errorf("read lost member %s evidence: %w", seat.MemberID, err)
	}
	if !complete {
		controller.hold(fmt.Sprintf("member %s lost its host; replacement awaits writer-stop, retained-volume and survivor replication evidence", seat.MemberID))
		return false, nil
	}
	lost := MemberObservation{DatabaseID: state.DatabaseID, PartitionID: state.PartitionID, MemberID: state.MemberID,
		Region: state.Region, FailureDomain: state.FailureDomain, InstanceID: state.InstanceID,
		VolumeID: state.VolumeID, Stage: state.Stage}
	survivors := make([]MemberObservation, 0, len(seats))
	for _, other := range seats {
		if other.MemberID == seat.MemberID {
			continue
		}
		peer, exists := members[other.MemberID]
		if !exists {
			continue
		}
		survivors = append(survivors, controller.observeMember(intent, peer.State, instances, statuses))
	}
	if allowed, reason := CanReplaceLostMember(intent, lost, survivors, evidence); !allowed {
		controller.hold(fmt.Sprintf("member %s lost its host; replacement is held: %s", seat.MemberID, reason))
		return false, nil
	}
	next, err := replacementMemberState(intent, seat, state)
	if err != nil {
		return false, err
	}
	if err := controller.guard(ctx, epoch); err != nil {
		return false, err
	}
	_, err = controller.persist(ctx, epoch, versioned.Revision, next)
	return true, err
}

// observeMember reports a member's current serving health from the same
// host, instance and serving-report evidence the Serving stage uses.
func (controller *Controller) observeMember(intent Intent, state MemberState, instances map[string]oci.Instance,
	statuses map[string]host.HostStatus,
) MemberObservation {
	observation := MemberObservation{DatabaseID: state.DatabaseID, PartitionID: state.PartitionID,
		MemberID: state.MemberID, Region: state.Region, FailureDomain: state.FailureDomain,
		InstanceID: state.InstanceID, VolumeID: state.VolumeID, Stage: state.Stage}
	instance, exists := instances[state.InstanceID]
	if !exists || state.Stage != StageServing {
		return observation
	}
	status, admitted := controller.admittedHost(intent, state, instance, statuses)
	if admitted && status.Registration.Generation == state.HostGeneration &&
		controller.hasServingReport(intent, state, instance, status) {
		observation.Healthy, observation.CurrentSession = true, true
	}
	return observation
}
