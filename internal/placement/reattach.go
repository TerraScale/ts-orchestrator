package placement

import (
	"context"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/failover"
)

// reattachRetainedVolume moves the retained volume of a replacement host
// attempt from its lost predecessor instance to the replacement. It runs only
// for a replacement attempt that recorded
// its PreviousInstanceID. Each call executes at most one failover step; the
// member advances to StageAwaitingRuntimeContract once the volume is attached
// to the replacement alone and carries a mount-existing permit.
func (controller *Controller) reattachRetainedVolume(ctx context.Context, epoch uint64, intent Intent, seat Seat,
	versioned VersionedMemberState,
) (bool, error) {
	state := versioned.State
	boundary, supported := failover.NewOCIBoundary(controller.fleet)
	if !supported {
		controller.hold(fmt.Sprintf("member %s replacement needs reattach on host loss, which the OCI fleet does not support", seat.MemberID))
		return false, nil
	}
	// Hold one workload effect bound to this tick's epoch for the whole step.
	// Every nested OCI effect joins it through the shared effect context, so
	// an authority loss and reacquire mid-step fences the nested effect
	// instead of letting it run under the new epoch with this tick's inputs.
	ctx = authority.WithActiveWorkloadEffectContext(ctx)
	release, err := controller.beginWorkloadEffect(ctx, epoch, intent)
	if err != nil {
		return false, err
	}
	defer release()
	if state.AttachRequestedAt.IsZero() {
		// The attach deadline runs from the first reattach step, durably.
		state.AttachRequestedAt = controller.currentTime().UTC()
		if err := controller.guard(ctx, epoch); err != nil {
			return false, err
		}
		revision, err := controller.persist(ctx, epoch, versioned.Revision, state)
		if err != nil {
			return false, err
		}
		versioned.Revision = revision
	}
	reattacher := failover.Reattacher{
		Fencer:    controller.fencer,
		Instances: boundary, Volumes: boundary, Permits: boundary, Now: controller.currentTime,
		// The member state was read under this tick's epoch; a step under a
		// later epoch must not act on it.
		ExpectedEpoch: epoch,
	}
	request := failover.Request{
		DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID, VolumeID: state.VolumeID,
		OldInstanceID: state.PreviousInstanceID, ReplacementInstanceID: state.InstanceID,
		AttachKey: memberOperationID(intent, seat.MemberID, state.HostAttempt, "attach-volume"),
	}
	if err := controller.guard(ctx, epoch); err != nil {
		return false, err
	}
	step, err := reattacher.Step(ctx, request)
	switch step.Kind {
	case failover.StepProveFence:
		if errors.Is(err, failover.ErrFenceUnobserved) {
			// A failed lookup is not a wait for TERMINATED: report it.
			controller.holdStalledAttachRequest(seat.MemberID, state)
			return false, fmt.Errorf("reattach retained member volume %s/%s: prove lost instance %s fenced: %w",
				intent.DatabaseID, seat.MemberID, state.PreviousInstanceID, err)
		}
		controller.hold(fmt.Sprintf("member %s replacement waits for OCI to report lost instance %s TERMINATED before its volume moves",
			seat.MemberID, state.PreviousInstanceID))
		controller.holdStalledAttachRequest(seat.MemberID, state)
		return false, nil
	case failover.StepHold:
		reason := step.Reason
		if err != nil && !errors.Is(err, storage.ErrVolumeHeld) {
			return false, err
		}
		controller.hold(fmt.Sprintf("member %s retained volume reattach is held for an operator: %s", seat.MemberID, reason))
		return false, nil
	case failover.StepWaitDetached:
		controller.hold(fmt.Sprintf("member %s retained volume waits for the lost instance's attachment %s to reach DETACHED",
			seat.MemberID, step.Attachment.ID))
		controller.holdStalledAttachRequest(seat.MemberID, state)
		return false, nil
	case failover.StepWaitAttached:
		controller.holdStuckAttachment(seat.MemberID, step.Attachment.ID, state)
		return false, nil
	case failover.StepDetach, failover.StepGrantMount:
		if err != nil {
			return false, fmt.Errorf("reattach retained member volume %s/%s (%s): %w", intent.DatabaseID, seat.MemberID, step.Kind, err)
		}
		return true, nil
	case failover.StepAttach:
		if err != nil {
			controller.holdStalledAttachRequest(seat.MemberID, state)
			return false, fmt.Errorf("reattach retained member volume %s/%s: %w", intent.DatabaseID, seat.MemberID, err)
		}
		return true, nil
	case failover.StepDone:
		if err != nil {
			return false, err
		}
		if step.Attachment.ID == "" || step.Attachment.InstanceID != state.InstanceID || step.Attachment.VolumeID != state.VolumeID {
			return false, errors.New("reattach completed with a mismatched replacement attachment")
		}
		if err := controller.guard(ctx, epoch); err != nil {
			return false, err
		}
		state.AttachmentID = step.Attachment.ID
		state.AttachRequestedAt = time.Time{}
		state.Stage = StageAwaitingRuntimeContract
		state.OperationID = memberOperationID(intent, seat.MemberID, state.HostAttempt, "runtime-hold")
		_, err = controller.persist(ctx, epoch, versioned.Revision, state)
		return true, err
	default:
		if err != nil {
			return false, fmt.Errorf("reattach retained member volume %s/%s: %w", intent.DatabaseID, seat.MemberID, err)
		}
		return false, fmt.Errorf("reattach retained member volume %s/%s returned step %q", intent.DatabaseID, seat.MemberID, step.Kind)
	}
}
