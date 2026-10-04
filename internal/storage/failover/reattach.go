// Package failover moves a retained volume from a lost host to its
// replacement. The one rule it never bends: the volume is attached elsewhere
// only after the old writer is proven fenced, and today the only accepted
// proof is OCI reporting the old instance TERMINATED. A host that merely
// stopped heartbeating may still be writing.
//
// The sequence is: prove fenced -> detach every attachment on the old
// instance -> wait until OCI reports them DETACHED -> attach to the
// replacement -> grant a mount-existing permit (never a format permit).
//
// Decide is pure; Reattacher executes exactly one step per call so a
// leader-only reconciler can drive it and persist progress between steps.
package failover

import (
	"context"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
)

// Config gates reattach-on-host-loss. It is off by default.
type Config struct {
	Enabled bool `json:"enabled,omitzero"`
}

// Attachment is one observed OCI attachment record of the volume.
type Attachment struct {
	ID         string
	VolumeID   string
	InstanceID string
	State      string
	ETag       string
}

// FenceProof records why the old writer can no longer write.
type FenceProof struct {
	InstanceID string
	State      string
	ObservedAt time.Time
}

// Request names the volume, the lost instance and its replacement.
type Request struct {
	DatabaseID, PartitionID string
	VolumeID                string
	OldInstanceID           string
	ReplacementInstanceID   string
	// AttachKey is the stable idempotency key of the replacement attach.
	AttachKey string
}

func (request Request) validate() error {
	if request.DatabaseID == "" || request.PartitionID == "" || request.VolumeID == "" ||
		request.OldInstanceID == "" || request.ReplacementInstanceID == "" || request.AttachKey == "" {
		return errors.New("reattach request is incomplete")
	}
	if request.OldInstanceID == request.ReplacementInstanceID {
		return errors.New("reattach replacement must be a different instance")
	}
	return nil
}

// StepKind is the next action of a reattach.
type StepKind string

const (
	StepProveFence   StepKind = "prove-fence"
	StepDetach       StepKind = "detach"
	StepWaitDetached StepKind = "wait-detached"
	StepAttach       StepKind = "attach"
	StepWaitAttached StepKind = "wait-attached"
	StepGrantMount   StepKind = "grant-mount-existing"
	StepDone         StepKind = "done"
	StepHold         StepKind = "hold"
)

// Step is the decided next action.
type Step struct {
	Kind       StepKind
	Attachment Attachment
	Reason     string
}

// Decide chooses the next step. fenced must come from ProveFenced for
// request.OldInstanceID. mounted reports that the replacement already holds a
// current mount-existing permit.
func Decide(request Request, fenced bool, attachments []Attachment, mounted bool) Step {
	if !fenced {
		return Step{Kind: StepProveFence, Reason: "old writer is not proven fenced"}
	}
	var replacement *Attachment
	for index := range attachments {
		attachment := attachments[index]
		if attachment.VolumeID != request.VolumeID {
			return Step{Kind: StepHold, Attachment: attachment, Reason: "attachment listing returned another volume"}
		}
		switch attachment.InstanceID {
		case request.OldInstanceID:
			switch attachment.State {
			case "DETACHED":
			case "DETACHING":
				return Step{Kind: StepWaitDetached, Attachment: attachment}
			case "ATTACHED", "ATTACHING":
				return Step{Kind: StepDetach, Attachment: attachment}
			default:
				return Step{Kind: StepHold, Attachment: attachment, Reason: "old attachment is in unknown state " + attachment.State}
			}
		case request.ReplacementInstanceID:
			if attachment.State == "DETACHED" {
				continue
			}
			if replacement != nil {
				return Step{Kind: StepHold, Attachment: attachment, Reason: "replacement has more than one live attachment"}
			}
			replacement = &attachments[index]
		default:
			if attachment.State != "DETACHED" {
				// A third writer was never proven fenced.
				return Step{Kind: StepHold, Attachment: attachment, Reason: "volume is attached to an unrelated instance"}
			}
		}
	}
	if replacement == nil {
		return Step{Kind: StepAttach}
	}
	switch replacement.State {
	case "ATTACHING":
		return Step{Kind: StepWaitAttached, Attachment: *replacement}
	case "ATTACHED":
		if mounted {
			return Step{Kind: StepDone, Attachment: *replacement}
		}
		return Step{Kind: StepGrantMount, Attachment: *replacement}
	default:
		return Step{Kind: StepHold, Attachment: *replacement, Reason: "replacement attachment is " + replacement.State}
	}
}

// InstanceObserver reads an instance's OCI lifecycle state.
type InstanceObserver interface {
	InstanceLifecycleState(ctx context.Context, instanceID string) (string, error)
}

// ProveFenced returns proof only when OCI reports the instance TERMINATED.
// TERMINATING, STOPPED or an unreachable host are not proof: a stopped
// instance can be started again with the volume still attached.
func ProveFenced(ctx context.Context, observer InstanceObserver, instanceID string, now time.Time) (FenceProof, error) {
	state, err := observer.InstanceLifecycleState(ctx, instanceID)
	if err != nil {
		return FenceProof{}, errors.Join(storage.ErrWriterNotFenced, ErrFenceUnobserved, err)
	}
	if state != "TERMINATED" {
		return FenceProof{}, fmt.Errorf("%w: instance %s is %s", storage.ErrWriterNotFenced, instanceID, state)
	}
	return FenceProof{InstanceID: instanceID, State: state, ObservedAt: now.UTC()}, nil
}

// ErrFenceUnobserved marks a missing fence proof caused by a failed lifecycle
// lookup (authorization, network, cancellation, a purged instance) rather
// than an observed non-TERMINATED state. Callers report it as an error
// instead of a normal wait.
var ErrFenceUnobserved = errors.New("lost instance lifecycle state could not be observed")

// VolumeAttacher is the journaled OCI attachment boundary used by reattach.
type VolumeAttacher interface {
	VolumeAttachments(ctx context.Context, volumeID string) ([]Attachment, error)
	// DetachFenced detaches an attachment of a proven-terminated instance.
	DetachFenced(ctx context.Context, request Request, attachment Attachment, proof FenceProof) error
	AttachReplacement(ctx context.Context, request Request, proof FenceProof) (Attachment, error)
}

// MountPermitter grants a one-time mount-existing permit; it must never
// grant format authority for a reattached volume.
type MountPermitter interface {
	GrantMountExisting(ctx context.Context, request Request, attachment Attachment) error
	HasMountExisting(ctx context.Context, request Request, attachment Attachment) (bool, error)
}

// Reattacher executes one reattach step per call on the authority leader.
type Reattacher struct {
	Config    Config
	Fencer    authority.Fencer
	Instances InstanceObserver
	Volumes   VolumeAttacher
	Permits   MountPermitter
	Now       func() time.Time
	// ExpectedEpoch, when non-zero, binds the step to the authority epoch
	// under which the caller read its inputs: a step under any other epoch
	// is fenced before anything is read or changed.
	ExpectedEpoch uint64
}

// Step decides and executes the next step and returns it. StepHold and
// StepProveFence return an error wrapping the reason.
func (reattacher Reattacher) Step(ctx context.Context, request Request) (Step, error) {
	if !reattacher.Config.Enabled {
		return Step{}, storage.ErrDisabled
	}
	if err := request.validate(); err != nil {
		return Step{}, err
	}
	if reattacher.Fencer == nil || reattacher.Instances == nil || reattacher.Volumes == nil || reattacher.Permits == nil {
		return Step{}, errors.New("reattacher requires authority, instance, volume and permit boundaries")
	}
	snapshot := reattacher.Fencer.Current()
	if !snapshot.CanMutate() {
		return Step{}, authority.ErrNotLeader
	}
	epoch := snapshot.Epoch
	if reattacher.ExpectedEpoch != 0 && epoch != reattacher.ExpectedEpoch {
		return Step{}, authority.ErrFenced
	}
	now := time.Now
	if reattacher.Now != nil {
		now = reattacher.Now
	}
	proof, proofErr := ProveFenced(ctx, reattacher.Instances, request.OldInstanceID, now())
	fenced := proofErr == nil
	if !fenced {
		// Nothing past the fence proof is decided while it is missing, so
		// the attachment listing is not read for this step.
		return Decide(request, false, nil, false), proofErr
	}
	attachments, err := reattacher.Volumes.VolumeAttachments(ctx, request.VolumeID)
	if err != nil {
		return Step{}, err
	}
	mounted := false
	step := Decide(request, fenced, attachments, false)
	if step.Kind == StepGrantMount {
		if mounted, err = reattacher.Permits.HasMountExisting(ctx, request, step.Attachment); err != nil {
			return Step{}, err
		}
		step = Decide(request, fenced, attachments, mounted)
	}
	switch step.Kind {
	case StepProveFence:
		return step, proofErr
	case StepHold:
		return step, fmt.Errorf("%w: %s", storage.ErrVolumeHeld, step.Reason)
	case StepWaitDetached, StepWaitAttached, StepDone:
		return step, nil
	}
	if err := reattacher.guard(ctx, epoch); err != nil {
		return step, err
	}
	switch step.Kind {
	case StepDetach:
		err := reattacher.Volumes.DetachFenced(ctx, request, step.Attachment, proof)
		if err == nil {
			recordFencedDetach(ctx, epoch, request, proof, step.Attachment)
		}
		return step, err
	case StepAttach:
		attached, err := reattacher.Volumes.AttachReplacement(ctx, request, proof)
		step.Attachment = attached
		if err == nil {
			recordReattach(ctx, epoch, request, proof, attached)
		}
		return step, err
	case StepGrantMount:
		err := reattacher.Permits.GrantMountExisting(ctx, request, step.Attachment)
		if err == nil {
			recordMountGranted(ctx, epoch, request, step.Attachment)
		}
		return step, err
	default:
		return step, fmt.Errorf("unknown reattach step %q", step.Kind)
	}
}

func (reattacher Reattacher) guard(ctx context.Context, epoch uint64) error {
	if snapshot := reattacher.Fencer.Current(); !snapshot.CanMutate() || snapshot.Epoch != epoch {
		return authority.ErrFenced
	}
	return reattacher.Fencer.Guard(ctx, epoch)
}

// recordReattach journals the replacement attach once per attach key: the
// attach is idempotent on that key, so a retried step does not duplicate it.
func recordReattach(ctx context.Context, epoch uint64, request Request, proof FenceProof, attached Attachment) {
	key := "reattach:" + request.AttachKey
	if decisionlog.Correlated(key) != "" {
		return
	}
	id := decisionlog.Record(ctx, decisionlog.Decision{
		Actor:   decisionlog.Actor{Slice: "storage"},
		Kind:    decisionlog.KindVolumeReattached,
		Subject: decisionlog.Subject{Kind: "volume", ID: request.VolumeID},
		Summary: "Reattached volume " + request.VolumeID + " to replacement instance " + request.ReplacementInstanceID,
		Reason:  "The previous writer instance was proven fenced (" + proof.State + ").",
		Rule:    "storage.reattach_on_host_loss",
		Signals: []decisionlog.Signal{{Name: "old_instance_state", Text: proof.State}},
		Status:  decisionlog.StatusInProgress,
		Epoch:   epoch,
		Attrs: map[string]string{"database": request.DatabaseID, "partition": request.PartitionID,
			"old_instance": request.OldInstanceID, "attachment": attached.ID},
	})
	decisionlog.Correlate(key, id)
}

// recordFencedDetach journals the detach of the lost instance's attachment,
// once per attachment, before the replacement attach.
func recordFencedDetach(ctx context.Context, epoch uint64, request Request, proof FenceProof, attachment Attachment) {
	key := "reattach-detach:" + request.AttachKey + ":" + attachment.ID
	if decisionlog.Correlated(key) != "" {
		return
	}
	id := decisionlog.Record(ctx, decisionlog.Decision{
		Actor:   decisionlog.Actor{Slice: "storage"},
		Kind:    decisionlog.KindVolumeReattached,
		Subject: decisionlog.Subject{Kind: "volume", ID: request.VolumeID},
		Summary: "Detached volume " + request.VolumeID + " from lost instance " + request.OldInstanceID,
		Reason:  "OCI reports the lost instance " + proof.State + ", so it can no longer write.",
		Rule:    "storage.reattach_on_host_loss",
		Signals: []decisionlog.Signal{{Name: "old_instance_state", Text: proof.State},
			{Name: "old_attachment_state", Text: attachment.State}},
		Status: decisionlog.StatusInProgress,
		Epoch:  epoch,
		Attrs: map[string]string{"database": request.DatabaseID, "partition": request.PartitionID,
			"old_instance": request.OldInstanceID, "attachment": attachment.ID},
	})
	decisionlog.Correlate(key, id)
}

// recordMountGranted closes the reattach chain: the replacement may mount
// the existing filesystem and is never allowed to format it.
func recordMountGranted(ctx context.Context, epoch uint64, request Request, attachment Attachment) {
	key := "reattach-mount:" + request.AttachKey
	if decisionlog.Correlated(key) != "" {
		return
	}
	id := decisionlog.Record(ctx, decisionlog.Decision{
		Actor:    decisionlog.Actor{Slice: "storage"},
		Kind:     decisionlog.KindVolumeReattached,
		Subject:  decisionlog.Subject{Kind: "volume", ID: request.VolumeID},
		Summary:  "Granted a mount-existing permit for volume " + request.VolumeID + " on its replacement instance",
		Reason:   "The volume is attached only to the replacement; its filesystem is mounted as is and never formatted.",
		Rule:     "storage.reattach_on_host_loss",
		Status:   decisionlog.StatusSucceeded,
		Epoch:    epoch,
		ParentID: decisionlog.Correlated("reattach:" + request.AttachKey),
		Attrs: map[string]string{"database": request.DatabaseID, "partition": request.PartitionID,
			"replacement_instance": request.ReplacementInstanceID, "attachment": attachment.ID},
	})
	decisionlog.Correlate(key, id)
}
