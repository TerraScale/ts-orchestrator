package provider

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// The block storage reconciler creates and repairs each member's data volume
// and its attachment (D-65): Balanced performance volumes, one per member
// slot, attached to that slot's instance. Volumes only ever grow — a declared
// size below the observed size is refused because shrinking destroys data.

// BalancedVPUsPerGiB is the OCI "Balanced" volume performance tier (D-65).
const BalancedVPUsPerGiB = 10

// These defaults are deliberately conservative.  A full volume may be grown
// by one current-volume-sized step, but never beyond OCI's supported bound.
const (
	DefaultFullUtilizationPercent uint8  = 95
	DefaultMaxVolumeGiB           uint64 = 32 * 1024
)

// DataVolumeName derives the deterministic data volume name for a member slot.
func DataVolumeName(regionCode string, index int) string {
	return "terrascale-" + regionCode + "-" + strconv.Itoa(index) + "-data"
}

type ObservedVolume struct {
	ID                 string
	DisplayName        string
	SizeGiB            uint64
	VPUsPerGiB         uint64
	LifecycleState     string
	AvailabilityDomain string
	// UtilizationPercent and HealthState are supplied by the host/storage
	// observation contract when available.  Zero/empty means that signal was
	// not reported; it is not treated as evidence of health or fullness.
	UtilizationPercent uint8
	HealthState        string
	// KMSKeyID is retained across a replacement.  An empty value means the
	// provider did not return encryption metadata, so replacement is unsafe.
	KMSKeyID string
	// BackupVerified and ReplicaCount are the minimum evidence a stateful
	// replacement needs.  They are intentionally observations, never guesses.
	BackupVerified bool
	ReplicaCount   uint8
	CompartmentID  string
	FreeformTags   map[string]string
}

type ObservedAttachment struct {
	ID             string
	InstanceID     string
	VolumeID       string
	LifecycleState string
	// OCI volume attachments have no freeform tag surface. Managed is set only
	// by an attach response or a trusted observation adapter; an ID alone is
	// never sufficient authority to detach.
	Managed       bool
	CompartmentID string
}

type BlockStorageObserved struct {
	Volumes     []ObservedVolume
	Attachments []ObservedAttachment
	Members     []ObservedMember
}

// BlockStoragePolicy controls repairs which can affect durable data.  A zero
// policy keeps the historical safe behaviour (create/expand/attach only).
// Replacement requires both explicit permission and proof of a recoverable
// copy; the reconciler never infers that proof from a provider lifecycle bit.
type BlockStoragePolicy struct {
	AllowReplacement       bool
	DataSafetyProven       bool
	FullUtilizationPercent uint8
	MaxVolumeGiB           uint64
}

// BlockStorageGateway is the OCI core-service seam for volume reconciliation.
type BlockStorageGateway interface {
	ListVolumes(ctx context.Context) ([]ObservedVolume, error)
	CreateVolume(ctx context.Context, spec VolumeSpec) (ObservedVolume, error)
	ExpandVolume(ctx context.Context, volumeID string, sizeGiB uint64) error
	ListAttachments(ctx context.Context) ([]ObservedAttachment, error)
	AttachVolume(ctx context.Context, instanceID, volumeID, displayName string) (ObservedAttachment, error)
	DetachAttachment(ctx context.Context, attachmentID string) error
}

type VolumeSpec struct {
	DisplayName        string
	SizeGiB            uint64
	VPUsPerGiB         uint64
	AvailabilityDomain string
	KMSKeyID           string
	// RetryToken binds retries of a replacement to the same intent. Empty
	// means the stable display name is sufficient for first-time creation.
	RetryToken string
}

type CreateVolumeAction struct{ Spec VolumeSpec }

func (a CreateVolumeAction) Kind() OCIActionKind { return OCIActionCreateVolume }
func (a CreateVolumeAction) Summary() string {
	return "create volume " + a.Spec.DisplayName + " (" + strconv.FormatUint(a.Spec.SizeGiB, 10) + " GiB Balanced)"
}

type ExpandVolumeAction struct {
	VolumeID   string
	NewSizeGiB uint64
}

func (a ExpandVolumeAction) Kind() OCIActionKind { return OCIActionExpandVolume }
func (a ExpandVolumeAction) Summary() string {
	return "expand volume " + a.VolumeID + " to " + strconv.FormatUint(a.NewSizeGiB, 10) + " GiB"
}

type AttachVolumeAction struct {
	InstanceID, VolumeID string
}

func (a AttachVolumeAction) Kind() OCIActionKind { return OCIActionAttachVolume }
func (a AttachVolumeAction) Summary() string {
	return "attach volume " + a.VolumeID + " to " + a.InstanceID
}

type DetachAttachmentAction struct{ AttachmentID string }

func (a DetachAttachmentAction) Kind() OCIActionKind { return OCIActionDetachAttachment }
func (a DetachAttachmentAction) Summary() string     { return "detach attachment " + a.AttachmentID }

// ReplaceVolumeAction is an additive, data-preserving repair. Apply creates
// the replacement in the old volume's residency and encryption scope, binds
// it to the existing member, and only then detaches the old attachment. The
// old volume is intentionally never deleted by this reconciler.
type ReplaceVolumeAction struct {
	OldVolumeID     string
	OldAttachmentID string
	InstanceID      string
	Spec            VolumeSpec
}

// A replacement is reported as a create for existing drift/reporting
// consumers; it remains an action owned by this reconciler in Apply.
func (a ReplaceVolumeAction) Kind() OCIActionKind { return OCIActionCreateVolume }
func (a ReplaceVolumeAction) Summary() string {
	return "replace volume " + a.OldVolumeID + " with " + a.Spec.DisplayName
}

// BlockStorageReconciler converges one Region's data volumes and attachments.
type BlockStorageReconciler struct {
	Block   BlockStorageGateway
	Compute ComputeGateway
	Policy  BlockStoragePolicy
}

var _ OCIReconciler[estate.Region, BlockStorageObserved] = (*BlockStorageReconciler)(nil)

func volumeIsLive(state string) bool {
	return state != "TERMINATED" && state != "TERMINATING" && state != "" && state != "FAILED" && state != "ERROR"
}

func attachmentIsLive(state string) bool {
	return state != "DETACHED" && state != "DETACHING" && state != "" && state != "FAILED" && state != "ERROR"
}

type volumeLifecycleState uint8

const (
	volumeStateAbsent volumeLifecycleState = iota
	volumeStatePending
	volumeStateActive
	volumeStateFailed
	volumeStateUnknown
)

func observedVolumeState(state string) volumeLifecycleState {
	switch state {
	case "AVAILABLE":
		return volumeStateActive
	case "CREATING", "PROVISIONING", "RESTORING", "UPDATING", "ATTACHING":
		return volumeStatePending
	case "TERMINATED", "TERMINATING", "":
		return volumeStateAbsent
	case "FAILED", "ERROR":
		return volumeStateFailed
	default:
		return volumeStateUnknown
	}
}

type attachmentLifecycleState uint8

const (
	attachmentStateAbsent attachmentLifecycleState = iota
	attachmentStatePending
	attachmentStateActive
	attachmentStateFailed
	attachmentStateUnknown
)

func observedAttachmentState(state string) attachmentLifecycleState {
	switch state {
	case "ATTACHED":
		return attachmentStateActive
	case "ATTACHING", "DETACHING", "UPDATING":
		return attachmentStatePending
	case "DETACHED", "":
		return attachmentStateAbsent
	case "FAILED", "ERROR":
		return attachmentStateFailed
	default:
		return attachmentStateUnknown
	}
}

func (r *BlockStorageReconciler) Observe(ctx context.Context, declared estate.Region) (BlockStorageObserved, error) {
	if r == nil || r.Block == nil || r.Compute == nil {
		return BlockStorageObserved{}, &InvalidOperationError{Message: "block storage reconciler is unavailable"}
	}
	if ctx == nil {
		return BlockStorageObserved{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return BlockStorageObserved{}, err
	}
	observed := BlockStorageObserved{}
	var err error
	if observed.Volumes, err = r.Block.ListVolumes(ctx); err != nil {
		return BlockStorageObserved{}, err
	}
	if observed.Attachments, err = r.Block.ListAttachments(ctx); err != nil {
		return BlockStorageObserved{}, err
	}
	if observed.Members, err = r.Compute.ListMembers(ctx); err != nil {
		return BlockStorageObserved{}, err
	}
	return observed, nil
}

func (r *BlockStorageReconciler) Reconcile(ctx context.Context, declared estate.Region, observed BlockStorageObserved) (OCIPlan, error) {
	if r == nil || r.Block == nil || r.Compute == nil {
		return OCIPlan{}, &InvalidOperationError{Message: "block storage reconciler is unavailable"}
	}
	if ctx == nil {
		return OCIPlan{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return OCIPlan{}, err
	}
	pool := declared.Members
	if pool.DataVolumeGiB == 0 {
		return OCIPlan{}, &errs.Argument{Message: "declared member pool has no data volume size"}
	}
	if uint64(pool.DataVolumeGiB) > r.maxVolumeGiB() {
		return OCIPlan{}, &errs.Argument{Message: "declared member data volume exceeds the bounded expansion limit"}
	}
	members := make(map[int]ObservedMember, len(observed.Members))
	for _, member := range observed.Members {
		switch observedMemberState(member.LifecycleState) {
		case memberStateAbsent:
			continue
		case memberStateFailed:
			return OCIPlan{}, &InvalidDataError{Message: "observed member " + member.DisplayName + " failed and cannot host a volume"}
		case memberStateUnknown:
			return OCIPlan{}, &InvalidDataError{Message: "observed member " + member.DisplayName + " has an unusable lifecycle state"}
		}
		if _, duplicate := members[member.Index]; duplicate {
			return OCIPlan{}, &InvalidDataError{Message: "multiple instances occupy declared member slot " + strconv.Itoa(member.Index)}
		}
		members[member.Index] = member
	}
	declaredVolumeNames := make(map[string]bool, int(pool.Count))
	for index := 1; index <= int(pool.Count); index++ {
		declaredVolumeNames[DataVolumeName(declared.Code, index)] = true
	}
	volumes := make(map[string]ObservedVolume, len(observed.Volumes))
	for _, volume := range observed.Volumes {
		if !declaredVolumeNames[volume.DisplayName] {
			continue
		}
		state := observedVolumeState(volume.LifecycleState)
		if state == volumeStateAbsent {
			continue
		}
		if state == volumeStateUnknown {
			return OCIPlan{}, &InvalidDataError{Message: "observed volume " + volume.DisplayName + " has an unusable lifecycle state"}
		}
		if volume.HealthState != "" && !volumeHealthIsKnown(volume.HealthState) {
			return OCIPlan{}, &InvalidDataError{Message: "observed volume " + volume.DisplayName + " has an unusable health state"}
		}
		if volume.UtilizationPercent > 100 {
			return OCIPlan{}, &InvalidDataError{Message: "observed volume " + volume.DisplayName + " has an invalid utilization"}
		}
		if previous, duplicate := volumes[volume.DisplayName]; duplicate {
			// A failed/terminated volume can coexist with the replacement while
			// an asynchronous repair settles. Prefer the usable observation;
			// two usable volumes are ambiguous and fail closed.
			if volumeSelectionRank(volume) > volumeSelectionRank(previous) {
				volumes[volume.DisplayName] = volume
				continue
			}
			if volumeSelectionRank(volume) < volumeSelectionRank(previous) {
				continue
			}
			return OCIPlan{}, &InvalidDataError{Message: "multiple usable volumes share the declared name " + volume.DisplayName}
		}
		volumes[volume.DisplayName] = volume
	}
	plan := OCIPlan{}
	attachments := make(map[string]ObservedAttachment, len(observed.Attachments))
	for _, attachment := range observed.Attachments {
		state := observedAttachmentState(attachment.LifecycleState)
		if state == attachmentStateFailed {
			return OCIPlan{}, &InvalidDataError{Message: "observed volume attachment " + attachment.ID + " failed and cannot be used"}
		}
		if state == attachmentStateUnknown {
			return OCIPlan{}, &InvalidDataError{Message: "observed volume attachment " + attachment.ID + " has an unusable lifecycle state"}
		}
		if state == attachmentStateAbsent {
			continue
		}
		volumeName := volumeNameByID(observed, attachment.VolumeID)
		if volumeName == "" {
			return OCIPlan{}, &InvalidDataError{Message: "observed attachment " + attachment.ID + " refers to an unknown volume"}
		}
		if !declaredVolumeNames[volumeName] {
			continue
		}
		if _, duplicate := attachments[attachment.VolumeID]; duplicate {
			return OCIPlan{}, &InvalidDataError{Message: "multiple attachments exist for volume " + attachment.VolumeID}
		}
		attachments[attachment.VolumeID] = attachment
	}
	for index := 1; index <= int(pool.Count); index++ {
		name := DataVolumeName(declared.Code, index)
		member, memberExists := members[index]
		volume, volumeExists := volumes[name]
		if !memberExists || observedMemberState(member.LifecycleState) != memberStateActive {
			// Compute must produce a RUNNING instance before a volume can be
			// created or attached. Bootstrap polls this pending slot.
			continue
		}
		if !volumeExists {
			plan.Actions = append(plan.Actions, CreateVolumeAction{Spec: VolumeSpec{
				DisplayName:        name,
				SizeGiB:            uint64(pool.DataVolumeGiB),
				VPUsPerGiB:         BalancedVPUsPerGiB,
				AvailabilityDomain: member.AvailabilityDomain,
			}})
			continue
		}
		if observedVolumeState(volume.LifecycleState) == volumeStatePending {
			continue
		}
		if volume.SizeGiB == 0 {
			return OCIPlan{}, &InvalidDataError{Message: "observed volume " + name + " has no size"}
		}
		if volume.AvailabilityDomain != "" && member.AvailabilityDomain != "" && volume.AvailabilityDomain != member.AvailabilityDomain {
			return OCIPlan{}, &InvalidDataError{Message: "volume " + name + " is outside the member availability domain"}
		}
		if volumeNeedsReplacement(volume) {
			if !r.Policy.AllowReplacement || !r.volumeSafetyProven(volume) {
				return OCIPlan{}, &InvalidDataError{Message: "observed volume " + name + " is unhealthy and replacement safety is unproven"}
			}
			if volume.KMSKeyID == "" {
				return OCIPlan{}, &InvalidDataError{Message: "observed volume " + name + " has no encryption identity for replacement"}
			}
			if volume.SizeGiB > r.maxVolumeGiB() {
				return OCIPlan{}, &InvalidDataError{Message: "unhealthy volume " + name + " exceeds the bounded replacement size"}
			}
			availabilityDomain := volume.AvailabilityDomain
			if availabilityDomain == "" {
				availabilityDomain = member.AvailabilityDomain
			}
			var oldAttachmentID string
			if attachment, attached := attachments[volume.ID]; attached {
				if observedAttachmentState(attachment.LifecycleState) == attachmentStatePending {
					continue
				}
				oldAttachmentID = attachment.ID
			}
			plan.Actions = append(plan.Actions, ReplaceVolumeAction{
				OldVolumeID: volume.ID, OldAttachmentID: oldAttachmentID, InstanceID: member.ID,
				Spec: VolumeSpec{DisplayName: name, SizeGiB: maxVolumeSize(volume.SizeGiB, uint64(pool.DataVolumeGiB)), VPUsPerGiB: BalancedVPUsPerGiB, AvailabilityDomain: availabilityDomain, KMSKeyID: volume.KMSKeyID, RetryToken: volume.ID + ".replacement"},
			})
			continue
		}
		targetSize := uint64(pool.DataVolumeGiB)
		if volume.SizeGiB > uint64(pool.DataVolumeGiB) {
			// A larger observed volume is safe to retain, but report the drift
			// unless the full-volume repair below is the reason it grew.
			if !volumeIsFull(volume, r.Policy) {
				return OCIPlan{}, &InvalidDataError{Message: "declared data volume size is below the observed volume; volumes never shrink"}
			}
		}
		if volume.VPUsPerGiB != BalancedVPUsPerGiB {
			return OCIPlan{}, &InvalidDataError{Message: "observed volume " + name + " is not on the Balanced performance tier"}
		}
		if volumeIsFull(volume, r.Policy) {
			maxSize := r.maxVolumeGiB()
			if volume.SizeGiB >= maxSize {
				return OCIPlan{}, &InvalidDataError{Message: "full volume " + name + " reached the bounded expansion limit"}
			}
			newSize := volume.SizeGiB * 2
			if newSize < volume.SizeGiB || newSize < uint64(pool.DataVolumeGiB) {
				newSize = uint64(pool.DataVolumeGiB)
			}
			if newSize > maxSize {
				newSize = maxSize
			}
			if newSize > targetSize {
				targetSize = newSize
			}
		}
		if targetSize > volume.SizeGiB {
			plan.Actions = append(plan.Actions, ExpandVolumeAction{VolumeID: volume.ID, NewSizeGiB: targetSize})
		}
		if attachment, attached := attachments[volume.ID]; attached {
			if observedAttachmentState(attachment.LifecycleState) == attachmentStatePending {
				continue
			}
			if attachment.InstanceID == member.ID {
				continue
			}
			plan.Actions = append(plan.Actions, DetachAttachmentAction{AttachmentID: attachment.ID})
			// The detach and attach form one ordered repair. OCI accepts the
			// deterministic attach retry token; a later pass observes the
			// attachment if the provider performs the operation asynchronously.
			plan.Actions = append(plan.Actions, AttachVolumeAction{InstanceID: member.ID, VolumeID: volume.ID})
			continue
		}
		plan.Actions = append(plan.Actions, AttachVolumeAction{InstanceID: member.ID, VolumeID: volume.ID})
	}
	for _, attachment := range observed.Attachments {
		if !attachmentOwned(attachment, observed, declared.Code) {
			continue
		}
		state := observedAttachmentState(attachment.LifecycleState)
		if state != attachmentStateActive {
			continue
		}
		name := volumeNameByID(observed, attachment.VolumeID)
		desired, selected := volumes[name]
		if selected && observedVolumeState(desired.LifecycleState) == volumeStatePending {
			// Keep the known-good/last-known attachment until the replacement
			// volume is AVAILABLE and can be attached safely.
			continue
		}
		if name == "" || !declaredVolumeNames[name] || (selected && desired.ID != attachment.VolumeID) {
			plan.Actions = append(plan.Actions, DetachAttachmentAction{AttachmentID: attachment.ID})
		}
	}
	return plan, nil
}

func volumeNameByID(observed BlockStorageObserved, volumeID string) string {
	for _, volume := range observed.Volumes {
		if volume.ID == volumeID {
			return volume.DisplayName
		}
	}
	return ""
}

func volumeHealthIsKnown(state string) bool {
	switch state {
	case "HEALTHY", "AVAILABLE", "ONLINE", "OK", "GOOD", "DEGRADED", "UNHEALTHY", "FAILED", "ERROR", "FAULTED", "INACCESSIBLE", "IO_ERROR":
		return true
	default:
		return false
	}
}

func volumeUsableForSelection(volume ObservedVolume) bool {
	return observedVolumeState(volume.LifecycleState) == volumeStateActive && !volumeNeedsReplacement(volume)
}

func volumeSelectionRank(volume ObservedVolume) uint8 {
	if volumeUsableForSelection(volume) {
		return 3
	}
	if observedVolumeState(volume.LifecycleState) == volumeStatePending {
		return 2
	}
	return 1
}

func volumeNeedsReplacement(volume ObservedVolume) bool {
	if observedVolumeState(volume.LifecycleState) == volumeStateFailed {
		return true
	}
	switch volume.HealthState {
	case "DEGRADED", "UNHEALTHY", "FAILED", "ERROR", "FAULTED", "INACCESSIBLE", "IO_ERROR":
		return true
	default:
		return false
	}
}

func (r *BlockStorageReconciler) volumeSafetyProven(volume ObservedVolume) bool {
	return r.Policy.DataSafetyProven || (volume.BackupVerified && volume.ReplicaCount >= 2)
}

func (r *BlockStorageReconciler) maxVolumeGiB() uint64 {
	if r == nil || r.Policy.MaxVolumeGiB == 0 {
		return DefaultMaxVolumeGiB
	}
	return r.Policy.MaxVolumeGiB
}

func maxVolumeSize(current, desired uint64) uint64 {
	if current > desired {
		return current
	}
	return desired
}

func volumeIsFull(volume ObservedVolume, policy BlockStoragePolicy) bool {
	if volume.UtilizationPercent == 0 {
		return false
	}
	threshold := policy.FullUtilizationPercent
	if threshold == 0 {
		threshold = DefaultFullUtilizationPercent
	}
	return volume.UtilizationPercent >= threshold
}

func (r *BlockStorageReconciler) bootstrapConverged(value, declaration any) (bool, error) {
	observed, ok := value.(BlockStorageObserved)
	if !ok {
		return false, &InvalidDataError{Message: "block storage convergence observation has the wrong type"}
	}
	declared, ok := declaration.(estate.Region)
	if !ok {
		return false, &InvalidDataError{Message: "block storage convergence declaration has the wrong type"}
	}
	members := make(map[int]ObservedMember, len(observed.Members))
	for _, member := range observed.Members {
		switch observedMemberState(member.LifecycleState) {
		case memberStateFailed:
			return false, &InvalidDataError{Message: "observed member " + member.DisplayName + " failed and cannot host a volume"}
		case memberStateUnknown:
			return false, &InvalidDataError{Message: "observed member " + member.DisplayName + " has an unusable lifecycle state"}
		case memberStateAbsent:
			continue
		}
		if _, duplicate := members[member.Index]; duplicate {
			return false, &InvalidDataError{Message: "multiple instances occupy declared member slot " + strconv.Itoa(member.Index)}
		}
		members[member.Index] = member
	}
	volumes := make(map[string]ObservedVolume, len(observed.Volumes))
	for _, volume := range observed.Volumes {
		if !declaredVolumeName(declared, volume.DisplayName) {
			continue
		}
		switch observedVolumeState(volume.LifecycleState) {
		case volumeStatePending:
			return false, nil
		case volumeStateFailed:
			// A failed volume is a repair candidate. Reconcile decides whether
			// replacement is permitted; bootstrap must keep polling rather than
			// declaring a data-loss failure.
			continue
		case volumeStateUnknown:
			return false, &InvalidDataError{Message: "observed volume " + volume.DisplayName + " has an unusable lifecycle state"}
		case volumeStateAbsent:
			continue
		}
		if volume.HealthState != "" && volumeNeedsReplacement(volume) {
			return false, nil
		}
		if _, duplicate := volumes[volume.DisplayName]; duplicate {
			return false, &InvalidDataError{Message: "multiple volumes share the declared name " + volume.DisplayName}
		}
		volumes[volume.DisplayName] = volume
	}
	attachments := make(map[string]ObservedAttachment, len(observed.Attachments))
	for _, attachment := range observed.Attachments {
		state := observedAttachmentState(attachment.LifecycleState)
		volumeName := volumeNameByID(observed, attachment.VolumeID)
		if volumeName == "" && state != attachmentStateAbsent {
			return false, &InvalidDataError{Message: "observed attachment " + attachment.ID + " refers to an unknown volume"}
		}
		if !declaredVolumeName(declared, volumeName) {
			if state == attachmentStatePending {
				return false, nil
			}
			continue
		}
		switch state {
		case attachmentStatePending:
			return false, nil
		case attachmentStateFailed:
			return false, &InvalidDataError{Message: "observed volume attachment " + attachment.ID + " failed and cannot be used"}
		case attachmentStateUnknown:
			return false, &InvalidDataError{Message: "observed volume attachment " + attachment.ID + " has an unusable lifecycle state"}
		case attachmentStateAbsent:
			continue
		}
		if _, duplicate := attachments[attachment.VolumeID]; duplicate {
			return false, &InvalidDataError{Message: "multiple attachments exist for volume " + attachment.VolumeID}
		}
		attachments[attachment.VolumeID] = attachment
	}
	for index := 1; index <= int(declared.Members.Count); index++ {
		member, memberOK := members[index]
		if !memberOK || observedMemberState(member.LifecycleState) != memberStateActive {
			return false, nil
		}
		name := DataVolumeName(declared.Code, index)
		volume, volumeOK := volumes[name]
		if !volumeOK || observedVolumeState(volume.LifecycleState) != volumeStateActive || volume.SizeGiB < uint64(declared.Members.DataVolumeGiB) || volume.VPUsPerGiB != BalancedVPUsPerGiB || volumeNeedsReplacement(volume) || volumeIsFull(volume, r.Policy) {
			return false, nil
		}
		attachment, attached := attachments[volume.ID]
		if !attached || observedAttachmentState(attachment.LifecycleState) != attachmentStateActive || attachment.InstanceID != member.ID {
			return false, nil
		}
	}
	return true, nil
}

func declaredVolumeName(region estate.Region, name string) bool {
	for index := 1; index <= int(region.Members.Count); index++ {
		if DataVolumeName(region.Code, index) == name {
			return true
		}
	}
	return false
}

func (r *BlockStorageReconciler) Apply(ctx context.Context, declared estate.Region, observed BlockStorageObserved, plan OCIPlan) error {
	if r == nil || r.Block == nil {
		return &InvalidOperationError{Message: "block storage reconciler is unavailable"}
	}
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, action := range plan.Actions {
		switch a := action.(type) {
		case CreateVolumeAction:
			if _, err := r.Block.CreateVolume(ctx, a.Spec); err != nil {
				return blockMutationError(ctx, err)
			}
		case ExpandVolumeAction:
			if err := r.Block.ExpandVolume(ctx, a.VolumeID, a.NewSizeGiB); err != nil {
				return blockMutationError(ctx, err)
			}
		case AttachVolumeAction:
			if _, err := r.Block.AttachVolume(ctx, a.InstanceID, a.VolumeID, ""); err != nil {
				return blockMutationError(ctx, err)
			}
		case DetachAttachmentAction:
			if err := r.detachOwnedAttachment(ctx, declared.Code, observed, a.AttachmentID); err != nil {
				return blockMutationError(ctx, err)
			}
		case ReplaceVolumeAction:
			if a.OldVolumeID == "" || a.InstanceID == "" || a.Spec.DisplayName == "" || a.Spec.SizeGiB == 0 || a.Spec.AvailabilityDomain == "" || a.Spec.KMSKeyID == "" || a.Spec.RetryToken == "" {
				return &InvalidOperationError{Message: "volume replacement action is incomplete"}
			}
			var oldVolume bool
			for _, volume := range observed.Volumes {
				if volume.ID == a.OldVolumeID && volume.DisplayName == a.Spec.DisplayName {
					oldVolume = true
					break
				}
			}
			if !oldVolume {
				return &InvalidOperationError{Message: "volume replacement action is stale"}
			}
			if a.OldAttachmentID != "" {
				found := false
				for _, attachment := range observed.Attachments {
					if attachment.ID == a.OldAttachmentID && attachment.VolumeID == a.OldVolumeID {
						found = true
						break
					}
				}
				if !found {
					return &InvalidOperationError{Message: "volume replacement attachment is stale"}
				}
			}
			created, err := r.Block.CreateVolume(ctx, a.Spec)
			if err != nil {
				return blockMutationError(ctx, err)
			}
			if created.ID == "" {
				return &ProviderOutcomeUnknownError{Message: "volume replacement create returned no identity"}
			}
			if observedVolumeState(created.LifecycleState) == volumeStatePending {
				// OCI creates are asynchronous. The old attachment remains in
				// place; the next observation selects this pending replacement
				// and waits before issuing an attach.
				return nil
			}
			if observedVolumeState(created.LifecycleState) != volumeStateActive {
				return &ProviderOutcomeUnknownError{Message: "volume replacement create has an unconfirmed lifecycle state"}
			}
			if _, err := r.Block.AttachVolume(ctx, a.InstanceID, created.ID, a.Spec.DisplayName); err != nil {
				return blockMutationError(ctx, err)
			}
			if a.OldAttachmentID != "" {
				if err := r.detachOwnedAttachment(ctx, declared.Code, observed, a.OldAttachmentID); err != nil {
					return blockMutationError(ctx, err)
				}
			}
		default:
			return &InvalidOperationError{Message: "block storage reconciler received a foreign action"}
		}
	}
	return nil
}

func volumeOwnedInRegion(volume ObservedVolume, region string) bool {
	return isOCID(volume.ID, "volume") && positiveOCIOwnership(volume.FreeformTags, "volume", region) &&
		volume.DisplayName == DataVolumeName(region, volumeSlot(volume.DisplayName))
}

func volumeSlot(name string) int {
	const suffix = "-data"
	if len(name) <= len(suffix) || name[len(name)-len(suffix):] != suffix {
		return 0
	}
	part := name[:len(name)-len(suffix)]
	for i := len(part) - 1; i >= 0; i-- {
		if part[i] == '-' {
			v, err := strconv.Atoi(part[i+1:])
			if err == nil {
				return v
			}
			break
		}
	}
	return 0
}

func attachmentOwned(attachment ObservedAttachment, observed BlockStorageObserved, region string) bool {
	if !isOCID(attachment.ID, "volumeattachment") || !isOCID(attachment.InstanceID, "instance") || !isOCID(attachment.VolumeID, "volume") {
		return false
	}
	if attachment.Managed {
		return true
	}
	// Attachments have no OCI tag API. A future trusted adapter may set
	// Managed after proving both parent resources; absent that proof preserve.
	return false
}

func sameObservedAttachment(a, b ObservedAttachment) bool {
	return a.ID == b.ID && a.InstanceID == b.InstanceID && a.VolumeID == b.VolumeID && a.LifecycleState == b.LifecycleState && a.Managed == b.Managed && a.CompartmentID == b.CompartmentID
}

func (r *BlockStorageReconciler) detachOwnedAttachment(ctx context.Context, region string, observed BlockStorageObserved, id string) error {
	var expected ObservedAttachment
	found := false
	for _, attachment := range observed.Attachments {
		if attachment.ID == id {
			expected, found = attachment, true
			break
		}
	}
	if !found || !attachmentOwned(expected, observed, region) {
		return &InvalidOperationError{Message: "attachment detach requires positively owned observed attachment"}
	}
	current, err := r.Block.ListAttachments(ctx)
	if err != nil {
		return err
	}
	for _, attachment := range current {
		if attachment.ID != id {
			continue
		}
		if !attachmentOwned(attachment, observed, region) || !sameObservedAttachment(attachment, expected) {
			return &InvalidOperationError{Message: "refusing stale or ownership-changed attachment detach"}
		}
		return r.Block.DetachAttachment(ctx, id)
	}
	return nil
}

// blockMutationError turns transport failures after a request may have been
// accepted into the shared unknown-outcome contract.  Cancellation remains a
// context error so callers can distinguish a stopped reconcile from a cloud
// mutation which needs re-observation.
func blockMutationError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if indeterminate(err) {
		return &ProviderOutcomeUnknownError{Message: "block storage mutation outcome is unknown; reconcile after observation"}
	}
	return err
}

// OCIBlockStorageGateway is the real block-volume gateway over the signed
// core-service transport.
type OCIBlockStorageGateway struct {
	Core          *OCIHTTPTransport
	CompartmentID string
}

var _ BlockStorageGateway = (*OCIBlockStorageGateway)(nil)

// NewOCIBlockStorageGateway validates the compartment scope.
func NewOCIBlockStorageGateway(core *OCIHTTPTransport, compartmentID string) (*OCIBlockStorageGateway, error) {
	if core == nil || core.Config.Service != OCIServiceCore {
		return nil, &errs.Argument{Message: "block storage gateway requires the OCI core transport"}
	}
	if !isOCID(compartmentID, "compartment") {
		return nil, &errs.Argument{Message: "block storage gateway requires a compartment identity"}
	}
	return &OCIBlockStorageGateway{Core: core, CompartmentID: compartmentID}, nil
}

type ociVolumeDocument struct {
	ID                 string            `json:"id"`
	CompartmentID      string            `json:"compartmentId"`
	DisplayName        string            `json:"displayName"`
	SizeInGBs          uint64            `json:"sizeInGBs"`
	VPUsPerGB          uint64            `json:"vpusPerGB"`
	LifecycleState     string            `json:"lifecycleState"`
	AvailabilityDomain string            `json:"availabilityDomain"`
	KMSKeyID           string            `json:"kmsKeyId"`
	UtilizationPercent uint8             `json:"utilizationPercent"`
	HealthState        string            `json:"healthState"`
	BackupVerified     bool              `json:"backupVerified"`
	ReplicaCount       uint8             `json:"replicaCount"`
	FreeformTags       map[string]string `json:"freeformTags"`
}

func (g *OCIBlockStorageGateway) ListVolumes(ctx context.Context) ([]ObservedVolume, error) {
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	var list struct {
		Items []ociVolumeDocument `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Core, http.MethodGet, "/20160918/volumes?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	volumes := make([]ObservedVolume, 0, len(list.Items))
	for _, item := range list.Items {
		if !isOCID(item.ID, "volume") {
			return nil, &InvalidDataError{Message: "OCI volume response is invalid"}
		}
		volumes = append(volumes, ObservedVolume{ID: item.ID, DisplayName: item.DisplayName, SizeGiB: item.SizeInGBs, VPUsPerGiB: item.VPUsPerGB, LifecycleState: item.LifecycleState, AvailabilityDomain: item.AvailabilityDomain, KMSKeyID: item.KMSKeyID, UtilizationPercent: item.UtilizationPercent, HealthState: item.HealthState, BackupVerified: item.BackupVerified, ReplicaCount: item.ReplicaCount, CompartmentID: item.CompartmentID, FreeformTags: copyOCITags(item.FreeformTags)})
	}
	return volumes, nil
}

func (g *OCIBlockStorageGateway) CreateVolume(ctx context.Context, spec VolumeSpec) (ObservedVolume, error) {
	if !validEstateName(spec.DisplayName) || spec.SizeGiB == 0 || spec.SizeGiB > 16<<20 ||
		spec.VPUsPerGiB == 0 || spec.VPUsPerGiB > 120 || len(spec.AvailabilityDomain) == 0 || len(spec.AvailabilityDomain) > 128 ||
		(spec.RetryToken != "" && (len(spec.RetryToken) > 96 || !tokenPattern.MatchString(spec.RetryToken))) {
		return ObservedVolume{}, &errs.Argument{Message: "volume create request is invalid"}
	}
	var document ociVolumeDocument
	retryToken := spec.RetryToken
	if retryToken == "" {
		retryToken = spec.DisplayName
	}
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/volumes", struct {
		CompartmentID      string            `json:"compartmentId"`
		AvailabilityDomain string            `json:"availabilityDomain"`
		DisplayName        string            `json:"displayName"`
		SizeInGBs          uint64            `json:"sizeInGBs"`
		VPUsPerGB          uint64            `json:"vpusPerGB"`
		KMSKeyID           string            `json:"kmsKeyId,omitempty"`
		FreeformTags       map[string]string `json:"freeformTags"`
	}{CompartmentID: g.CompartmentID, AvailabilityDomain: spec.AvailabilityDomain, DisplayName: spec.DisplayName, SizeInGBs: spec.SizeGiB, VPUsPerGB: spec.VPUsPerGiB, KMSKeyID: spec.KMSKeyID, FreeformTags: volumeOwnershipTags(spec.DisplayName)}, map[string]string{"opc-retry-token": retryToken}, &document); err != nil {
		return ObservedVolume{}, err
	}
	if !isOCID(document.ID, "volume") {
		return ObservedVolume{}, &InvalidDataError{Message: "OCI volume create response is invalid"}
	}
	return ObservedVolume{ID: document.ID, DisplayName: document.DisplayName, SizeGiB: document.SizeInGBs, VPUsPerGiB: document.VPUsPerGB, LifecycleState: document.LifecycleState, AvailabilityDomain: document.AvailabilityDomain, KMSKeyID: document.KMSKeyID, UtilizationPercent: document.UtilizationPercent, HealthState: document.HealthState, BackupVerified: document.BackupVerified, ReplicaCount: document.ReplicaCount, CompartmentID: document.CompartmentID, FreeformTags: copyOCITags(document.FreeformTags)}, nil
}

func (g *OCIBlockStorageGateway) ExpandVolume(ctx context.Context, volumeID string, sizeGiB uint64) error {
	if !isOCID(volumeID, "volume") || sizeGiB == 0 || sizeGiB > 16<<20 {
		return &errs.Argument{Message: "volume expand request is invalid"}
	}
	return doOCIJSON[struct{}](ctx, g.Core, http.MethodPut, "/20160918/volumes/"+url.PathEscape(volumeID), struct {
		SizeInGBs uint64 `json:"sizeInGBs"`
	}{SizeInGBs: sizeGiB}, map[string]string{"opc-retry-token": volumeID + "/" + strconv.FormatUint(sizeGiB, 10)}, nil)
}

type ociAttachmentDocument struct {
	ID             string `json:"id"`
	InstanceID     string `json:"instanceId"`
	VolumeID       string `json:"volumeId"`
	LifecycleState string `json:"lifecycleState"`
}

func (g *OCIBlockStorageGateway) ListAttachments(ctx context.Context) ([]ObservedAttachment, error) {
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	var list struct {
		Items []ociAttachmentDocument `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Core, http.MethodGet, "/20160918/volumeAttachments?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	attachments := make([]ObservedAttachment, 0, len(list.Items))
	for _, item := range list.Items {
		if !isOCID(item.ID, "volumeattachment") || !isOCID(item.InstanceID, "instance") || !isOCID(item.VolumeID, "volume") {
			return nil, &InvalidDataError{Message: "OCI volume attachment response is invalid"}
		}
		attachments = append(attachments, ObservedAttachment{ID: item.ID, InstanceID: item.InstanceID, VolumeID: item.VolumeID, LifecycleState: item.LifecycleState, CompartmentID: g.CompartmentID})
	}
	return attachments, nil
}

func (g *OCIBlockStorageGateway) AttachVolume(ctx context.Context, instanceID, volumeID, displayName string) (ObservedAttachment, error) {
	if !isOCID(instanceID, "instance") || !isOCID(volumeID, "volume") {
		return ObservedAttachment{}, &errs.Argument{Message: "volume attach request is invalid"}
	}
	if displayName == "" {
		// OCI requires a display name; derive a stable one from the ids.
		displayName = "terrascale-attachment-" + shortOCID(volumeID)
	}
	var document ociAttachmentDocument
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/volumeAttachments", struct {
		CompartmentID string `json:"compartmentId"`
		InstanceID    string `json:"instanceId"`
		VolumeID      string `json:"volumeId"`
		AttachmentTyp string `json:"type"`
		DisplayName   string `json:"displayName"`
	}{CompartmentID: g.CompartmentID, InstanceID: instanceID, VolumeID: volumeID, AttachmentTyp: "iscsi", DisplayName: displayName}, map[string]string{"opc-retry-token": instanceID + "/" + volumeID}, &document); err != nil {
		return ObservedAttachment{}, err
	}
	if !isOCID(document.ID, "volumeattachment") {
		return ObservedAttachment{}, &InvalidDataError{Message: "OCI volume attach response is invalid"}
	}
	return ObservedAttachment{ID: document.ID, InstanceID: document.InstanceID, VolumeID: document.VolumeID, LifecycleState: document.LifecycleState, Managed: true, CompartmentID: g.CompartmentID}, nil
}

func (g *OCIBlockStorageGateway) DetachAttachment(ctx context.Context, attachmentID string) error {
	if !isOCID(attachmentID, "volumeattachment") {
		return &errs.Argument{Message: "attachment detach request is invalid"}
	}
	return doOCIJSON[struct{}](ctx, g.Core, http.MethodDelete, "/20160918/volumeAttachments/"+url.PathEscape(attachmentID), nil, nil, nil)
}

func shortOCID(id string) string {
	if len(id) > 24 {
		return id[len(id)-24:]
	}
	return id
}

func volumeOwnershipTags(name string) map[string]string {
	region := strings.TrimPrefix(name, "terrascale-")
	region = strings.TrimSuffix(region, "-data")
	if i := strings.LastIndexByte(region, '-'); i >= 0 {
		region = region[:i]
	}
	return map[string]string{OCIManagedTag: "volume", OCIScopeTag: region}
}
