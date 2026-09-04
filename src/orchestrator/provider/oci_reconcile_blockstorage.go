package provider

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// The block storage reconciler creates and repairs each member's data volume
// and its attachment (D-65): Balanced performance volumes, one per member
// slot, attached to that slot's instance. Volumes only ever grow — a declared
// size below the observed size is refused because shrinking destroys data.

// BalancedVPUsPerGiB is the OCI "Balanced" volume performance tier (D-65).
const BalancedVPUsPerGiB = 10

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
}

type ObservedAttachment struct {
	ID             string
	InstanceID     string
	VolumeID       string
	LifecycleState string
}

type BlockStorageObserved struct {
	Volumes     []ObservedVolume
	Attachments []ObservedAttachment
	Members     []ObservedMember
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

// BlockStorageReconciler converges one Region's data volumes and attachments.
type BlockStorageReconciler struct {
	Block   BlockStorageGateway
	Compute ComputeGateway
}

var _ OCIReconciler[estate.Region, BlockStorageObserved] = (*BlockStorageReconciler)(nil)

func volumeIsLive(state string) bool {
	return state != "TERMINATED" && state != "TERMINATING" && state != ""
}

func attachmentIsLive(state string) bool {
	return state != "DETACHED" && state != "DETACHING" && state != ""
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
	members := make(map[int]ObservedMember, len(observed.Members))
	for _, member := range observed.Members {
		if memberIsLive(member.LifecycleState) {
			members[member.Index] = member
		}
	}
	volumes := make(map[string]ObservedVolume, len(observed.Volumes))
	declaredVolumeNames := make(map[string]bool, int(pool.Count))
	for index := 1; index <= int(pool.Count); index++ {
		declaredVolumeNames[DataVolumeName(declared.Code, index)] = true
	}
	plan := OCIPlan{}
	for _, volume := range observed.Volumes {
		if volumeIsLive(volume.LifecycleState) && declaredVolumeNames[volume.DisplayName] {
			volumes[volume.DisplayName] = volume
		}
	}
	attachments := make(map[string]ObservedAttachment, len(observed.Attachments))
	for _, attachment := range observed.Attachments {
		if attachmentIsLive(attachment.LifecycleState) && declaredVolumeNames[volumeNameByID(observed, attachment.VolumeID)] {
			attachments[attachment.VolumeID] = attachment
		}
	}
	for index := 1; index <= int(pool.Count); index++ {
		name := DataVolumeName(declared.Code, index)
		member, memberExists := members[index]
		volume, volumeExists := volumes[name]
		if !volumeExists {
			if !memberExists {
				// The instance launches first; the next reconcile pass
				// creates this volume once it is observed.
				continue
			}
			plan.Actions = append(plan.Actions, CreateVolumeAction{Spec: VolumeSpec{
				DisplayName:        name,
				SizeGiB:            uint64(pool.DataVolumeGiB),
				VPUsPerGiB:         BalancedVPUsPerGiB,
				AvailabilityDomain: member.AvailabilityDomain,
			}})
			continue
		}
		if volume.SizeGiB < uint64(pool.DataVolumeGiB) {
			plan.Actions = append(plan.Actions, ExpandVolumeAction{VolumeID: volume.ID, NewSizeGiB: uint64(pool.DataVolumeGiB)})
		} else if volume.SizeGiB > uint64(pool.DataVolumeGiB) {
			return OCIPlan{}, &InvalidDataError{Message: "declared data volume size is below the observed volume; volumes never shrink"}
		}
		if volume.VPUsPerGiB != BalancedVPUsPerGiB {
			return OCIPlan{}, &InvalidDataError{Message: "observed volume " + name + " is not on the Balanced performance tier"}
		}
		if attachment, attached := attachments[volume.ID]; attached {
			if attachment.InstanceID == member.ID {
				continue
			}
			plan.Actions = append(plan.Actions, DetachAttachmentAction{AttachmentID: attachment.ID})
		}
		if memberExists {
			plan.Actions = append(plan.Actions, AttachVolumeAction{InstanceID: member.ID, VolumeID: volume.ID})
		}
	}
	for _, attachment := range observed.Attachments {
		if attachmentIsLive(attachment.LifecycleState) && !declaredVolumeNames[volumeNameByID(observed, attachment.VolumeID)] {
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
				return err
			}
		case ExpandVolumeAction:
			if err := r.Block.ExpandVolume(ctx, a.VolumeID, a.NewSizeGiB); err != nil {
				return err
			}
		case AttachVolumeAction:
			if _, err := r.Block.AttachVolume(ctx, a.InstanceID, a.VolumeID, ""); err != nil {
				return err
			}
		case DetachAttachmentAction:
			if err := r.Block.DetachAttachment(ctx, a.AttachmentID); err != nil {
				return err
			}
		default:
			return &InvalidOperationError{Message: "block storage reconciler received a foreign action"}
		}
	}
	return nil
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
	ID                 string `json:"id"`
	DisplayName        string `json:"displayName"`
	SizeInGBs          uint64 `json:"sizeInGBs"`
	VPUsPerGB          uint64 `json:"vpusPerGB"`
	LifecycleState     string `json:"lifecycleState"`
	AvailabilityDomain string `json:"availabilityDomain"`
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
		volumes = append(volumes, ObservedVolume{ID: item.ID, DisplayName: item.DisplayName, SizeGiB: item.SizeInGBs, VPUsPerGiB: item.VPUsPerGB, LifecycleState: item.LifecycleState, AvailabilityDomain: item.AvailabilityDomain})
	}
	return volumes, nil
}

func (g *OCIBlockStorageGateway) CreateVolume(ctx context.Context, spec VolumeSpec) (ObservedVolume, error) {
	if !validEstateName(spec.DisplayName) || spec.SizeGiB == 0 || spec.SizeGiB > 16<<20 ||
		spec.VPUsPerGiB == 0 || spec.VPUsPerGiB > 120 || len(spec.AvailabilityDomain) == 0 || len(spec.AvailabilityDomain) > 128 {
		return ObservedVolume{}, &errs.Argument{Message: "volume create request is invalid"}
	}
	var document ociVolumeDocument
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/volumes", struct {
		CompartmentID      string `json:"compartmentId"`
		AvailabilityDomain string `json:"availabilityDomain"`
		DisplayName        string `json:"displayName"`
		SizeInGBs          uint64 `json:"sizeInGBs"`
		VPUsPerGB          uint64 `json:"vpusPerGB"`
	}{CompartmentID: g.CompartmentID, AvailabilityDomain: spec.AvailabilityDomain, DisplayName: spec.DisplayName, SizeInGBs: spec.SizeGiB, VPUsPerGB: spec.VPUsPerGiB}, nil, &document); err != nil {
		return ObservedVolume{}, err
	}
	if !isOCID(document.ID, "volume") {
		return ObservedVolume{}, &InvalidDataError{Message: "OCI volume create response is invalid"}
	}
	return ObservedVolume{ID: document.ID, DisplayName: document.DisplayName, SizeGiB: document.SizeInGBs, VPUsPerGiB: document.VPUsPerGB, LifecycleState: document.LifecycleState, AvailabilityDomain: document.AvailabilityDomain}, nil
}

func (g *OCIBlockStorageGateway) ExpandVolume(ctx context.Context, volumeID string, sizeGiB uint64) error {
	if !isOCID(volumeID, "volume") || sizeGiB == 0 || sizeGiB > 16<<20 {
		return &errs.Argument{Message: "volume expand request is invalid"}
	}
	return doOCIJSON[struct{}](ctx, g.Core, http.MethodPut, "/20160918/volumes/"+url.PathEscape(volumeID), struct {
		SizeInGBs uint64 `json:"sizeInGBs"`
	}{SizeInGBs: sizeGiB}, nil, nil)
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
		attachments = append(attachments, ObservedAttachment{ID: item.ID, InstanceID: item.InstanceID, VolumeID: item.VolumeID, LifecycleState: item.LifecycleState})
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
	}{CompartmentID: g.CompartmentID, InstanceID: instanceID, VolumeID: volumeID, AttachmentTyp: "iscsi", DisplayName: displayName}, nil, &document); err != nil {
		return ObservedAttachment{}, err
	}
	if !isOCID(document.ID, "volumeattachment") {
		return ObservedAttachment{}, &InvalidDataError{Message: "OCI volume attach response is invalid"}
	}
	return ObservedAttachment{ID: document.ID, InstanceID: document.InstanceID, VolumeID: document.VolumeID, LifecycleState: document.LifecycleState}, nil
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
