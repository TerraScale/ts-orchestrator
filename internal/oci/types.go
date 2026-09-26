package oci

import (
	"context"
	"errors"
	"time"
)

var (
	ErrForeignResource               = errors.New("OCI resource ownership does not match this fleet")
	ErrDuplicateCreateKey            = errors.New("OCI create key resolves to multiple resources")
	ErrStaleETag                     = errors.New("OCI resource ETag changed")
	ErrWriterStopUnverified          = errors.New("database writer stop is not verified")
	ErrRetainedVolumeInUse           = errors.New("retained volume is attached to a different instance")
	ErrRetainedVolumeUnknown         = errors.New("retained volume has no durable controller ownership record")
	ErrAttachmentRecoveryHold        = errors.New("retained volume attachment requires operator reconciliation")
	ErrImageQualificationUnavailable = errors.New("retained volumes require verified image qualification")
	ErrImageNotQualified             = errors.New("pinned OCI image is not qualified for retained volumes")
	ErrOutcomeUnknown                = errors.New("OCI provider mutation outcome is unknown")
	ErrCreateRecoveryHold            = errors.New("OCI create requires operator reconciliation")
	ErrPlacementProfileMismatch      = errors.New("OCI host does not match its signed placement compute profile")
	ErrHostBootBindingMismatch       = errors.New("OCI host does not match its durable public boot descriptor")
)

// CreateRecoveryHoldError stops automatic retries when the original OCI
// idempotency window has expired or a previously confirmed resource vanished.
// Recovery needs a separately approved, exact-resource operator workflow.
type CreateRecoveryHoldError struct {
	Resource  string
	CreateKey string
	Reason    string
}

func (err *CreateRecoveryHoldError) Error() string {
	return err.Resource + " create " + err.CreateKey + " is held: " + err.Reason + "; operator reconciliation is required"
}

func (err *CreateRecoveryHoldError) Unwrap() error { return ErrCreateRecoveryHold }

// Instance is one positively owned host in this Fleet's configured region.
// DataVolumes contains retained data volumes currently attached to the host;
// terminating an instance always asks OCI to preserve all volumes.
type Instance struct {
	ID                     string
	Node                   string
	CreateKey              string
	Region                 Region
	Generation             uint64
	Owner                  string
	FaultDomain            string
	Shape                  string
	WholeOCPUs             uint32
	MemoryInGBs            uint32
	PlacementProfileDigest string
	PlacementGeneration    uint64
	ImageID                string
	BootDescriptorSHA256   string
	ETag                   string
	State                  string
	DataVolumes            []string
	Attachments            []Attachment
}

// Attachment identifies a retained data-volume attachment. VolumeID remains
// owned by its durable controller record after detachment and instance scale-in.
type Attachment struct {
	ID                             string
	VolumeID                       string
	InstanceID                     string
	ETag                           string
	State                          string
	Device                         string
	IsReadOnly                     bool
	IsShareable                    bool
	IsPvEncryptionInTransitEnabled bool
}

// EnsureRequest identifies the idempotent host launch and carries the complete
// signed regional placement compute profile. Image, network, compartment, and
// OCI region generation remain pinned by the region-bound Fleet configuration.
type EnsureRequest struct {
	CreateKey              string
	FaultDomain            string
	Shape                  string
	WholeOCPUs             uint32
	MemoryInGBs            uint32
	PlacementProfileDigest string
	PlacementGeneration    uint64
	BootPins               HostBootPins
}

// HostBootPins are the placement-owned commitments for one managed host
// attempt. Fleet adds its region, node, owner, image, and generation before
// persisting the public, non-authorizing OCI boot descriptor.
type HostBootPins struct {
	DatabaseID            string
	PartitionID           string
	SeatID                string
	HostAttempt           uint64
	IntentPayloadDigest   string
	CanonicalRosterDigest string
	RuntimeManifestDigest string
}

// VolumeAttachRequest attaches an already-owned retained data volume. The
// idempotency key must remain stable across retries of the same desired state.
type VolumeAttachRequest struct {
	VolumeID       string
	InstanceID     string
	IdempotencyKey string
}

// VolumeCreateRequest defines one retained member data volume in the region
// pinned by a Fleet. AvailabilityDomain may be empty to use the configured AD.
type VolumeCreateRequest struct {
	CreateKey          string
	SizeGB             int64
	AvailabilityDomain string
}

// RetainedVolume is a positively reobserved and durably owned data volume.
type RetainedVolume struct {
	ID                 string
	CreateKey          string
	Region             Region
	Generation         uint64
	Owner              string
	AvailabilityDomain string
	SizeGB             int64
	State              string
}

// WriterStopEvidence is verified against the target instance and volume by an
// injected WriterStopVerifier. OCI never treats host-process shutdown alone as
// proof that a stateful database has relinquished its writer lease.
type WriterStopEvidence []byte

// Fleet is a region-pinned OCI host pool consumed by placement reconciliation.
// Implementations must fail closed for unknown desired state or ownership.
type Fleet interface {
	Region() Region
	Observe(context.Context) ([]Instance, error)
	EnsureHost(context.Context, EnsureRequest) (Instance, error)
	CreateRetainedVolume(context.Context, VolumeCreateRequest) (RetainedVolume, error)
	Cordon(context.Context, string, string) error
	RequestDrain(context.Context, string, string) error
	AttachRetainedVolume(context.Context, VolumeAttachRequest) (Attachment, error)
	Detach(context.Context, string, string, string, WriterStopEvidence) error
	Terminate(context.Context, string, string, WriterStopEvidence) error
}

// DrainRequest carries the exact observed instance and the current authority
// epoch to the durable host-command writer. The writer is responsible for
// persisting desired drain state before acknowledging this call.
type DrainRequest struct {
	Region         Region
	InstanceID     string
	Node           string
	CreateKey      string
	IdempotencyKey string
	ExpectedETag   string
	Epoch          uint64
}

// DrainRequester persists and publishes a host drain command through the
// regional control plane. An OCI Fleet without one refuses drain requests.
type DrainRequester interface {
	RequestDrain(context.Context, DrainRequest) error
}

// WriterStopVerifier validates proof that the database has stopped writing to
// the specific retained volume on the specific host.
type WriterStopVerifier interface {
	VerifyVolumeWriterStopped(context.Context, Region, string, string, WriterStopEvidence) error
	VerifyInstanceWritersStopped(context.Context, Region, string, WriterStopEvidence) error
}

// ImageQualificationVerifier proves that the pinned image is approved for
// retained-volume attachment. A raw image ID or digest is not qualification
// evidence; deployments without an evidence source must hold these operations.
type ImageQualificationVerifier interface {
	VerifyImageQualified(context.Context, Region, string) error
}

// ResourceIdentity is the complete durable scope needed to positively identify
// a resource. Tags alone are never sufficient to adopt a seed or OpenTofu item.
type ResourceIdentity struct {
	ID                 string
	Region             Region
	Generation         uint64
	Owner              string
	CreateKey          string
	AvailabilityDomain string
	SizeGB             int64
}

// OperationIntent is durably written before an OCI mutation is attempted.
type OperationIntent struct {
	Action                         string    `json:"action"`
	Key                            string    `json:"key"`
	Region                         Region    `json:"region"`
	Generation                     uint64    `json:"generation"`
	Owner                          string    `json:"owner"`
	ResourceID                     string    `json:"resource_id,omitempty"`
	CreateKey                      string    `json:"create_key,omitempty"`
	ExpectedETag                   string    `json:"expected_etag,omitempty"`
	FaultDomain                    string    `json:"fault_domain,omitempty"`
	Shape                          string    `json:"shape,omitempty"`
	WholeOCPUs                     uint32    `json:"whole_ocpus,omitzero"`
	MemoryInGBs                    uint32    `json:"memory_in_gbs,omitzero"`
	PlacementProfileDigest         string    `json:"placement_profile_digest,omitempty"`
	PlacementGeneration            uint64    `json:"placement_generation,omitzero"`
	ImageID                        string    `json:"image_id,omitempty"`
	BootDescriptor                 string    `json:"boot_descriptor,omitempty"`
	BootDescriptorSHA256           string    `json:"boot_descriptor_sha256,omitempty"`
	VolumeID                       string    `json:"volume_id,omitempty"`
	AvailabilityDomain             string    `json:"availability_domain,omitempty"`
	SizeGB                         int64     `json:"size_gb,omitempty"`
	Device                         string    `json:"device,omitempty"`
	IsReadOnly                     bool      `json:"is_read_only"`
	IsShareable                    bool      `json:"is_shareable"`
	IsPvEncryptionInTransitEnabled bool      `json:"is_pv_encryption_in_transit_enabled"`
	CreatedAt                      time.Time `json:"created_at,omitzero"`
}

// OperationResult records the observed result of a provider mutation. A result
// with Unknown=true keeps the original intent visible for later reconciliation.
type OperationResult struct {
	Intent     OperationIntent `json:"intent"`
	ResourceID string          `json:"resource_id,omitempty"`
	ETag       string          `json:"etag,omitempty"`
	Unknown    bool            `json:"unknown,omitzero"`
	RecordedAt time.Time       `json:"recorded_at,omitzero"`
}

// OperationScope identifies the immutable portion of an operation key that is
// known before all mutation details (such as the selected device) are known.
type OperationScope struct {
	Action     string
	Key        string
	Region     Region
	Generation uint64
	Owner      string
}

// AttachmentIdentity binds an observed attachment to the confirmed operation
// result that created it, including the instance, retained volume, path, ETag,
// and fixed attach policy.
type AttachmentIdentity struct {
	ID                             string
	InstanceID                     string
	VolumeID                       string
	Device                         string
	ETag                           string
	Region                         Region
	Generation                     uint64
	Owner                          string
	CreateKey                      string
	IsReadOnly                     bool
	IsShareable                    bool
	IsPvEncryptionInTransitEnabled bool
}

// Journal is backed by replicated JetStream KV in production. IsOwnedInstance
// and IsOwnedVolume must return true only for resources whose controller
// ownership is backed by a durable operation or a separately verified handoff.
type Journal interface {
	RecordIntent(context.Context, OperationIntent) error
	RecordResult(context.Context, OperationResult) error
	// GetResult always returns the immutable stored intent in result.Intent,
	// including its original CreatedAt, even when found is false.
	GetResult(context.Context, OperationIntent) (OperationResult, bool, error)
	// GetOperation resolves the exact operation key from its known regional
	// scope and returns the original immutable intent, even before a result is
	// recorded. Callers must not invent omitted mutation details on a retry.
	GetOperation(context.Context, OperationScope) (OperationIntent, bool, error)
	IsOwnedAttachment(context.Context, AttachmentIdentity) (bool, error)
	IsOwnedInstance(context.Context, ResourceIdentity) (bool, error)
	IsOwnedVolume(context.Context, ResourceIdentity) (bool, error)
}

// Provider is the narrow OCI Compute/Block Volume SDK seam. Fakes can exercise
// retry, loss-of-response, and ownership behavior without OCI credentials.
type Provider interface {
	ListInstances(context.Context, string) ([]CloudInstance, error)
	GetInstance(context.Context, string) (CloudInstance, error)
	LaunchInstance(context.Context, LaunchRequest) (CloudInstance, error)
	UpdateInstanceTags(context.Context, string, string, map[string]string) (CloudInstance, error)
	TerminateInstance(context.Context, string, string) error
	ListVolumeAttachments(context.Context, string, string) ([]CloudAttachment, error)
	ListInstanceDevices(context.Context, string) ([]CloudDevice, error)
	GetVolumeAttachment(context.Context, string) (CloudAttachment, error)
	AttachVolume(context.Context, CloudVolumeAttachRequest) (CloudAttachment, error)
	DetachVolume(context.Context, string, string) error
	ListVolumes(context.Context, string, string) ([]CloudVolume, error)
	CreateVolume(context.Context, VolumeCreateRequest, map[string]string, string) (CloudVolume, error)
	GetVolume(context.Context, string) (CloudVolume, error)
}

// CloudInstance and CloudAttachment are normalized SDK values used at the
// narrow provider boundary.
type CloudInstance struct {
	ID                            string
	CompartmentID                 string
	AvailabilityDomain            string
	FaultDomain                   string
	Shape                         string
	Ocpus                         *float32
	MemoryInGBs                   *float32
	LifecycleState                string
	ETag                          string
	ImageID                       string
	ConsistentVolumeNamingEnabled *bool
	Metadata                      map[string]string
	FreeformTags                  map[string]string
}

type CloudAttachment struct {
	ID                             string
	VolumeID                       string
	InstanceID                     string
	LifecycleState                 string
	ETag                           string
	Device                         string
	IsReadOnly                     *bool
	IsShareable                    *bool
	IsPvEncryptionInTransitEnabled *bool
}

// CloudDevice is a provider candidate only. Fleet validates and deterministically
// selects a device, then persists it before making an attachment request.
type CloudDevice struct {
	Name        string
	IsAvailable *bool
}

// CloudVolumeAttachRequest is the provider-bound mutation assembled by Fleet
// from its durable intent. Placement callers cannot select the device or flags.
type CloudVolumeAttachRequest struct {
	VolumeID                       string
	InstanceID                     string
	IdempotencyKey                 string
	Device                         string
	IsReadOnly                     bool
	IsShareable                    bool
	IsPvEncryptionInTransitEnabled bool
}

type CloudVolume struct {
	ID                 string
	CompartmentID      string
	AvailabilityDomain string
	SizeGB             int64
	LifecycleState     string
	FreeformTags       map[string]string
}

// LaunchRequest carries the immutable signed placement compute profile to the
// provider. It cannot specify a different endpoint or compartment than the
// Fleet's RegionConfig.
type LaunchRequest struct {
	CreateKey              string
	Node                   string
	RetryToken             string
	FaultDomain            string
	Shape                  string
	WholeOCPUs             uint32
	MemoryInGBs            uint32
	PlacementProfileDigest string
	PlacementGeneration    uint64
	ImageID                string
	BootDescriptor         string
	FreeformTags           map[string]string
}
