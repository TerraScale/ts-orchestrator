package placement

import (
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

const (
	// IntentSchemaVersion is the only schema accepted for new managed
	// placement admissions. Historical schemas are rejected.
	IntentSchemaVersion                   = 5
	managedUpdateMemberStateSchemaVersion = 5
	maxIntentPayloadBytes                 = 16 << 10
	managedMemoryPageBytes                = uint64(4096)
	managedMemoryGiB                      = uint64(1 << 30)
	maxManagedMemoryByteValue             = uint64(1<<63 - 1)
)

var (
	ErrInvalidIntent = errors.New("invalid TerraBase placement intent")
)

type Intent struct {
	SchemaVersion       int                  `json:"schema_version"`
	DatabaseID          string               `json:"database_id"`
	PartitionID         string               `json:"partition_id"`
	ActiveRegions       []oci.Region         `json:"active_regions"`
	Generation          uint64               `json:"generation"`
	CanonicalRoster     CanonicalRoster      `json:"canonical_roster,omitzero"`
	ManagedHostProfiles []ManagedHostProfile `json:"managed_host_profiles,omitempty"`
	RuntimeManifests    []RuntimeManifest    `json:"runtime_manifests,omitempty"`
	committedPayloadSHA string
}

// AuthorityReference identifies a TerraBase certificate and trust root. It is
// only a structural pin: this package does not possess the bytes or verifier
// needed to authenticate the referenced certificate or key.
type AuthorityReference struct {
	Version           uint32 `json:"version"`
	Epoch             uint64 `json:"epoch"`
	ConfigurationID   string `json:"configuration_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	TrustedKeySHA256  string `json:"trusted_key_sha256"`
}

// CanonicalRoster is the signed cluster scope and ordered set of TerraBase
// member identities. Rows use Go placement-seat order: region, permanent,
// elastic. Certificate consumers may have a different member-ID order.
type CanonicalRoster struct {
	ClusterID  string               `json:"cluster_id"`
	TenantID   string               `json:"tenant_id"`
	DatabaseID string               `json:"database_id"`
	ShardID    uint64               `json:"shard_id"`
	Authority  AuthorityReference   `json:"authority"`
	Rows       []CanonicalRosterRow `json:"members"`
}

// CanonicalRosterRow binds one Go placement seat to its TerraBase identity,
// incarnation, TLS certificate leaf and server name.
type CanonicalRosterRow struct {
	Region        oci.Region `json:"region"`
	SeatID        string     `json:"seat_id"`
	FailureDomain string     `json:"failure_domain"`
	MemberID      string     `json:"member_id"`
	Incarnation   string     `json:"incarnation"`
	TLSLeafSHA256 string     `json:"tls_leaf_sha256"`
	ServerName    string     `json:"server_name"`
}

// RuntimeManifest is an operator-signed, per-seat preprovisioned runtime
// contract. OCI attachment identity and device are observed later, never
// accepted from this operator payload.
type RuntimeManifest struct {
	Region                              oci.Region                 `json:"region"`
	SeatID                              string                     `json:"seat_id"`
	ArtifactDigest                      string                     `json:"artifact_digest"`
	SourceDigest                        string                     `json:"source_digest"`
	ManagedRuntimeRoot                  string                     `json:"managed_runtime_root"`
	FileSystemUUID                      string                     `json:"filesystem_uuid"`
	FileSystemType                      string                     `json:"filesystem_type"`
	TrustedKeySHA256                    string                     `json:"trusted_key_sha256"`
	ServerCertificateSHA256             string                     `json:"server_certificate_sha256"`
	ServerPrivateKeySHA256              string                     `json:"server_private_key_sha256"`
	ClientCARootsSHA256                 string                     `json:"client_ca_roots_sha256"`
	ClientManagedMaterialManifestSHA256 string                     `json:"client_managed_material_manifest_sha256,omitempty"`
	SQLSchemaBundleSHA256               string                     `json:"sql_schema_bundle_sha256,omitempty"`
	LiveS3ConfigSHA256                  string                     `json:"live_s3_config_sha256"`
	LiveS3TargetSHA256                  string                     `json:"live_s3_target_sha256"`
	LiveS3Credential                    oci.SecretVersionReference `json:"live_s3_credential"`
	BackupManifestSHA256                string                     `json:"backup_manifest_sha256,omitempty"`
	BackupS3ConfigSHA256                string                     `json:"backup_s3_config_sha256,omitempty"`
	BackupS3TargetSHA256                string                     `json:"backup_s3_target_sha256,omitempty"`
	BackupS3CredentialSHA256            string                     `json:"backup_s3_credential_sha256,omitempty"`
	BackupDataKeySHA256                 string                     `json:"backup_data_key_sha256,omitempty"`
	BackupOwner                         bool                       `json:"backup_owner,omitzero"`
	BackupS3Credential                  oci.SecretVersionReference `json:"backup_s3_credential,omitzero"`
	BackupDataKey                       oci.SecretVersionReference `json:"backup_data_key,omitzero"`
	ReplicationListenAddress            string                     `json:"replication_listen_address"`
	ReplicationPeerMemberID             string                     `json:"replication_peer_member_id,omitempty"`
	ReplicationPeerAddress              string                     `json:"replication_peer_address,omitempty"`
	ReplicationServerCASHA256           string                     `json:"replication_server_ca_sha256,omitempty"`
}

// ComputeTuple is the explicit Flex compute shape pinned by a signed profile.
// OCPUs and memory are whole provider units; fractional values are not accepted.
type ComputeTuple struct {
	Shape       string `json:"shape"`
	WholeOCPUs  uint32 `json:"whole_ocpus"`
	MemoryInGBs uint32 `json:"memory_in_gbs"`
}

// ManagedHostProfile pins one selected region's OCI compute tuple and guest
// memory contract. The byte values are supplied by the operator and are never
// inferred or defaulted by placement admission.
type ManagedHostProfile struct {
	Region                 oci.Region   `json:"region"`
	Compute                ComputeTuple `json:"compute"`
	ProcessMemoryBytes     uint64       `json:"process_memory_bytes"`
	MemoryHeadroomBytes    uint64       `json:"memory_headroom_bytes"`
	CgroupMemoryMaxBytes   uint64       `json:"cgroup_memory_max_bytes"`
	SystemReserveBytes     uint64       `json:"system_reserve_bytes"`
	AllocatableMemoryBytes uint64       `json:"allocatable_memory_bytes"`
}

type MemberKind string

const (
	MemberPermanent MemberKind = "permanent"
	MemberElastic   MemberKind = "elastic"
)

type Seat struct {
	MemberID      string
	Region        oci.Region
	FailureDomain string
	Kind          MemberKind
}

type MemberStage string

const (
	StagePreparedHost            MemberStage = "prepared-host"
	StageAwaitingHost            MemberStage = "awaiting-host"
	StagePreparedVolume          MemberStage = "prepared-volume"
	StagePreparedAttach          MemberStage = "prepared-attach"
	StageAwaitingAttach          MemberStage = "awaiting-attach"
	StagePreparedDesired         MemberStage = "prepared-desired"
	StageAwaitingRuntimeContract MemberStage = "awaiting-runtime-contract"
	StageAwaitingHealthy         MemberStage = "awaiting-healthy"
	StageServing                 MemberStage = "serving"
	StageRemoveCandidate         MemberStage = "remove-candidate"
	StageCordoned                MemberStage = "cordoned"
	StageDraining                MemberStage = "draining"
	StageDrained                 MemberStage = "drained"
	StageStorageHandled          MemberStage = "storage-handled"
	StageTerminated              MemberStage = "terminated"
	StageRemoved                 MemberStage = "removed"
)

// MemberState is the durable per-member lifecycle record. Store revisions are
// kept outside this value so its content remains stable across CAS retries.
type MemberState struct {
	SchemaVersion            int                  `json:"schema_version"`
	DatabaseID               string               `json:"database_id"`
	PartitionID              string               `json:"partition_id"`
	MemberID                 string               `json:"member_id"`
	Region                   oci.Region           `json:"region"`
	FailureDomain            string               `json:"failure_domain"`
	Kind                     MemberKind           `json:"kind"`
	Stage                    MemberStage          `json:"stage"`
	CreateKey                string               `json:"create_key"`
	HostNode                 string               `json:"host_node,omitempty"`
	InstanceID               string               `json:"instance_id,omitempty"`
	InstanceETag             string               `json:"instance_etag,omitempty"`
	VolumeID                 string               `json:"volume_id,omitempty"`
	AttachmentID             string               `json:"attachment_id,omitempty"`
	AttachmentDevice         string               `json:"attachment_device,omitempty"`
	AttachmentETag           string               `json:"attachment_etag,omitempty"`
	HostAttempt              uint64               `json:"host_attempt"`
	WriterEpoch              uint64               `json:"writer_epoch,omitzero"`
	IntentGeneration         uint64               `json:"intent_generation"`
	IntentPayloadDigest      string               `json:"intent_payload_digest,omitempty"`
	ManagedHostProfile       ManagedHostProfile   `json:"managed_host_profile,omitzero"`
	ManagedHostProfileDigest string               `json:"managed_host_profile_digest,omitempty"`
	CanonicalRosterRow       CanonicalRosterRow   `json:"canonical_roster_row,omitzero"`
	CanonicalRosterDigest    string               `json:"canonical_roster_digest,omitempty"`
	AuthorityReference       AuthorityReference   `json:"authority_reference,omitzero"`
	RuntimeManifest          RuntimeManifest      `json:"runtime_manifest,omitzero"`
	RuntimeManifestDigest    string               `json:"runtime_manifest_digest,omitempty"`
	ManagedRuntimeTarget     ManagedRuntimeTarget `json:"managed_runtime_target,omitzero"`
	DesiredGeneration        uint64               `json:"desired_generation"`
	HostGeneration           uint64               `json:"host_generation"`
	OperationID              string               `json:"operation_id"`
	UpdatedAt                time.Time            `json:"updated_at"`
	// HostLostAt is when the member's OCI host was first seen missing or
	// TERMINATED while it awaited its runtime contract. The lost-member
	// replacement grace runs from it, not from the last persisted write,
	// and it clears when the host is observed again.
	HostLostAt time.Time `json:"host_lost_at,omitzero"`
	// AttachRequestedAt is when the retained volume attach was first
	// requested for this host attempt. The attach deadline runs from it:
	// a production attach that stays ATTACHING is withheld from observation
	// and fails its settle wait, so the member never reaches the stage that
	// observes ATTACHING. It clears once the volume is attached.
	AttachRequestedAt time.Time `json:"attach_requested_at,omitzero"`
	// PreviousInstanceID is the lost instance a replacement host attempt
	// succeeded. Reattach on host loss moves the retained volume from it
	// only after OCI reports it TERMINATED. It is empty for a first attempt.
	PreviousInstanceID string `json:"previous_instance_id,omitempty"`
}

type ManagedUpdateSeatPhase string

const (
	ManagedUpdateSeatPrepared      ManagedUpdateSeatPhase = "prepared"
	ManagedUpdateSeatCanaryServing ManagedUpdateSeatPhase = "canary-serving"
	ManagedUpdateSeatHeld          ManagedUpdateSeatPhase = "held"
)

// ManagedRuntimeTarget is the durable canary target layered over the
// immutable placement RuntimeManifest. It never changes OCI boot or material
// pins and is only effective while a matching signed authority operation is
// retained. A later managed update of the same seat replaces it; the
// replaced target's artifact and source become the Previous pins.
// PreviousSourceDigest is empty when the predecessor is the placement's own
// runtime manifest.
type ManagedRuntimeTarget struct {
	OperationID               string                 `json:"operation_id"`
	AuthoritySequence         uint64                 `json:"authority_sequence"`
	RequestSHA256             string                 `json:"request_sha256"`
	PreparedAt                time.Time              `json:"prepared_at"`
	PlacementGeneration       uint64                 `json:"placement_generation"`
	PlacementPayloadDigest    string                 `json:"placement_payload_digest"`
	CanarySeatID              string                 `json:"canary_seat_id"`
	PreviousDesiredGeneration uint64                 `json:"previous_desired_generation"`
	PreviousArtifactDigest    string                 `json:"previous_artifact_digest"`
	PreviousSourceDigest      string                 `json:"previous_source_digest,omitempty"`
	DesiredGeneration         uint64                 `json:"desired_generation"`
	ArtifactDigest            string                 `json:"artifact_digest"`
	ManifestDigest            string                 `json:"manifest_digest"`
	SourceDigest              string                 `json:"source_digest"`
	Phase                     ManagedUpdateSeatPhase `json:"phase"`
	Outcome                   string                 `json:"outcome,omitempty"`
	// RollbackOfHeld marks a target that returned a held seat to its
	// predecessor. If it is held too, its own predecessor is the candidate
	// that already failed, so it is never a rollback destination.
	RollbackOfHeld bool `json:"rollback_of_held,omitzero"`
}
