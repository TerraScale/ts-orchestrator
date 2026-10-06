package host

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	stateBucket        = "TS_HOST_STATE"
	sessionTTL         = 30 * time.Second
	requestTTL         = 10 * time.Second
	maxClockSkew       = 2 * time.Second
	maxArtifactBytes   = 512 << 20
	artifactChunkBytes = 256 << 10
)

// ReportMaxAge is how old a host's latest report may be and still count as
// current. Hosts report once per reconcile, which takes up to about half a
// minute on a single-OCPU host; liveness is still bounded by the host session,
// and every managed proof is bound to the exact reported process.
const ReportMaxAge = 90 * time.Second

var tokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var managedFaultDomainPattern = regexp.MustCompile(`^FAULT-DOMAIN-[1-3]$`)
var filesystemUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var ErrDesiredConflict = errors.New("desired generation or target conflicts with committed state")

// Registration is the controller's durable allowlist for one host identity.
// PublicKey is a base64 encoded Ed25519 key; a higher Generation rotates it.
type Registration struct {
	Cell               string                   `json:"cell"`
	Node               string                   `json:"node"`
	FailureDomain      string                   `json:"failure_domain"`
	Environment        string                   `json:"environment"`
	Roles              []string                 `json:"roles"`
	PublicKey          string                   `json:"public_key"`
	NATSUserPublicKey  string                   `json:"nats_user_public_key"`
	Generation         uint64                   `json:"generation"`
	Capacity           Capacity                 `json:"capacity"`
	ManagedPlacement   *ManagedPlacementBinding `json:"managed_placement,omitempty"`
	ManagedOCI         *ManagedOCIBinding       `json:"managed_oci,omitempty"`
	ManagedMember      *ManagedMemberBinding    `json:"managed_member,omitempty"`
	SystemReserveBytes int64                    `json:"system_reserve_bytes,omitzero"`
	// TerraBaseDataVolumeID is the operator-assigned C# member volume. A
	// replacement host keeps it; a new member with a reused name gets a new ID.
	TerraBaseDataVolumeID string `json:"terrabase_data_volume_id,omitempty"`
}

// ManagedPlacementBinding fixes a managed host registration to one business
// placement seat and the current schema-3 placement pins.
type ManagedPlacementBinding struct {
	DatabaseID               string `json:"database_id"`
	PartitionID              string `json:"partition_id"`
	SeatID                   string `json:"seat_id"`
	IntentGeneration         uint64 `json:"intent_generation"`
	IntentPayloadDigest      string `json:"intent_payload_digest"`
	CanonicalRosterDigest    string `json:"canonical_roster_digest"`
	ManagedHostProfileDigest string `json:"managed_host_profile_digest"`
}

// ManagedMemberBinding fixes one logical member and host attempt to this host.
// It is assigned with the first registration and cannot be retargeted.
type ManagedMemberBinding struct {
	Scope       MemberScope `json:"scope"`
	HostAttempt uint64      `json:"host_attempt"`
}

// ManagedOCIBinding is an operator-assigned OCI identity for a host key. It is
// not hardware attestation; callers must verify ownership and live OCI state.
type ManagedOCIBinding struct {
	Region          string `json:"region"`
	InstanceID      string `json:"instance_id"`
	Owner           string `json:"owner"`
	FleetGeneration uint64 `json:"fleet_generation"`
	CreateKey       string `json:"create_key"`
}

type Capacity struct {
	CPU         int   `json:"cpu"`
	MemoryBytes int64 `json:"memory_bytes"`
	DiskBytes   int64 `json:"disk_bytes"`
}

// Desired is a single host allocation. A generation can be written only once;
// a later generation may replace or withdraw it.
type Desired struct {
	Cell           string               `json:"cell"`
	Node           string               `json:"node"`
	Environment    string               `json:"environment"`
	Role           string               `json:"role"`
	Digest         string               `json:"digest"`
	Generation     uint64               `json:"generation"`
	AuthorityEpoch uint64               `json:"authority_epoch"`
	Args           []string             `json:"args,omitempty"`
	Env            map[string]string    `json:"env,omitempty"`
	Withdrawn      bool                 `json:"withdrawn"`
	ManagedMember  *ManagedMemberLaunch `json:"managed_member,omitempty"`

	// Secrets name the Vault secrets the host adds to Env at each start.
	Secrets map[string]vaultsecret.Ref `json:"secrets,omitempty"`
}

// ManagedMemberLaunch is inert until the agent can verify the assignment,
// mounted attachment and private authority material against the real process.
type ManagedMemberLaunch struct {
	OCI                  ManagedOCIBinding    `json:"oci"`
	Member               ManagedMemberBinding `json:"member"`
	Authority            MemberAuthority      `json:"authority"`
	SourceDigest         string               `json:"source_digest"`
	VolumeID             string               `json:"volume_id"`
	AttachmentID         string               `json:"attachment_id"`
	AttachmentETag       string               `json:"attachment_etag,omitempty"`
	ProcessMemoryBytes   uint64               `json:"process_memory_bytes,omitzero"`
	MemoryHeadroomBytes  uint64               `json:"memory_headroom_bytes,omitzero"`
	CgroupMemoryMaxBytes uint64               `json:"cgroup_memory_max_bytes,omitzero"`
	SystemReserveBytes   uint64               `json:"system_reserve_bytes,omitzero"`
	Runtime              *ManagedRuntimePins  `json:"runtime,omitempty"`
}

// ManagedRuntimePins names the exact preprovisioned, preformatted runtime that
// may be attached to this signed member desired. Missing pins keep it held.
// The corresponding files are installed outside NATS by a trusted operator.
type ManagedRuntimePins struct {
	DevicePath                          string                     `json:"device_path"`
	MountPath                           string                     `json:"mount_path"`
	FileSystemUUID                      string                     `json:"filesystem_uuid"`
	FileSystemType                      string                     `json:"filesystem_type"`
	TrustedKeySHA256                    string                     `json:"trusted_key_sha256"`
	ServerCertificateSHA256             string                     `json:"server_certificate_sha256"`
	ServerPrivateKeySHA256              string                     `json:"server_private_key_sha256"`
	ClientCARootsSHA256                 string                     `json:"client_ca_roots_sha256"`
	ClientManagedMaterialManifestSHA256 string                     `json:"client_managed_material_manifest_sha256"`
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

type Receipt struct {
	Generation uint64 `json:"generation"`
	Revision   uint64 `json:"revision"`
}

type Report struct {
	Cell        string                `json:"cell"`
	Node        string                `json:"node"`
	Environment string                `json:"environment"`
	Role        string                `json:"role"`
	Digest      string                `json:"digest"`
	Generation  uint64                `json:"generation"`
	SessionID   string                `json:"session_id"`
	Epoch       uint64                `json:"epoch"`
	State       string                `json:"state"`
	Error       string                `json:"error,omitempty"`
	ObservedAt  time.Time             `json:"observed_at"`
	Managed     *ManagedRuntimeReport `json:"managed,omitempty"`
}

// ManagedRuntimeReport binds a native process and mounted volume to its
// TerraBase serving proof when the process currently offers one.
type ManagedRuntimeReport struct {
	ClientCredentialGeneration uint64                     `json:"client_credential_generation,omitzero"`
	Member                     ManagedMemberBinding       `json:"member"`
	Authority                  MemberAuthority            `json:"authority"`
	OCI                        ManagedOCIBinding          `json:"oci"`
	VolumeID                   string                     `json:"volume_id"`
	AttachmentID               string                     `json:"attachment_id"`
	AttachmentETag             string                     `json:"attachment_etag"`
	FileSystemUUID             string                     `json:"filesystem_uuid"`
	FileSystemType             string                     `json:"filesystem_type"`
	MountDevice                string                     `json:"mount_device"`
	MountPath                  string                     `json:"mount_path"`
	MountID                    uint64                     `json:"mount_id"`
	ProcessPID                 int                        `json:"process_pid"`
	ProcessStart               string                     `json:"process_start"`
	ProcessCgroup              string                     `json:"process_cgroup"`
	ProcessBootID              string                     `json:"process_boot_id"`
	StorageRecovered           bool                       `json:"storage_recovered"`
	ListenerReady              bool                       `json:"listener_ready"`
	ServingProof               *memberstatus.ServingProof `json:"serving_proof,omitempty"`
}

type HostStatus struct {
	Registration     Registration `json:"registration"`
	SessionExpiresAt time.Time    `json:"session_expires_at,omitzero"`
	Reports          []Report     `json:"reports,omitempty"`
	Verified         bool         `json:"verified"`
}

type AgentConfig struct {
	Cell                    string
	Node                    string
	Environment             string
	Roles                   []string
	Conn                    *nats.Conn
	Identity                ed25519.PrivateKey
	NATSUserPublicKey       string
	ControllerPublicKey     ed25519.PublicKey
	Runner                  Runner
	InstallRoot             string
	StateRoot               string
	ManagedRuntimeRoot      string
	TerraBaseRoot           string // Set: launch a non-managed "terrabase" desired as a C# TerraBase member.
	TSAuthRoot              string // Set: launch a "ts-auth" desired with its readiness probe and bundle directory.
	TSAuthPort              int    // The port a ts-auth replica serves and the host probes; zero means tsauth.Port.
	ManagedS3Credentials    ManagedS3CredentialResolver
	ManagedBackupDataKeys   ManagedBackupDataKeyResolver
	BakedSystemReserveBytes uint64
	WorkloadIdentity        WorkloadIdentity
	PollInterval            time.Duration
	SessionTrace            bool
	ClockCheck              func() error
	VolumeInitSocket        string

	// TerraBaseDataVolume requires the member data directory to be the
	// mounted OCI data volume; without that mount the member never starts.
	TerraBaseDataVolume   bool
	TerraBaseDataVolumeID string
	// Initialized, when set, is called once Run has recovered the native
	// runner and passed its clock check, before it waits for a controller
	// session. A self-update activation proof belongs here: earlier, a host
	// whose recovery fails would still confirm its release.
	Initialized func()
	// LoadInterval, when nonzero, publishes host load telemetry that often
	// (5s..1h). Zero, the default, never samples or sends load.
	LoadInterval time.Duration
	// SecretResolver reads a desired's Vault secrets at each start; nil
	// refuses a desired with secrets.
	SecretResolver func(context.Context, map[string]vaultsecret.Ref) (map[string]string, error)
}

type ControllerConfig struct {
	Cell           string
	Conn           *nats.Conn
	JS             jetstream.JetStream
	State          jetstream.KeyValue
	Artifacts      ArtifactStore
	ResponseKey    ed25519.PrivateKey
	StateReplicas  int
	AuthorityEpoch func() uint64
	AuthorityGuard func(context.Context, uint64) error
	// AuthorityLeader reports whether this controller holds the cell authority;
	// only the leader serves host requests. Nil serves always (one controller).
	AuthorityLeader             func() bool
	HostMutations               authority.HostMutationStore
	ManagedRegistrationVerifier ManagedRegistrationVerifier
	ManagedDesiredVerifier      ManagedDesiredVerifier
	ManagedEffectGate           func(context.Context, uint64, authority.WorkloadScope) (func(), error)
	ManagedMaterialProvider     ManagedMaterialProvider
	ManagedCredentialFloor      func(context.Context, Registration) (uint64, error)
	ManagedVolumeInspector      ManagedVolumeInspector
	ControlLog                  jetstream.Stream
	// TerraBaseCA signs C# TerraBase member certificates; nil refuses them.
	TerraBaseCA *terrabase.CA
	// RestartGate, when set, is asked before a host opens a new cycle to
	// apply desired. A cycle it does not grant is held: the host keeps its
	// running workload and reports it waiting at the new generation, and
	// asks again on its next poll. Nil grants every cycle. Withdrawals and
	// managed members, which stop their workload before they ask, are never
	// held, and a host revalidating a cycle it already holds is not asked
	// again.
	RestartGate func(ctx context.Context, node string, desired Desired) (bool, error)
}

// ManagedVolumeInspector independently reobserves the exact owned OCI host,
// retained volume and attachment before a host may prepare its local device.
type ManagedVolumeInspector func(context.Context, Desired, Registration) (VolumeInitObservation, error)

type VolumeInitObservation struct {
	BootDescriptorSHA256 string `json:"boot_descriptor_sha256"`
	AllowFormat          bool   `json:"allow_format"`
}

// ManagedMaterialProvider returns only a currently admitted member's exact
// R3-pinned host files. The host RPC encrypts each requested chunk separately.
type ManagedMaterialProvider func(context.Context, Desired, Registration) (map[string][]byte, error)

// ManagedRegistrationVerifier checks a managed registration against current
// admitted placement, durable member state, and OCI observation.
type ManagedRegistrationVerifier interface {
	VerifyManagedRegistration(context.Context, Registration) error
}

// ManagedDesiredVerifier admits only a managed desired whose initial launch or
// signed canary update is current in durable placement and authority state.
type ManagedDesiredVerifier func(context.Context, Desired, Registration, Desired, bool) error

type ReaderConfig struct {
	Cell          string
	Conn          *nats.Conn
	JS            jetstream.JetStream
	State         jetstream.KeyValue
	StateReplicas int
	HostMutations authority.HostMutationStore
	ControlLog    jetstream.Stream
}

// ArtifactStore is the read-only object-store capability held by controllers.
type ArtifactStore interface {
	Get(context.Context, string, ...jetstream.GetObjectOpt) (jetstream.ObjectResult, error)
	GetInfo(context.Context, string, ...jetstream.GetObjectInfoOpt) (*jetstream.ObjectInfo, error)
}

func validateToken(value, name string) error {
	if !tokenPattern.MatchString(value) {
		return fmt.Errorf("invalid %s %q", name, value)
	}
	return nil
}

func validateDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return errors.New("digest must be lowercase SHA-256 hex")
	}
	return nil
}

func validateRegistration(r Registration, cell string) error {
	if r.Cell != cell {
		return errors.New("registration belongs to another cell")
	}
	for name, value := range map[string]string{"cell": r.Cell, "node": r.Node, "environment": r.Environment} {
		if err := validateToken(value, name); err != nil {
			return err
		}
	}
	if r.ManagedOCI != nil {
		if err := validateManagedOCIBinding(*r.ManagedOCI, r.FailureDomain); err != nil {
			return err
		}
		if r.ManagedMember == nil || r.SystemReserveBytes <= 0 || r.Capacity.MemoryBytes <= 0 ||
			r.Capacity.MemoryBytes > math.MaxInt64-r.SystemReserveBytes ||
			len(r.Roles) != 1 || r.Roles[0] != "terrabase" {
			return errors.New("managed host requires one terrabase role, member binding and signed memory reserve")
		}
		// Stored pre-schema-3 registrations remain readable for inspection;
		// Controller.Register separately requires these pins for admission.
		if r.ManagedPlacement != nil {
			if err := validateManagedPlacementBinding(*r.ManagedPlacement); err != nil {
				return err
			}
		}
		if err := validateManagedMemberBinding(*r.ManagedMember); err != nil {
			return err
		}
	} else if r.FailureDomain != "" {
		if err := validateToken(r.FailureDomain, "failure domain"); err != nil {
			return err
		}
	}
	if r.ManagedOCI == nil && (r.ManagedPlacement != nil || r.ManagedMember != nil || r.SystemReserveBytes != 0) {
		return errors.New("generic host cannot carry managed placement, member or memory reserve")
	}
	if r.TerraBaseDataVolumeID != "" && (r.ManagedOCI != nil || !slices.Contains(r.Roles, "terrabase") ||
		!strings.HasPrefix(r.TerraBaseDataVolumeID, "ocid1.volume.") || strings.ContainsAny(r.TerraBaseDataVolumeID, " \t\r\n/\\")) {
		return errors.New("C# terrabase data volume binding needs a volume OCID and terrabase role")
	}
	if r.Generation == 0 || len(r.Roles) == 0 || len(r.Roles) > 32 {
		return errors.New("invalid registration generation or roles")
	}
	seen := make(map[string]bool, len(r.Roles))
	for _, role := range r.Roles {
		if err := validateToken(role, "role"); err != nil {
			return err
		}
		if seen[role] {
			return errors.New("duplicate role")
		}
		seen[role] = true
	}
	if _, err := decodePublicKey(r.PublicKey); err != nil {
		return err
	}
	if !nkeys.IsValidPublicUserKey(r.NATSUserPublicKey) {
		return errors.New("registration NATS user public key is invalid")
	}
	if r.Capacity.CPU < 0 || r.Capacity.MemoryBytes < 0 || r.Capacity.DiskBytes < 0 {
		return errors.New("negative host capacity")
	}
	return nil
}

func validateManagedPlacementBinding(binding ManagedPlacementBinding) error {
	if err := validateToken(binding.DatabaseID, "managed placement database id"); err != nil {
		return err
	}
	if err := validateToken(binding.PartitionID, "managed placement partition id"); err != nil {
		return err
	}
	if err := validateToken(binding.SeatID, "managed placement seat id"); err != nil {
		return err
	}
	if binding.IntentGeneration == 0 || validateDigest(binding.IntentPayloadDigest) != nil ||
		validateDigest(binding.CanonicalRosterDigest) != nil || validateDigest(binding.ManagedHostProfileDigest) != nil {
		return errors.New("managed placement pins are invalid")
	}
	return nil
}

// ManagedRegistrationPins describes the current values that a managed
// registration must match before it can be admitted or used by placement.
type ManagedRegistrationPins struct {
	Placement              ManagedPlacementBinding
	Member                 ManagedMemberBinding
	OCI                    ManagedOCIBinding
	FailureDomain          string
	AllocatableMemoryBytes uint64
	SystemReserveBytes     uint64
}

// ValidateManagedRegistrationPins rejects a registration that does not match
// the current schema-3 placement, member attempt, OCI host, and memory pins.
func ValidateManagedRegistrationPins(registration Registration, pins ManagedRegistrationPins) error {
	if registration.ManagedPlacement == nil || *registration.ManagedPlacement != pins.Placement ||
		registration.ManagedMember == nil || *registration.ManagedMember != pins.Member ||
		registration.ManagedOCI == nil || *registration.ManagedOCI != pins.OCI ||
		registration.FailureDomain != pins.FailureDomain || pins.AllocatableMemoryBytes > math.MaxInt64 ||
		registration.Capacity.MemoryBytes != int64(pins.AllocatableMemoryBytes) || pins.SystemReserveBytes > math.MaxInt64 ||
		registration.SystemReserveBytes != int64(pins.SystemReserveBytes) {
		return errors.New("managed registration differs from current placement pins")
	}
	return nil
}

func validateManagedMemberBinding(binding ManagedMemberBinding) error {
	scope := binding.Scope
	if !lowerHex(scope.ClusterID, 32) || !lowerHex(scope.Incarnation, 32) ||
		!canonicalMemberID(scope.TenantID) || !canonicalMemberID(scope.DatabaseID) ||
		!canonicalMemberID(scope.MemberID) || scope.ShardID == 0 || binding.HostAttempt == 0 {
		return errors.New("managed member identity is invalid")
	}
	return nil
}

func validateManagedOCIBinding(binding ManagedOCIBinding, failureDomain string) error {
	if !catalog.IsCell(binding.Region) {
		return errors.New("managed OCI region is invalid")
	}
	const instancePrefix = "ocid1.instance."
	if !strings.HasPrefix(binding.InstanceID, instancePrefix) || len(binding.InstanceID) <= len(instancePrefix) ||
		len(binding.InstanceID) > 255 || strings.ContainsFunc(binding.InstanceID, unicode.IsSpace) {
		return errors.New("managed OCI instance ID is invalid")
	}
	if err := validateToken(binding.Owner, "managed OCI owner"); err != nil {
		return err
	}
	if binding.FleetGeneration == 0 {
		return errors.New("managed OCI fleet generation must be positive")
	}
	if len(binding.CreateKey) == 0 || len(binding.CreateKey) > 128 || strings.TrimSpace(binding.CreateKey) != binding.CreateKey ||
		strings.ContainsAny(binding.CreateKey, " \t\r\n\f\v") {
		return errors.New("managed OCI create key is invalid")
	}
	if !managedFaultDomainPattern.MatchString(failureDomain) {
		return errors.New("managed OCI fault domain is invalid")
	}
	return nil
}

func validateDesired(d Desired, cell string, r Registration) error {
	if d.Cell != cell || d.Node != r.Node || d.Environment != r.Environment {
		return errors.New("desired identity mismatch")
	}
	if err := validateToken(d.Role, "role"); err != nil {
		return err
	}
	if !slices.Contains(r.Roles, d.Role) {
		return errors.New("role is not registered")
	}
	if (r.ManagedOCI == nil) != (d.ManagedMember == nil) {
		return errors.New("managed desired and registration kind differ")
	}
	if d.ManagedMember != nil {
		if r.ManagedMember == nil {
			return errors.New("managed registration lacks member binding")
		}
		if d.Role != "terrabase" || *r.ManagedOCI != d.ManagedMember.OCI ||
			*r.ManagedMember != d.ManagedMember.Member {
			return errors.New("managed desired binding differs from registration")
		}
		if err := validateManagedMemberLaunch(*d.ManagedMember, d, r); err != nil {
			return err
		}
	}
	if d.Generation == 0 {
		return errors.New("desired generation must be positive")
	}
	if d.Withdrawn {
		if d.Digest != "" || len(d.Args) != 0 || len(d.Env) != 0 || len(d.Secrets) != 0 {
			return errors.New("withdrawn desired contains execution data")
		}
	} else if err := validateDigest(d.Digest); err != nil {
		return err
	}
	if len(d.Args) > 64 || len(d.Env) > 64 {
		return errors.New("too many workload arguments or environment variables")
	}
	for _, arg := range d.Args {
		if len(arg) > 4096 {
			return errors.New("argument too long")
		}
	}
	for key, value := range d.Env {
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(key) || len(value) > 4096 {
			return errors.New("invalid workload environment")
		}
	}
	// A C# TerraBase member's environment is host-owned.
	if len(d.Secrets) != 0 && d.Role == terrabase.Role {
		return errors.New("terrabase takes no Vault secrets")
	}
	return vaultsecret.ValidateRefs(d.Cell, d.Role, d.Secrets, d.Env)
}

func validateManagedMemberLaunch(launch ManagedMemberLaunch, d Desired, r Registration) error {
	if len(d.Args) != 0 || len(d.Env) != 0 || len(d.Secrets) != 0 {
		return errors.New("managed desired cannot carry arbitrary arguments or environment")
	}
	if validateDigest(launch.SourceDigest) != nil ||
		!strings.HasPrefix(launch.VolumeID, "ocid1.volume.") ||
		!strings.HasPrefix(launch.AttachmentID, "ocid1.volumeattachment.") ||
		len(launch.VolumeID) > 255 || len(launch.AttachmentID) > 255 ||
		strings.ContainsFunc(launch.VolumeID, unicode.IsSpace) || strings.ContainsFunc(launch.AttachmentID, unicode.IsSpace) ||
		launch.Authority.Epoch == 0 ||
		!lowerHex(launch.Authority.ConfigurationID, 64) ||
		!lowerHex(launch.Authority.CertificateSHA256, 64) ||
		!lowerHex(launch.Authority.TLSLeafSHA256, 64) {
		return errors.New("managed launch source, volume or authority is invalid")
	}
	if d.Withdrawn {
		if launch.ProcessMemoryBytes != 0 || launch.MemoryHeadroomBytes != 0 || launch.CgroupMemoryMaxBytes != 0 || launch.SystemReserveBytes != 0 || launch.Runtime != nil {
			return errors.New("withdrawn managed desired contains memory execution data")
		}
		return nil
	}
	const gib = uint64(1 << 30)
	p, h, c := launch.ProcessMemoryBytes, launch.MemoryHeadroomBytes, launch.CgroupMemoryMaxBytes
	if p < 4*gib || h < max(gib, p/4) || h >= p || launch.SystemReserveBytes == 0 ||
		launch.SystemReserveBytes > math.MaxInt64 || launch.SystemReserveBytes != uint64(r.SystemReserveBytes) ||
		validateCgroupMemoryMax(c) != nil || c < p || c > uint64(r.Capacity.MemoryBytes) ||
		p > math.MaxInt64 || h > math.MaxInt64 || p%uint64(os.Getpagesize()) != 0 || h%uint64(os.Getpagesize()) != 0 {
		return errors.New("managed process memory, headroom or cgroup cap is invalid")
	}
	if launch.Runtime != nil {
		if launch.AttachmentETag == "" {
			return errors.New("managed runtime requires an exact attachment ETag")
		}
		if err := validateManagedRuntimePins(*launch.Runtime); err != nil {
			return err
		}
	}
	return nil
}

func validateManagedRuntimePins(pins ManagedRuntimePins) error {
	if !strings.HasPrefix(pins.DevicePath, "/dev/") || filepath.Clean(pins.DevicePath) != pins.DevicePath ||
		!filepath.IsAbs(pins.MountPath) || filepath.Clean(pins.MountPath) != pins.MountPath ||
		!filesystemUUIDPattern.MatchString(pins.FileSystemUUID) ||
		pins.FileSystemType != "ext4" && pins.FileSystemType != "xfs" ||
		!lowerHex(pins.TrustedKeySHA256, 64) || !lowerHex(pins.ServerCertificateSHA256, 64) ||
		!lowerHex(pins.ServerPrivateKeySHA256, 64) || !lowerHex(pins.ClientCARootsSHA256, 64) ||
		!lowerHex(pins.ClientManagedMaterialManifestSHA256, 64) ||
		!lowerHex(pins.LiveS3ConfigSHA256, 64) || !lowerHex(pins.LiveS3TargetSHA256, 64) ||
		pins.SQLSchemaBundleSHA256 != "" && !lowerHex(pins.SQLSchemaBundleSHA256, 64) ||
		pins.LiveS3Credential.Validate() != nil ||
		!validPrivateIPv4Endpoint(pins.ReplicationListenAddress) {
		return errors.New("managed runtime device, filesystem, material or listener pin is invalid")
	}
	peer := pins.ReplicationPeerMemberID != "" || pins.ReplicationPeerAddress != "" || pins.ReplicationServerCASHA256 != ""
	if !peer || !canonicalMemberID(pins.ReplicationPeerMemberID) || !validPrivateIPv4Endpoint(pins.ReplicationPeerAddress) ||
		!lowerHex(pins.ReplicationServerCASHA256, 64) {
		return errors.New("managed runtime outbound peer pins are incomplete")
	}
	if pins.BackupManifestSHA256 != "" {
		if !lowerHex(pins.BackupManifestSHA256, 64) || !lowerHex(pins.BackupS3ConfigSHA256, 64) ||
			!lowerHex(pins.BackupS3TargetSHA256, 64) || !lowerHex(pins.BackupS3CredentialSHA256, 64) ||
			!lowerHex(pins.BackupDataKeySHA256, 64) || pins.BackupS3TargetSHA256 == pins.LiveS3TargetSHA256 ||
			pins.BackupOwner && (pins.BackupS3Credential.Validate() != nil || pins.BackupDataKey.Validate() != nil ||
				pins.BackupS3Credential.SecretOCID == pins.LiveS3Credential.SecretOCID ||
				pins.BackupS3Credential.SecretOCID == pins.BackupDataKey.SecretOCID) ||
			!pins.BackupOwner && (pins.BackupS3Credential != (oci.SecretVersionReference{}) ||
				pins.BackupDataKey != (oci.SecretVersionReference{})) {
			return errors.New("managed backup runtime pins are incomplete")
		}
	} else if pins.BackupS3ConfigSHA256 != "" || pins.BackupS3TargetSHA256 != "" ||
		pins.BackupS3CredentialSHA256 != "" || pins.BackupDataKeySHA256 != "" || pins.BackupOwner ||
		pins.BackupS3Credential != (oci.SecretVersionReference{}) || pins.BackupDataKey != (oci.SecretVersionReference{}) {
		return errors.New("partial managed backup runtime pins")
	}
	return nil
}

func validPrivateIPv4Endpoint(address string) bool {
	endpoint, err := netip.ParseAddrPort(address)
	return err == nil && endpoint.String() == address && endpoint.Port() != 0 &&
		endpoint.Addr().Is4() && endpoint.Addr().IsPrivate()
}
