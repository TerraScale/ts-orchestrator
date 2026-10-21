// Package authority provides regional leadership, fencing, and the ordered
// control log shared by authority changes and host mutations.
package authority

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	controlStreamName    = "TS_CONTROL_LOG"
	controlSubjectRoot   = protocol.ControlRoot
	defaultLeaseDuration = 15 * time.Second
	defaultRenewInterval = 3 * time.Second
	defaultReplicas      = 3
	maxControlPayload    = 1 << 20
	maxPlacementIntents  = 10_000
)

var (
	ErrNotLeader         = errors.New("authority is not the current leader")
	ErrFenced            = errors.New("authority epoch has been fenced")
	ErrLeaseCorrupt      = errors.New("authority lease record is corrupt")
	ErrConflict          = errors.New("control log compare-and-set conflict")
	ErrNotFound          = errors.New("control log entry not found")
	ErrOperationConflict = errors.New("operation ID is already bound to different content")
	ErrOutcomeUnknown    = errors.New("control log publish outcome is unknown")
	ErrInvalidTransition = errors.New("invalid operation journal transition")
	ErrProofConsumed     = errors.New("operation proof has already been consumed")
	ErrListTooLarge      = errors.New("placement intent count exceeds the configured bound")
	ErrClockUnhealthy    = errors.New("authority clock health is not bounded")
)

// Config identifies this candidate within one regional or global control log.
// Scope is a lowercase NATS token; DeploymentID and CandidateID are canonical
// ULIDs. A fresh owner ULID prevents a restarted or duplicated candidate
// adopting its old lease.
type Config struct {
	Scope         string
	DeploymentID  string
	CandidateID   string
	LeaseDuration time.Duration
	RenewInterval time.Duration
	Replicas      int
	Logger        *slog.Logger
	ClockCheck    func() error
}

// Snapshot is the latest lease observation made by this runtime.
type Snapshot struct {
	Scope        string
	DeploymentID string
	CandidateID  string
	OwnerID      string
	Leader       bool
	Ready        bool
	Epoch        uint64
	Revision     uint64
	ExpiresAt    time.Time
	ObservedAt   time.Time
	Reason       string
}

// CanMutate reports whether this snapshot grants the local candidate a live
// lease. Mutating consumers must still call Guard immediately before effects.
func (s Snapshot) CanMutate() bool {
	return entityid.Valid(s.DeploymentID) && s.Ready && s.Leader && s.Epoch > 0 && s.Revision > 0 &&
		!s.ExpiresAt.IsZero() && time.Now().Before(s.ExpiresAt)
}

// Fencer is the narrow consumer contract for mutation paths.
type Fencer interface {
	Current() Snapshot
	Guard(context.Context, uint64) error
}

// HostMutationKind selects a restricted family of host state records in the
// ordered control log.
type HostMutationKind string

const (
	MutationRegistration        HostMutationKind = "registration"
	MutationRetirement          HostMutationKind = "retirement"
	MutationDesired             HostMutationKind = "desired"
	MutationRuntimeOwner        HostMutationKind = "runtime-owner"
	MutationManagedRuntimeOwner HostMutationKind = "managed-runtime-owner"
	MutationUsageObservation    HostMutationKind = "usage-observation"
	MutationPlacementIntent     HostMutationKind = "placement-intent"
	MutationMaterialReceipt     HostMutationKind = "material-receipt"
	MutationClientCredentials   HostMutationKind = "client-credentials"
	MutationTerminalIntent      HostMutationKind = "terminal-intent"
	MutationEnrollmentEffect    HostMutationKind = "enrollment-effect"
	MutationRuntimeEffect       HostMutationKind = "runtime-effect"
	MutationManagedUpdate       HostMutationKind = "managed-update"
	MutationBackupOperation     HostMutationKind = "backup-operation"
	MutationNetBirdState        HostMutationKind = "netbird-state"
	MutationNetBirdIntent       HostMutationKind = "netbird-intent"
	MutationFunctionIntent      HostMutationKind = "function-intent"
	MutationFunctionGrant       HostMutationKind = "function-grant"
)

// WorkloadScope identifies one admitted database partition. The terminal gate
// uses the same key as the placement intent, never a host or controller key.
type WorkloadScope struct {
	DatabaseID  string
	PartitionID string
}

// TerminalTarget pins every workload-owned resource whose deletion is allowed.
// Controller instances and resources are not represented by this contract.
type TerminalTarget struct {
	SeatID        string `json:"seat_id"`
	MemberID      string `json:"member_id"`
	HostCreateKey string `json:"host_create_key"`
	DataCreateKey string `json:"data_create_key"`
	InstanceID    string `json:"instance_id"`
	BootVolumeID  string `json:"boot_volume_id"`
	DataVolumeID  string `json:"data_volume_id"`
}

// TerminalIntent is the exact, operator-signed scope admitted before forced
// workload teardown. The immutable control-log record fences later effects.
type TerminalIntent struct {
	Cell                         string           `json:"cell"`
	DatabaseID                   string           `json:"database_id"`
	PartitionID                  string           `json:"partition_id"`
	Region                       string           `json:"region"`
	Owner                        string           `json:"owner"`
	CompartmentID                string           `json:"compartment_id"`
	FleetGeneration              uint64           `json:"fleet_generation"`
	PlacementGeneration          uint64           `json:"placement_generation"`
	PlacementPayloadDigest       string           `json:"placement_payload_digest"`
	OperationID                  string           `json:"operation_id"`
	Nonce                        string           `json:"nonce"`
	Targets                      []TerminalTarget `json:"targets"`
	DisposableWorkload           bool             `json:"disposable_workload"`
	AcknowledgePermanentDataLoss bool             `json:"acknowledge_permanent_data_loss"`
	AuthorizeForcedStop          bool             `json:"authorize_forced_stop"`
}

// Validate requires a closed, exact workload inventory and both independent
// acknowledgements. It does not by itself authenticate the operator signature
// or prove the resources are owned by this workload.
func (intent TerminalIntent) Validate() error {
	if !natsToken.MatchString(intent.Cell) || !entityid.Valid(intent.DatabaseID) ||
		!entityid.Valid(intent.PartitionID) || !natsToken.MatchString(intent.Owner) ||
		!catalog.IsCell(intent.Region) ||
		!strings.HasPrefix(intent.CompartmentID, "ocid1.compartment.") ||
		intent.FleetGeneration == 0 || intent.PlacementGeneration == 0 ||
		!validTerminalDigest(intent.PlacementPayloadDigest) || !entityid.Valid(intent.OperationID) ||
		!validTerminalNonce(intent.Nonce) ||
		!intent.DisposableWorkload || !intent.AcknowledgePermanentDataLoss || !intent.AuthorizeForcedStop ||
		len(intent.Targets) == 0 || len(intent.Targets) > 64 {
		return errors.New("terminal intent has incomplete scope, grant, or inventory")
	}
	seats := make(map[string]struct{}, len(intent.Targets))
	resources := make(map[string]struct{}, len(intent.Targets)*3)
	for _, target := range intent.Targets {
		if !entityid.Valid(target.SeatID) || !entityid.Valid(target.MemberID) ||
			!entityid.Valid(target.HostCreateKey) || !entityid.Valid(target.DataCreateKey) ||
			(target.InstanceID == "") != (target.BootVolumeID == "") ||
			target.InstanceID != "" && !strings.HasPrefix(target.InstanceID, "ocid1.instance.") ||
			target.BootVolumeID != "" && !strings.HasPrefix(target.BootVolumeID, "ocid1.bootvolume.") ||
			target.DataVolumeID != "" && !strings.HasPrefix(target.DataVolumeID, "ocid1.volume.") {
			return errors.New("terminal target has incomplete workload identity")
		}
		if _, exists := seats[target.SeatID]; exists {
			return errors.New("terminal target repeats a placement seat")
		}
		seats[target.SeatID] = struct{}{}
		for _, id := range []string{target.InstanceID, target.BootVolumeID, target.DataVolumeID} {
			if id == "" {
				continue
			}
			if _, exists := resources[id]; exists {
				return errors.New("terminal inventory repeats a resource")
			}
			resources[id] = struct{}{}
		}
	}
	return nil
}

func validTerminalDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func validTerminalNonce(value string) bool {
	return backupHex(value, 16) && strings.Trim(value, "0") != ""
}

// LogEntry is a host mutation committed to the shared ordered control log.
type LogEntry struct {
	Kind        HostMutationKind
	SubjectKey  string
	OperationID string
	Epoch       uint64
	Sequence    uint64
	CreatedAt   time.Time
	Payload     []byte
}

// HostMutationStore exposes the fenced host record log to the host feature.
type HostMutationStore interface {
	CommitHostMutation(context.Context, uint64, HostMutationKind, string, string, uint64, []byte) (uint64, error)
	ReadHostMutation(context.Context, HostMutationKind, string) (LogEntry, error)
}

// VerifiedHostMutationStore runs a managed desired verifier inside the final
// global-sequence CAS retry, so update authorization cannot become stale
// between the verifier and the durable host desired record.
type VerifiedHostMutationStore interface {
	CommitHostMutationVerified(context.Context, uint64, HostMutationKind, string, string, uint64, []byte, func(context.Context) error) (uint64, error)
}

// PlacementIntentStore shares the ordered authority stream for admitted
// placement records so a new lease epoch cannot race an older placement write.
type PlacementIntentStore interface {
	CommitPlacementIntent(context.Context, uint64, string, string, string, uint64, []byte) (uint64, error)
	ReadPlacementIntent(context.Context, string, string) (LogEntry, error)
	ListPlacementIntents(context.Context) ([]LogEntry, error)
}

// TerminalIntentReader observes the immutable workload teardown fence. An
// unreadable marker is an error, not permission to resume active effects.
type TerminalIntentReader interface {
	ReadTerminalIntent(context.Context, string, string) (LogEntry, error)
}

// EnrollmentEffect is a durable in-flight grant mutation. A pending record
// prevents terminal admission even if a different leader currently reads no
// grant; the old process may still publish its delayed KV operation.
type EnrollmentEffect struct {
	EffectID   string
	InstanceID string
	Epoch      uint64
	Sequence   uint64
	Phase      string
}

// MaterialReceiptStore orders one immutable, controller-signed preparation
// receipt per database/partition with placement admission in the same R3 log.
// A KMS object without this CAS record has no placement authority.
type MaterialReceiptStore interface {
	CommitMaterialReceipt(context.Context, uint64, string, string, string, uint64, []byte) (uint64, error)
	ReadMaterialReceipt(context.Context, string, string) (LogEntry, error)
}

// ClientCredentialStore orders signed, monotonically numbered credential
// generations for the same database partition as the initial material.
type ClientCredentialStore interface {
	CommitClientCredentials(context.Context, uint64, string, string, string, uint64, []byte) (uint64, error)
	ReadClientCredentials(context.Context, string, string) (LogEntry, error)
}

// ManagedUpdatePhase is one immutable step in a signed managed runtime update.
type ManagedUpdatePhase string

const (
	ManagedUpdatePrepared      ManagedUpdatePhase = "prepared"
	ManagedUpdateCanaryServing ManagedUpdatePhase = "canary-serving"
	ManagedUpdateHeld          ManagedUpdatePhase = "held"
)

// ManagedUpdateRecord binds durable phase receipts to one exact signed Prepare
// request. SignedRequest contains the original canonical request bytes and is
// copied unchanged into every later phase receipt.
type ManagedUpdateRecord struct {
	SchemaVersion           int                `json:"schema_version"`
	Cell                    string             `json:"cell"`
	DatabaseID              string             `json:"database_id"`
	PartitionID             string             `json:"partition_id"`
	OperationID             string             `json:"operation_id"`
	Phase                   ManagedUpdatePhase `json:"phase"`
	SignedRequest           []byte             `json:"signed_request"`
	SignedRequestSHA256     string             `json:"signed_request_sha256"`
	PlacementGeneration     uint64             `json:"placement_generation"`
	PlacementPayloadDigest  string             `json:"placement_payload_digest"`
	PlacementSequence       uint64             `json:"placement_sequence"`
	CanarySeatID            string             `json:"canary_seat_id"`
	CanaryDesiredGeneration uint64             `json:"canary_desired_generation"`
	OldArtifactDigest       string             `json:"old_artifact_digest"`
	CandidateArtifactDigest string             `json:"candidate_artifact_digest"`
	CandidateManifestDigest string             `json:"candidate_manifest_digest"`
	CandidateSourceDigest   string             `json:"candidate_source_digest"`
	DurabilityProfileSHA256 string             `json:"durability_profile_sha256"`
	Outcome                 string             `json:"outcome,omitempty"`
}

// ManagedUpdateReader returns immutable signed Prepare and canary phase
// receipts from the retained R3 operation history.
type ManagedUpdateReader interface {
	ReadManagedUpdate(context.Context, string, string) (LogEntry, error)
	ReadManagedUpdateOperation(context.Context, string, string, string) ([]LogEntry, error)
	ListManagedUpdates(context.Context, string, string) ([]LogEntry, error)
}

// ManagedUpdateStore records the immutable signed Prepare request and each
// terminal canary result. Operation reads return every exact phase entry so
// callers can reconcile across authority epochs.
type ManagedUpdateStore interface {
	ManagedUpdateReader
	CommitManagedUpdate(context.Context, uint64, ManagedUpdateRecord, uint64, func(context.Context) error) (uint64, error)
}
