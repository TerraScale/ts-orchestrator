package placement

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

const (
	placementSchemaVersion = 1
	maxDatabaseIDLength    = 63
	maxPartitionIDLength   = 63
)

var (
	ErrInvalidIntent = errors.New("invalid TerraBase placement intent")
	regionsInOrder   = [...]oci.Region{oci.RegionGRU, oci.RegionSFO, oci.RegionFRA}
)

type Intent struct {
	SchemaVersion int          `json:"schema_version"`
	DatabaseID    string       `json:"database_id"`
	PartitionID   string       `json:"partition_id"`
	ActiveRegions []oci.Region `json:"active_regions"`
	Generation    uint64       `json:"generation"`
}

func (intent Intent) Validate() error {
	if intent.SchemaVersion != placementSchemaVersion || !validBoundedToken(intent.DatabaseID, maxDatabaseIDLength) ||
		!validBoundedToken(intent.PartitionID, maxPartitionIDLength) || intent.Generation == 0 ||
		len(intent.ActiveRegions) < 1 || len(intent.ActiveRegions) > len(regionsInOrder) {
		return fmt.Errorf("%w: schema, identity, generation or region count", ErrInvalidIntent)
	}
	seen := make(map[oci.Region]struct{}, len(intent.ActiveRegions))
	for _, region := range intent.ActiveRegions {
		if !knownRegion(region) {
			return fmt.Errorf("%w: unsupported region %q", ErrInvalidIntent, region)
		}
		if _, exists := seen[region]; exists {
			return fmt.Errorf("%w: repeated region %q", ErrInvalidIntent, region)
		}
		seen[region] = struct{}{}
	}
	return nil
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

// DesiredSeats returns the fixed two-member topology for every selected region.
// It never returns seats in a region absent from the admitted intent. Each seat
// in a region gets a distinct configured OCI failure domain.
func DesiredSeats(intent Intent, faultDomains map[oci.Region][]string) ([]Seat, error) {
	if err := intent.Validate(); err != nil {
		return nil, err
	}
	selected := make(map[oci.Region]struct{}, len(intent.ActiveRegions))
	for _, region := range intent.ActiveRegions {
		selected[region] = struct{}{}
	}

	seats := make([]Seat, 0, len(selected)*2)
	for _, region := range regionsInOrder {
		if _, active := selected[region]; !active {
			continue
		}
		domains := faultDomains[region]
		if len(domains) < 2 || !validBoundedToken(strings.ToLower(domains[0]), 63) ||
			!validBoundedToken(strings.ToLower(domains[1]), 63) || domains[0] == domains[1] {
			return nil, fmt.Errorf("%w: region %s needs two distinct configured fault domains", ErrInvalidIntent, region)
		}
		permanentID := permanentMember(region)
		seats = append(seats,
			Seat{MemberID: permanentID, Region: region, FailureDomain: domains[0], Kind: MemberPermanent},
			Seat{MemberID: elasticMember(region), Region: region, FailureDomain: domains[1], Kind: MemberElastic},
		)
	}
	return seats, nil
}

func permanentMember(region oci.Region) string {
	switch region {
	case oci.RegionGRU:
		return "permanent-a"
	case oci.RegionSFO:
		return "permanent-b"
	case oci.RegionFRA:
		return "permanent-c"
	default:
		return ""
	}
}

func elasticMember(region oci.Region) string {
	return "elastic-" + strings.ToLower(string(region))
}

func knownRegion(region oci.Region) bool {
	return slices.Contains(regionsInOrder[:], region)
}

func validBoundedToken(value string, maxLength int) bool {
	return len(value) <= maxLength && validToken(value)
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
	SchemaVersion     int         `json:"schema_version"`
	DatabaseID        string      `json:"database_id"`
	PartitionID       string      `json:"partition_id"`
	MemberID          string      `json:"member_id"`
	Region            oci.Region  `json:"region"`
	FailureDomain     string      `json:"failure_domain"`
	Kind              MemberKind  `json:"kind"`
	Stage             MemberStage `json:"stage"`
	CreateKey         string      `json:"create_key"`
	HostNode          string      `json:"host_node,omitempty"`
	InstanceID        string      `json:"instance_id,omitempty"`
	InstanceETag      string      `json:"instance_etag,omitempty"`
	VolumeID          string      `json:"volume_id,omitempty"`
	AttachmentID      string      `json:"attachment_id,omitempty"`
	HostAttempt       uint64      `json:"host_attempt"`
	WriterEpoch       uint64      `json:"writer_epoch,omitzero"`
	IntentGeneration  uint64      `json:"intent_generation"`
	DesiredGeneration uint64      `json:"desired_generation"`
	HostGeneration    uint64      `json:"host_generation"`
	OperationID       string      `json:"operation_id"`
	UpdatedAt         time.Time   `json:"updated_at"`
}

func (state MemberState) Validate() error {
	if state.SchemaVersion != placementSchemaVersion || !validBoundedToken(state.DatabaseID, maxDatabaseIDLength) ||
		!validBoundedToken(state.PartitionID, maxPartitionIDLength) || !validToken(state.MemberID) ||
		!knownRegion(state.Region) || !validBoundedToken(strings.ToLower(state.FailureDomain), 63) ||
		state.Kind != MemberPermanent && state.Kind != MemberElastic || !knownStage(state.Stage) ||
		!validToken(state.CreateKey) || state.HostAttempt == 0 || state.IntentGeneration == 0 ||
		stageRequiresHostGeneration(state.Stage) && state.HostGeneration == 0 ||
		!validToken(state.OperationID) || state.UpdatedAt.IsZero() || state.UpdatedAt.Location() != time.UTC ||
		state.Kind == MemberPermanent && state.MemberID != permanentMember(state.Region) ||
		state.Kind == MemberElastic && state.MemberID != elasticMember(state.Region) {
		return errors.New("invalid TerraBase member state")
	}
	return nil
}

func knownStage(stage MemberStage) bool {
	switch stage {
	case StagePreparedHost, StageAwaitingHost, StagePreparedVolume, StagePreparedAttach, StageAwaitingAttach,
		StagePreparedDesired, StageAwaitingRuntimeContract, StageAwaitingHealthy, StageServing,
		StageRemoveCandidate, StageCordoned, StageDraining, StageDrained, StageStorageHandled, StageTerminated, StageRemoved:
		return true
	default:
		return false
	}
}

func stageRequiresHostGeneration(stage MemberStage) bool {
	switch stage {
	case StagePreparedHost, StageAwaitingHost:
		return false
	default:
		return true
	}
}

type MemberObservation struct {
	DatabaseID     string
	PartitionID    string
	MemberID       string
	Region         oci.Region
	FailureDomain  string
	InstanceID     string
	VolumeID       string
	Stage          MemberStage
	Healthy        bool
	CurrentSession bool
}

type RetirementEvidence struct {
	DatabaseID         string
	PartitionID        string
	MemberID           string
	InstanceID         string
	VolumeID           string
	ReplicationHealthy bool
	QuorumSafe         bool
	HostDrained        bool
	WriterStopped      bool
	WriterStopProof    oci.WriterStopEvidence
	VolumeRetained     bool
}

// CanRetire refuses removal unless the intent leaves two serving members on
// distinct failure domains in every selected region and all independent
// data-plane and host-stop proofs are present. It never initiates or forces a
// TerraBase leadership change.
func CanRetire(intent Intent, candidate MemberObservation, survivors []MemberObservation, evidence RetirementEvidence) (bool, string) {
	if allowed, reason := retirementTopologySafe(intent, candidate, survivors); !allowed {
		return false, reason
	}
	if !evidenceMatchesCandidate(evidence, candidate) {
		return false, "retirement-evidence-identity-mismatch"
	}
	if !evidence.ReplicationHealthy {
		return false, "replication-health-unverified"
	}
	if !evidence.QuorumSafe {
		return false, "quorum-safety-unverified"
	}
	if !evidence.HostDrained {
		return false, "host-drain-unverified"
	}
	if !evidence.WriterStopped || len(evidence.WriterStopProof) == 0 {
		return false, "writer-stop-unverified"
	}
	if !evidence.VolumeRetained {
		return false, "retained-volume-decision-unverified"
	}
	return true, "safe-to-retire"
}

// CanBeginRetirement is the pre-drain gate. It permits cordon/drain only after
// the intent no longer needs the candidate and every selected region retains
// two serving members on distinct failure domains. Provider removal still
// requires CanRetire with fresh drain and writer-stop evidence.
func CanBeginRetirement(intent Intent, candidate MemberObservation, survivors []MemberObservation, evidence RetirementEvidence) (bool, string) {
	if candidate.Stage != StageServing || !candidate.Healthy || !candidate.CurrentSession {
		return false, "candidate-health-or-session-unverified"
	}
	if allowed, reason := retirementTopologySafe(intent, candidate, survivors); !allowed {
		return false, reason
	}
	if !evidenceMatchesCandidate(evidence, candidate) {
		return false, "retirement-evidence-identity-mismatch"
	}
	if !evidence.ReplicationHealthy {
		return false, "replication-health-unverified"
	}
	if !evidence.QuorumSafe {
		return false, "quorum-safety-unverified"
	}
	return true, "safe-to-begin-retirement"
}

func retirementTopologySafe(intent Intent, candidate MemberObservation, survivors []MemberObservation) (bool, string) {
	if err := intent.Validate(); err != nil {
		return false, "invalid-intent"
	}
	if candidate.DatabaseID != intent.DatabaseID || candidate.PartitionID != intent.PartitionID ||
		candidate.MemberID == "" || candidate.Region == "" || !knownRegion(candidate.Region) ||
		candidate.InstanceID == "" || candidate.VolumeID == "" {
		return false, "candidate-identity-missing"
	}
	if !removableStage(candidate.Stage) {
		return false, "candidate-stage-invalid"
	}
	if desiredMember(intent, candidate.Region, candidate.MemberID) {
		return false, "candidate-still-desired"
	}
	for _, member := range survivors {
		if member.DatabaseID != intent.DatabaseID || member.PartitionID != intent.PartitionID {
			return false, "survivor-identity-mismatch"
		}
	}
	for _, region := range intent.ActiveRegions {
		memberCount := 0
		failureDomains := make(map[string]struct{}, 2)
		for _, member := range survivors {
			if member.Region != region || member.MemberID == candidate.MemberID || member.Stage != StageServing ||
				!member.Healthy || !member.CurrentSession {
				continue
			}
			if member.FailureDomain == "" {
				return false, "survivor-failure-domain-unverified"
			}
			if _, exists := failureDomains[member.FailureDomain]; exists {
				return false, "survivor-anti-affinity-violated"
			}
			failureDomains[member.FailureDomain] = struct{}{}
			memberCount++
		}
		if memberCount < 2 {
			return false, "replica-floor-or-health-not-met"
		}
	}
	return true, "topology-safe"
}

func evidenceMatchesCandidate(evidence RetirementEvidence, candidate MemberObservation) bool {
	return evidence.DatabaseID == candidate.DatabaseID && evidence.PartitionID == candidate.PartitionID &&
		evidence.MemberID == candidate.MemberID && evidence.InstanceID == candidate.InstanceID &&
		evidence.VolumeID == candidate.VolumeID
}

func desiredMember(intent Intent, region oci.Region, memberID string) bool {
	if !slices.Contains(intent.ActiveRegions, region) {
		return false
	}
	return memberID == permanentMember(region) || memberID == elasticMember(region)
}

func removableStage(stage MemberStage) bool {
	switch stage {
	case StageServing, StageRemoveCandidate, StageCordoned, StageDraining, StageDrained, StageStorageHandled:
		return true
	default:
		return false
	}
}
