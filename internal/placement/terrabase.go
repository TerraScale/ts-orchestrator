package placement

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	// IntentSchemaVersion is the only schema accepted for new managed
	// placement admissions. Schema 1 can still be decoded for historical hold.
	IntentSchemaVersion       = 2
	legacyIntentSchemaVersion = 1
	placementSchemaVersion    = 1
	maxDatabaseIDLength       = 63
	maxPartitionIDLength      = 63
	maxIntentPayloadBytes     = 16 << 10
	managedMemoryPageBytes    = uint64(4096)
	managedMemoryGiB          = uint64(1 << 30)
	maxManagedMemoryByteValue = uint64(1<<63 - 1)
)

var (
	ErrInvalidIntent = errors.New("invalid TerraBase placement intent")
	regionsInOrder   = [...]oci.Region{oci.RegionGRU, oci.RegionSFO, oci.RegionFRA}
)

type Intent struct {
	SchemaVersion       int                  `json:"schema_version"`
	DatabaseID          string               `json:"database_id"`
	PartitionID         string               `json:"partition_id"`
	ActiveRegions       []oci.Region         `json:"active_regions"`
	Generation          uint64               `json:"generation"`
	ManagedHostProfiles []ManagedHostProfile `json:"managed_host_profiles,omitempty"`
	committedPayloadSHA string
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

// ProfileDigest returns the lower-case SHA-256 of deterministic JSON for the
// entire region profile, including its region, compute tuple and all byte
// limits. Placement generation is pinned separately by Intent.Generation.
func (profile ManagedHostProfile) ProfileDigest() (string, error) {
	if err := profile.Validate(); err != nil {
		return "", err
	}
	encoded, err := protocol.EncodeJSON(profile)
	if err != nil {
		return "", fmt.Errorf("encode managed host profile: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (profile ManagedHostProfile) Validate() error {
	if !knownRegion(profile.Region) || !validComputeShape(profile.Compute.Shape) ||
		profile.Compute.WholeOCPUs == 0 || profile.Compute.MemoryInGBs == 0 {
		return fmt.Errorf("%w: managed profile region or compute tuple", ErrInvalidIntent)
	}
	values := [...]uint64{
		profile.ProcessMemoryBytes, profile.MemoryHeadroomBytes, profile.CgroupMemoryMaxBytes,
		profile.SystemReserveBytes, profile.AllocatableMemoryBytes,
	}
	for _, value := range values {
		if value == 0 || value > maxManagedMemoryByteValue || value%managedMemoryPageBytes != 0 {
			return fmt.Errorf("%w: memory limits must be positive, signed-range, page-aligned byte values", ErrInvalidIntent)
		}
	}
	minimumHeadroom := max(managedMemoryGiB, profile.ProcessMemoryBytes/4)
	// MemoryInGBs is uint32, so this exact multiplication stays below 2^62.
	// GiB is the conservative upper bound whether the SDK's GB means decimal
	// or binary units; the host still verifies actual guest capacity.
	nominalMemoryBytes := uint64(profile.Compute.MemoryInGBs) * managedMemoryGiB
	if profile.ProcessMemoryBytes < 4*managedMemoryGiB || profile.MemoryHeadroomBytes < minimumHeadroom ||
		profile.MemoryHeadroomBytes >= profile.ProcessMemoryBytes ||
		profile.ProcessMemoryBytes > profile.CgroupMemoryMaxBytes ||
		profile.CgroupMemoryMaxBytes > profile.AllocatableMemoryBytes ||
		profile.SystemReserveBytes > maxManagedMemoryByteValue-profile.AllocatableMemoryBytes ||
		profile.AllocatableMemoryBytes > nominalMemoryBytes ||
		profile.SystemReserveBytes > nominalMemoryBytes-profile.AllocatableMemoryBytes {
		return fmt.Errorf("%w: managed process, headroom, cgroup, allocatable memory and reserve bounds", ErrInvalidIntent)
	}
	return nil
}

func (intent Intent) Validate() error {
	if intent.SchemaVersion != legacyIntentSchemaVersion && intent.SchemaVersion != IntentSchemaVersion ||
		!validBoundedToken(intent.DatabaseID, maxDatabaseIDLength) ||
		!validBoundedToken(intent.PartitionID, maxPartitionIDLength) || intent.Generation == 0 ||
		len(intent.ActiveRegions) < 1 || len(intent.ActiveRegions) > len(regionsInOrder) {
		return fmt.Errorf("%w: schema, identity, generation or region count", ErrInvalidIntent)
	}
	for index, region := range intent.ActiveRegions {
		if !knownRegion(region) {
			return fmt.Errorf("%w: unsupported region %q", ErrInvalidIntent, region)
		}
		if slices.Contains(intent.ActiveRegions[:index], region) {
			return fmt.Errorf("%w: repeated region %q", ErrInvalidIntent, region)
		}
	}
	if intent.SchemaVersion == legacyIntentSchemaVersion {
		if len(intent.ManagedHostProfiles) != 0 {
			return fmt.Errorf("%w: historical schema 1 cannot carry managed host profiles", ErrInvalidIntent)
		}
		return nil
	}
	if !canonicalRegions(intent.ActiveRegions) || len(intent.ManagedHostProfiles) != len(intent.ActiveRegions) {
		return fmt.Errorf("%w: managed profiles must exactly cover canonically ordered selected regions", ErrInvalidIntent)
	}
	for index, profile := range intent.ManagedHostProfiles {
		if profile.Region != intent.ActiveRegions[index] {
			return fmt.Errorf("%w: managed profiles are missing, foreign or out of canonical order", ErrInvalidIntent)
		}
		if err := profile.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ValidateForAdmission limits newly signed managed placements to the profile
// schema. Historical schema-1 records remain decodable for explicit hold.
func (intent Intent) ValidateForAdmission() error {
	if intent.SchemaVersion != IntentSchemaVersion {
		return fmt.Errorf("%w: schema %d is historical and cannot authorize a new managed placement", ErrInvalidIntent, intent.SchemaVersion)
	}
	return intent.Validate()
}

// ManagedHostProfile returns the exact admitted region profile.
func (intent Intent) ManagedHostProfile(region oci.Region) (ManagedHostProfile, error) {
	if err := intent.ValidateForAdmission(); err != nil {
		return ManagedHostProfile{}, err
	}
	index := slices.IndexFunc(intent.ManagedHostProfiles, func(profile ManagedHostProfile) bool { return profile.Region == region })
	if index < 0 {
		return ManagedHostProfile{}, fmt.Errorf("%w: region %q is not selected", ErrInvalidIntent, region)
	}
	return intent.ManagedHostProfiles[index], nil
}

// ProfileDigest returns the verified profile digest for one selected region.
func (intent Intent) ProfileDigest(region oci.Region) (string, error) {
	profile, err := intent.ManagedHostProfile(region)
	if err != nil {
		return "", err
	}
	return profile.ProfileDigest()
}

// PayloadDigest exposes the exact canonical payload digest attached by
// DecodeCommittedIntent after it reads the operator-signed ordered log.
func (intent Intent) PayloadDigest() string { return intent.committedPayloadSHA }

// OperationID is stable across regional log consumers and binds one admitted
// database/partition generation without depending on lease history.
func (intent Intent) OperationID() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", intent.DatabaseID, intent.PartitionID, intent.Generation)))
	return "p-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))
}

// DecodeCommittedIntent validates canonical bytes returned from the ordered
// authority log and attaches their exact payload digest. It accepts schema 1
// only so callers can hold historical records; it does not make them eligible
// for a new managed placement.
func DecodeCommittedIntent(payload []byte) (Intent, error) {
	var intent Intent
	if err := protocol.DecodeStrict(payload, &intent, maxIntentPayloadBytes); err != nil {
		return Intent{}, fmt.Errorf("%w: decode committed placement intent: %v", ErrInvalidIntent, err)
	}
	if err := intent.Validate(); err != nil {
		return Intent{}, err
	}
	canonical, err := protocol.EncodeJSON(intent)
	if err != nil {
		return Intent{}, fmt.Errorf("%w: encode committed placement intent: %v", ErrInvalidIntent, err)
	}
	if !bytes.Equal(canonical, payload) {
		return Intent{}, fmt.Errorf("%w: committed placement intent is not canonical JSON", ErrInvalidIntent)
	}
	digest := sha256.Sum256(payload)
	intent.committedPayloadSHA = hex.EncodeToString(digest[:])
	return intent, nil
}

func canonicalRegions(regions []oci.Region) bool {
	previous := -1
	for _, region := range regions {
		index := slices.Index(regionsInOrder[:], region)
		if index < 0 || index <= previous {
			return false
		}
		previous = index
	}
	return true
}

func validComputeShape(shape string) bool {
	if len(shape) == 0 || len(shape) > 128 {
		return false
	}
	for index := range len(shape) {
		character := shape[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
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
	SchemaVersion            int                `json:"schema_version"`
	DatabaseID               string             `json:"database_id"`
	PartitionID              string             `json:"partition_id"`
	MemberID                 string             `json:"member_id"`
	Region                   oci.Region         `json:"region"`
	FailureDomain            string             `json:"failure_domain"`
	Kind                     MemberKind         `json:"kind"`
	Stage                    MemberStage        `json:"stage"`
	CreateKey                string             `json:"create_key"`
	HostNode                 string             `json:"host_node,omitempty"`
	InstanceID               string             `json:"instance_id,omitempty"`
	InstanceETag             string             `json:"instance_etag,omitempty"`
	VolumeID                 string             `json:"volume_id,omitempty"`
	AttachmentID             string             `json:"attachment_id,omitempty"`
	HostAttempt              uint64             `json:"host_attempt"`
	WriterEpoch              uint64             `json:"writer_epoch,omitzero"`
	IntentGeneration         uint64             `json:"intent_generation"`
	IntentPayloadDigest      string             `json:"intent_payload_digest,omitempty"`
	ManagedHostProfile       ManagedHostProfile `json:"managed_host_profile,omitzero"`
	ManagedHostProfileDigest string             `json:"managed_host_profile_digest,omitempty"`
	DesiredGeneration        uint64             `json:"desired_generation"`
	HostGeneration           uint64             `json:"host_generation"`
	OperationID              string             `json:"operation_id"`
	UpdatedAt                time.Time          `json:"updated_at"`
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
	if state.IntentPayloadDigest != "" || state.ManagedHostProfile != (ManagedHostProfile{}) || state.ManagedHostProfileDigest != "" {
		if !validLowerSHA256Digest(state.IntentPayloadDigest) ||
			!validLowerSHA256Digest(state.ManagedHostProfileDigest) ||
			state.ManagedHostProfile.Region != state.Region || state.ManagedHostProfile.Validate() != nil {
			return errors.New("invalid TerraBase member state managed profile pin")
		}
		digest, err := state.ManagedHostProfile.ProfileDigest()
		if err != nil || digest != state.ManagedHostProfileDigest {
			return errors.New("invalid TerraBase member state managed profile digest")
		}
	}
	return nil
}

func validLowerSHA256Digest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	digest, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(digest) == value
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
