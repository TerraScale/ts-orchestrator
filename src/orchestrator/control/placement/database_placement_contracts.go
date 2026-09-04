package placement

import (
	"sort"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
)

// DatabasePlacementPolicy holds the fixed replication and active-Region limits
// for a production database.
const (
	DatabasePlacementPolicyMinimumActiveRegionCount = 1
	DatabasePlacementPolicyMaximumActiveRegionCount = 20
	DatabasePlacementPolicyActiveReplicationFactor  = 2
	DatabasePlacementPolicyMinimumMemberHosts       = 2
)

// RegionCode is the canonical TerraScale Region identity: exactly three
// uppercase ASCII airport letters; aliases and lowercase input are never
// normalized.
type RegionCode struct {
	value string
	valid bool
}

const RegionCodeLength = 3

var (
	RegionCodeGru = mustRegionCode("GRU")
	RegionCodeSfo = mustRegionCode("SFO")
	RegionCodeFra = mustRegionCode("FRA")
)

func mustRegionCode(value string) RegionCode {
	code, ok := RegionCodeTryCreate(value)
	if !ok {
		panic("invalid region code")
	}
	return code
}

func regionCodeIsCanonical(candidate string) bool {
	if len(candidate) != RegionCodeLength {
		return false
	}
	for i := 0; i < len(candidate); i++ {
		if candidate[i] < 'A' || candidate[i] > 'Z' {
			return false
		}
	}
	return true
}

func (c RegionCode) Value() string  { return c.value }
func (c RegionCode) IsValid() bool  { return c.valid }
func (c RegionCode) String() string { return c.value }

func RegionCodeTryCreate(value string) (RegionCode, bool) {
	if !regionCodeIsCanonical(value) {
		return RegionCode{}, false
	}
	return RegionCode{value: value, valid: true}, true
}

func RegionCodeFromValue(value string) (RegionCode, error) {
	code, ok := RegionCodeTryCreate(value)
	if !ok {
		return RegionCode{}, shared.InvalidArgument("A RegionCode must contain exactly three uppercase ASCII letters.")
	}
	return code, nil
}

type PartitionId struct{ Value string }
type MemberId struct{ Value string }
type FailureDomainId struct{ Value string }
type BackupId struct{ Value string }

type RegionCatalogEntry struct {
	Region           RegionCode
	Available        bool
	Permitted        bool
	ResidencyAllowed bool
	// Residency identifies the legal residency jurisdiction used by named
	// locks. It is deliberately metadata on the catalog, never inferred from
	// an OCI hostname. Jurisdiction is accepted as a compatibility spelling.
	Residency    string
	Jurisdiction string
	// MemberHosts is the current observed member-host count. A placement is
	// never admitted below the two-host failure-domain floor.
	MemberHosts int
}

// RegionCatalog is an immutable snapshot of the catalog used for one pure
// placement evaluation.
type RegionCatalog struct {
	Regions []*RegionCatalogEntry
}

func NewRegionCatalog(regions []*RegionCatalogEntry) *RegionCatalog {
	if regions == nil {
		regions = []*RegionCatalogEntry{}
	}
	return &RegionCatalog{Regions: regions}
}

func regionCatalogCreateInitial() *RegionCatalog {
	return NewRegionCatalog([]*RegionCatalogEntry{
		{Region: RegionCodeGru, Available: true, Permitted: true, ResidencyAllowed: true, Residency: "br", MemberHosts: 2},
		{Region: RegionCodeSfo, Available: true, Permitted: true, ResidencyAllowed: true, Residency: "us", MemberHosts: 2},
		{Region: RegionCodeFra, Available: true, Permitted: true, ResidencyAllowed: true, Residency: "eu", MemberHosts: 2},
	})
}

// DatabasePlacementPolicyInitialCatalog mirrors DatabasePlacementPolicy.InitialCatalog.
var DatabasePlacementPolicyInitialCatalog = regionCatalogCreateInitial()

type ActiveMemberSeat struct {
	Member        MemberId
	Region        RegionCode
	Partition     PartitionId
	FailureDomain FailureDomainId
	IsActive      bool
}

type PartitionRegionPlacement struct {
	Region RegionCode
	Seats  []*ActiveMemberSeat
}

func NewPartitionRegionPlacement(region RegionCode, seats []*ActiveMemberSeat) PartitionRegionPlacement {
	if seats == nil {
		seats = []*ActiveMemberSeat{}
	}
	return PartitionRegionPlacement{Region: region, Seats: seats}
}

type LogicalPartitionPlacement struct {
	Partition PartitionId
	Regions   []*PartitionRegionPlacement
}

func NewLogicalPartitionPlacement(partition PartitionId, regions []*PartitionRegionPlacement) LogicalPartitionPlacement {
	if regions == nil {
		regions = []*PartitionRegionPlacement{}
	}
	return LogicalPartitionPlacement{Partition: partition, Regions: regions}
}

type BackupPromotionPolicy int

const (
	BackupPromotionPolicyNeverPromote   BackupPromotionPolicy = 0
	BackupPromotionPolicyPromoteInPlace BackupPromotionPolicy = 1
)

type BackupPlacement struct {
	Backup          BackupId
	Region          RegionCode
	IsReadOnly      bool
	IsImmutable     bool
	IsVoting        bool
	PromotionPolicy BackupPromotionPolicy
}

// PlacementLockKind is the immutable residency policy selected when a
// database is created. Named policies resolve through the region catalog;
// explicit locks carry the exact region set in Regions.
type PlacementLockKind string

const (
	PlacementLockKindEUOnly   PlacementLockKind = "eu-only"
	PlacementLockKindBROnly   PlacementLockKind = "br-only"
	PlacementLockKindExplicit PlacementLockKind = "explicit"
	PlacementLockEUOnly                         = PlacementLockKindEUOnly
	PlacementLockBROnly                         = PlacementLockKindBROnly
	PlacementLockExplicit                       = PlacementLockKindExplicit
)

// DatabasePlacementLock is the descriptive alias used by persistence
// adapters; it remains exactly the same immutable value as PlacementLock.
type DatabasePlacementLock = PlacementLock

// PlacementLock is the durable customer residency lock. Regions is a copy of
// the resolved set at the lock generation and must never be widened by a
// later request. Generation starts at one and advances monotonically when a
// region is intentionally removed.
type PlacementLock struct {
	Kind                PlacementLockKind
	Regions             []RegionCode
	Generation          uint64
	PlacementGeneration uint64
}

// NewPlacementLock validates and copies a lock. Named locks may leave Regions
// empty until ResolvePlacementLock is called with the authoritative catalog.
func NewPlacementLock(kind PlacementLockKind, regions []RegionCode, generation uint64) (*PlacementLock, error) {
	if kind != PlacementLockKindEUOnly && kind != PlacementLockKindBROnly && kind != PlacementLockKindExplicit {
		return nil, shared.InvalidArgument("Placement lock kind is invalid.")
	}
	if generation == 0 {
		return nil, shared.InvalidArgument("Placement lock generation must be positive.")
	}
	if kind == PlacementLockKindExplicit && len(regions) == 0 {
		return nil, shared.InvalidArgument("An explicit placement lock must name at least one Region.")
	}
	copyRegions := append([]RegionCode(nil), regions...)
	seen := map[string]struct{}{}
	for _, region := range copyRegions {
		if !region.IsValid() {
			return nil, shared.InvalidArgument("Placement lock contains an invalid Region.")
		}
		if _, exists := seen[region.Value()]; exists {
			return nil, shared.InvalidArgument("Placement lock contains a duplicate Region.")
		}
		seen[region.Value()] = struct{}{}
	}
	return &PlacementLock{Kind: kind, Regions: copyRegions, Generation: generation, PlacementGeneration: generation}, nil
}

// NewEUOnlyPlacementLock and NewBROnlyPlacementLock are creation helpers for
// the two named residency policies.
func NewEUOnlyPlacementLock(generation uint64) (*PlacementLock, error) {
	return NewPlacementLock(PlacementLockKindEUOnly, nil, generation)
}

func NewExplicitPlacementLock(regions []RegionCode, generation uint64) (*PlacementLock, error) {
	return NewPlacementLock(PlacementLockKindExplicit, regions, generation)
}

func NewDatabasePlacementLock(kind string, regions []RegionCode, generation uint64) (*PlacementLock, error) {
	return NewPlacementLock(PlacementLockKind(kind), regions, generation)
}

func NewBROnlyPlacementLock(generation uint64) (*PlacementLock, error) {
	return NewPlacementLock(PlacementLockKindBROnly, nil, generation)
}

// ResolvePlacementLock binds a named lock to the registered catalog. Unknown
// or unregistered Regions are rejected; no hostname or provider response is
// used as an implicit registration.
func ResolvePlacementLock(lock *PlacementLock, catalog *RegionCatalog) (*PlacementLock, error) {
	if lock == nil || catalog == nil || (lock.Generation == 0 && lock.PlacementGeneration == 0) {
		return nil, shared.InvalidArgument("A placement lock and Region catalog are required.")
	}
	resolved := *lock
	if resolved.Generation == 0 {
		resolved.Generation = resolved.PlacementGeneration
	}
	resolved.PlacementGeneration = resolved.Generation
	resolved.Regions = append([]RegionCode(nil), lock.Regions...)
	if lock.Kind == PlacementLockKindEUOnly || lock.Kind == PlacementLockKindBROnly {
		want := string(lock.Kind[:2])
		resolved.Regions = nil
		for _, entry := range catalog.Regions {
			if entry == nil {
				continue
			}
			residency := entry.Residency
			if residency == "" {
				residency = entry.Jurisdiction
			}
			if strings.EqualFold(strings.TrimSpace(residency), want) {
				resolved.Regions = append(resolved.Regions, entry.Region)
			}
		}
		if len(resolved.Regions) == 0 {
			return nil, shared.InvalidArgument("Named placement lock has no registered Regions.")
		}
	}
	if len(resolved.Regions) == 0 {
		return nil, shared.InvalidArgument("Placement lock has no Regions.")
	}
	sort.Slice(resolved.Regions, func(i, j int) bool { return resolved.Regions[i].Value() < resolved.Regions[j].Value() })
	seen := map[string]struct{}{}
	for _, region := range resolved.Regions {
		if !region.IsValid() {
			return nil, shared.InvalidArgument("Placement lock contains an invalid Region.")
		}
		if _, exists := seen[region.Value()]; exists {
			return nil, shared.InvalidArgument("Placement lock contains a duplicate Region.")
		}
		seen[region.Value()] = struct{}{}
		found := false
		for _, entry := range catalog.Regions {
			if entry != nil && entry.Region.Value() == region.Value() {
				found = true
				break
			}
		}
		if !found {
			return nil, shared.InvalidArgument("Placement lock names an unregistered Region.")
		}
	}
	return &resolved, nil
}

// CheckPlacementLockWidening rejects a lock update that adds a Region or
// changes policy. Removing Regions is the only permitted mutation and must
// carry a strictly newer generation.
func CheckPlacementLockWidening(prior, updated *PlacementLock) error {
	if prior == nil || updated == nil || (prior.Generation == 0 && prior.PlacementGeneration == 0) || (updated.Generation == 0 && updated.PlacementGeneration == 0) {
		return shared.InvalidArgument("Both placement lock generations are required.")
	}
	priorGeneration, updatedGeneration := prior.Generation, updated.Generation
	if priorGeneration == 0 {
		priorGeneration = prior.PlacementGeneration
	}
	if updatedGeneration == 0 {
		updatedGeneration = updated.PlacementGeneration
	}
	if prior.Kind != updated.Kind {
		return shared.InvalidArgument("Placement lock policy cannot be changed.")
	}
	allowed := map[string]struct{}{}
	for _, region := range prior.Regions {
		allowed[region.Value()] = struct{}{}
	}
	for _, region := range updated.Regions {
		if _, ok := allowed[region.Value()]; !ok {
			return shared.InvalidArgument("Placement lock cannot be widened.")
		}
	}
	if !sameRegionSet(prior.Regions, updated.Regions) && updatedGeneration <= priorGeneration {
		return shared.InvalidArgument("Placement lock generation must advance.")
	}
	if updatedGeneration < priorGeneration {
		return shared.InvalidArgument("Placement lock generation cannot regress.")
	}
	return nil
}

func sameRegionSet(left, right []RegionCode) bool {
	if len(left) != len(right) {
		return false
	}
	a, b := append([]RegionCode(nil), left...), append([]RegionCode(nil), right...)
	sort.Slice(a, func(i, j int) bool { return a[i].Value() < a[j].Value() })
	sort.Slice(b, func(i, j int) bool { return b[i].Value() < b[j].Value() })
	for i := range a {
		if a[i].Value() != b[i].Value() {
			return false
		}
	}
	return true
}

// DatabasePlacementRequest is an immutable customer placement intent; a nil
// Backup means no backup is requested.
type DatabasePlacementRequest struct {
	ActiveRegions []RegionCode
	Partitions    []*LogicalPartitionPlacement
	Backup        *BackupPlacement
	// Lock and PlacementLock are aliases kept during the v1 contract
	// transition; callers should set Lock. A nil lock derives the default
	// explicit lock from ActiveRegions at generation one.
	Lock                *PlacementLock
	PlacementLock       *PlacementLock
	PreviousLock        *PlacementLock
	Generation          uint64
	PlacementGeneration uint64
}

func NewDatabasePlacementRequest(activeRegions []RegionCode, partitions []*LogicalPartitionPlacement,
	backup *BackupPlacement, locks ...*PlacementLock) *DatabasePlacementRequest {
	if activeRegions == nil {
		activeRegions = []RegionCode{}
	}
	if partitions == nil {
		partitions = []*LogicalPartitionPlacement{}
	}
	request := &DatabasePlacementRequest{ActiveRegions: activeRegions, Partitions: partitions, Backup: backup}
	if len(locks) > 0 {
		request.Lock = locks[0]
		request.PlacementLock = locks[0]
	}
	return request
}

type DatabasePlacementErrorCode int

const (
	DatabasePlacementErrorCodeRequestMissing DatabasePlacementErrorCode = 1 + iota
	DatabasePlacementErrorCodeCatalogDuplicateRegion
	DatabasePlacementErrorCodeActiveRegionCountOutOfRange
	DatabasePlacementErrorCodeActiveRegionIdMissing
	DatabasePlacementErrorCodeDuplicateActiveRegion
	DatabasePlacementErrorCodeUnknownRegion
	DatabasePlacementErrorCodeRegionUnavailable
	DatabasePlacementErrorCodeRegionNotPermitted
	DatabasePlacementErrorCodeResidencyDenied
	DatabasePlacementErrorCodeLogicalPartitionMissing
	DatabasePlacementErrorCodePartitionIdMissing
	DatabasePlacementErrorCodeDuplicateLogicalPartition
	DatabasePlacementErrorCodePartitionRegionMissing
	DatabasePlacementErrorCodePartitionRegionExtra
	DatabasePlacementErrorCodeDuplicatePartitionRegion
	DatabasePlacementErrorCodeSeatMissing
	DatabasePlacementErrorCodeSeatExtra
	DatabasePlacementErrorCodeSeatNull
	DatabasePlacementErrorCodeSeatIdMissing
	DatabasePlacementErrorCodeDuplicateSeat
	DatabasePlacementErrorCodeSeatRegionMismatch
	DatabasePlacementErrorCodeSeatPartitionMismatch
	DatabasePlacementErrorCodeSeatInactive
	DatabasePlacementErrorCodeFailureDomainMissing
	DatabasePlacementErrorCodeFailureDomainNotIndependent
	DatabasePlacementErrorCodeBackupIdMissing
	DatabasePlacementErrorCodeBackupRegionMissing
	DatabasePlacementErrorCodeBackupOverlapsActiveRegion
	DatabasePlacementErrorCodeBackupMustBeReadOnly
	DatabasePlacementErrorCodeBackupMustBeImmutable
	DatabasePlacementErrorCodeBackupMustBeNonVoting
	DatabasePlacementErrorCodeBackupPromotionForbidden
	DatabasePlacementErrorCodeCatalogEntryMissing
	DatabasePlacementErrorCodePlacementLockMissing
	DatabasePlacementErrorCodePlacementLockGenerationInvalid
	DatabasePlacementErrorCodePlacementLockWidened
	DatabasePlacementErrorCodePlacementLockRegionUnregistered
	DatabasePlacementErrorCodePlacementLockRegionOutside
	DatabasePlacementErrorCodeRegionMemberHostFloor
	DatabasePlacementErrorCodeBackupOutsidePlacementLock
)

type DatabasePlacementError struct {
	Code      DatabasePlacementErrorCode
	Region    *RegionCode
	Partition *PartitionId
	Member    *MemberId
	Detail    *string
}

type DatabasePlacementFactCode int

const (
	DatabasePlacementFactCodeRequestPresent DatabasePlacementFactCode = 1 + iota
	DatabasePlacementFactCodeActiveRegionCountWithinBounds
	DatabasePlacementFactCodeActiveRegionsUnique
	DatabasePlacementFactCodeActiveRegionsCatalogQualified
	DatabasePlacementFactCodeLogicalPartitionsPresent
	DatabasePlacementFactCodeEveryPartitionHasExactlySelectedRegions
	DatabasePlacementFactCodeEveryPartitionHasExactReplicationFactor
	DatabasePlacementFactCodeSeatsIndependentlyFailureDomainPlaced
	DatabasePlacementFactCodeBackupPolicyQualified
)

type DatabasePlacementQualificationFact struct {
	Code      DatabasePlacementFactCode
	Satisfied bool
}

type DatabasePlacementDecision struct {
	Errors      []DatabasePlacementError
	Facts       []DatabasePlacementQualificationFact
	Fingerprint string
	// EffectiveLock is the immutable lock used for this decision. It is
	// included in the result so replication, backup, restore and export
	// callers cannot accidentally fall back to an unconstrained placement.
	EffectiveLock *PlacementLock
	Generation    uint64
}

func (d *DatabasePlacementDecision) Accepted() bool   { return len(d.Errors) == 0 }
func (d *DatabasePlacementDecision) IsAccepted() bool { return len(d.Errors) == 0 }
