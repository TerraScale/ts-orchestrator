// Port of src/TerraScale.Orchestrator/ControlPlane/DatabasePlacement/DatabasePlacementContracts.cs
package control

// DatabasePlacementPolicy holds the fixed replication and active-Region limits
// for a production database.
const (
	DatabasePlacementPolicyMinimumActiveRegionCount = 1
	DatabasePlacementPolicyMaximumActiveRegionCount = 20
	DatabasePlacementPolicyActiveReplicationFactor  = 2
)

// RegionCode is the canonical TerraScale Region identity: exactly three
// uppercase ASCII airport letters; aliases and lowercase input are never
// normalized.
type RegionCode struct {
	value  string
	valid  bool
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
		return RegionCode{}, invalidArgument("A RegionCode must contain exactly three uppercase ASCII letters.")
	}
	return code, nil
}

type PartitionId struct{ Value string }
type MemberId struct{ Value string }
type FailureDomainId struct{ Value string }
type BackupId struct{ Value string }

type RegionCatalogEntry struct {
	Region          RegionCode
	Available       bool
	Permitted       bool
	ResidencyAllowed bool
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
		{Region: RegionCodeGru, Available: true, Permitted: true, ResidencyAllowed: true},
		{Region: RegionCodeSfo, Available: true, Permitted: true, ResidencyAllowed: true},
		{Region: RegionCodeFra, Available: true, Permitted: true, ResidencyAllowed: true},
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
	Regions  []*PartitionRegionPlacement
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
	Backup         BackupId
	Region         RegionCode
	IsReadOnly     bool
	IsImmutable    bool
	IsVoting       bool
	PromotionPolicy BackupPromotionPolicy
}

// DatabasePlacementRequest is an immutable customer placement intent; a nil
// Backup means no backup is requested.
type DatabasePlacementRequest struct {
	ActiveRegions []RegionCode
	Partitions    []*LogicalPartitionPlacement
	Backup        *BackupPlacement
}

func NewDatabasePlacementRequest(activeRegions []RegionCode, partitions []*LogicalPartitionPlacement,
	backup *BackupPlacement) *DatabasePlacementRequest {
	if activeRegions == nil {
		activeRegions = []RegionCode{}
	}
	if partitions == nil {
		partitions = []*LogicalPartitionPlacement{}
	}
	return &DatabasePlacementRequest{ActiveRegions: activeRegions, Partitions: partitions, Backup: backup}
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
	Errors  []DatabasePlacementError
	Facts   []DatabasePlacementQualificationFact
	Fingerprint string
}

func (d *DatabasePlacementDecision) Accepted() bool { return len(d.Errors) == 0 }
func (d *DatabasePlacementDecision) IsAccepted() bool { return len(d.Errors) == 0 }
