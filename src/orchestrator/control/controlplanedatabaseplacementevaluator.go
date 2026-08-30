// Port of src/TerraScale.Orchestrator/ControlPlane/DatabasePlacement/DatabasePlacementEvaluator.cs
package control

import (
	"sort"
	"strconv"
	"strings"
)

// DatabasePlacementEvaluator performs pure, deterministic admission of a
// database placement intent.
var DatabasePlacementEvaluator databasePlacementEvaluator

type databasePlacementEvaluator struct{}

func (databasePlacementEvaluator) Evaluate(request *DatabasePlacementRequest, catalog *RegionCatalog) *DatabasePlacementDecision {
	var errors []DatabasePlacementError
	var facts []DatabasePlacementQualificationFact
	effectiveCatalog := catalog
	if effectiveCatalog == nil {
		effectiveCatalog = DatabasePlacementPolicyInitialCatalog
	}

	if request == nil {
		errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeRequestMissing})
		databasePlacementAddFacts(&facts, false, false, false, false, false, false, false, false, false)
		return databasePlacementFinish(errors, facts)
	}

	catalogEntries := effectiveCatalog.Regions
	catalogByKey := map[string]RegionCatalogEntry{}
	hasCatalogGaps := false
	for _, entry := range catalogEntries {
		if entry == nil {
			hasCatalogGaps = true
		}
	}
	if hasCatalogGaps {
		errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeCatalogEntryMissing})
	}
	seenCatalog := map[string][]RegionCatalogEntry{}
	for _, entry := range catalogEntries {
		if entry == nil {
			continue
		}
		key := databasePlacementKey(entry.Region.Value())
		seenCatalog[key] = append(seenCatalog[key], *entry)
	}
	catalogKeys := make([]string, 0, len(seenCatalog))
	for key := range seenCatalog {
		catalogKeys = append(catalogKeys, key)
	}
	sort.Strings(catalogKeys)
	for _, key := range catalogKeys {
		group := seenCatalog[key]
		if len(group) != 1 {
			errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeCatalogDuplicateRegion,
				Region: &group[0].Region})
			continue
		}
		catalogByKey[key] = group[0]
	}

	activeRegions := request.ActiveRegions
	activeKeys := make([]string, len(activeRegions))
	for index, region := range activeRegions {
		activeKeys[index] = databasePlacementKey(region.Value())
	}
	activeRegionCountValid := len(activeRegions) >= DatabasePlacementPolicyMinimumActiveRegionCount &&
		len(activeRegions) <= DatabasePlacementPolicyMaximumActiveRegionCount
	if !activeRegionCountValid {
		detail := strconv.Itoa(len(activeRegions))
		errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeActiveRegionCountOutOfRange,
			Detail: &detail})
	}

	orderedRegions := databasePlacementOrderedRegions(activeRegions)
	for _, region := range orderedRegions {
		if !region.IsValid() {
			errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeActiveRegionIdMissing,
				Region: &region})
		}
	}

	activeGroups := map[string][]RegionCode{}
	for _, region := range activeRegions {
		key := databasePlacementKey(region.Value())
		activeGroups[key] = append(activeGroups[key], region)
	}
	groupKeys := make([]string, 0, len(activeGroups))
	for key := range activeGroups {
		groupKeys = append(groupKeys, key)
	}
	sort.Strings(groupKeys)
	for _, key := range groupKeys {
		group := activeGroups[key]
		if len(group) > 1 {
			sort.SliceStable(group, func(i, j int) bool {
				return (group[i].Value()) < (group[j].Value())
			})
			errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeDuplicateActiveRegion,
				Region: &group[0]})
		}
	}

	distinctKeys := map[string]struct{}{}
	for _, key := range activeKeys {
		distinctKeys[key] = struct{}{}
	}
	allValid := true
	for _, region := range activeRegions {
		if !region.IsValid() {
			allValid = false
			break
		}
	}
	uniqueRegions := len(distinctKeys) == len(activeRegions) && allValid
	catalogQualified := true
	for _, region := range orderedRegions {
		key := databasePlacementKey(region.Value())
		entry, known := catalogByKey[key]
		if !known {
			errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeUnknownRegion,
				Region: &region})
			catalogQualified = false
			continue
		}
		if !entry.Available {
			errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeRegionUnavailable,
				Region: &region})
			catalogQualified = false
		}
		if !entry.Permitted {
			errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeRegionNotPermitted,
				Region: &region})
			catalogQualified = false
		}
		if !entry.ResidencyAllowed {
			errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeResidencyDenied,
				Region: &region})
			catalogQualified = false
		}
	}
	for _, err := range errors {
		if err.Code == DatabasePlacementErrorCodeCatalogDuplicateRegion ||
			err.Code == DatabasePlacementErrorCodeCatalogEntryMissing {
			catalogQualified = false
		}
	}

	partitions := request.Partitions
	partitionsPresent := len(partitions) > 0
	for _, partition := range partitions {
		if partition == nil {
			partitionsPresent = false
		}
	}
	if !partitionsPresent {
		errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeLogicalPartitionMissing})
	}

	partitionGroups := map[string][]*LogicalPartitionPlacement{}
	for _, partition := range partitions {
		if partition == nil {
			continue
		}
		key := databasePlacementKey(partition.Partition.Value)
		partitionGroups[key] = append(partitionGroups[key], partition)
	}
	partitionKeys := make([]string, 0, len(partitionGroups))
	for key := range partitionGroups {
		partitionKeys = append(partitionKeys, key)
	}
	sort.Strings(partitionKeys)
	for _, key := range partitionKeys {
		group := partitionGroups[key]
		if len(group) > 1 {
			sort.SliceStable(group, func(i, j int) bool {
				return group[i].Partition.Value < group[j].Partition.Value
			})
			errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeDuplicateLogicalPartition,
				Partition: &group[0].Partition})
		}
	}

	regionsComplete := partitionsPresent
	replicasExact := partitionsPresent
	domainsIndependent := partitionsPresent
	orderedPartitions := make([]*LogicalPartitionPlacement, 0, len(partitions))
	for _, partition := range partitions {
		if partition != nil {
			orderedPartitions = append(orderedPartitions, partition)
		}
	}
	sort.Slice(orderedPartitions, func(i, j int) bool {
		return databasePlacementKey(orderedPartitions[i].Partition.Value) <
			databasePlacementKey(orderedPartitions[j].Partition.Value)
	})
	for _, partition := range orderedPartitions {
		if isNullOrWhiteSpace(partition.Partition.Value) {
			errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodePartitionIdMissing,
				Partition: &partition.Partition})
			regionsComplete = false
		}

		for _, placement := range partition.Regions {
			if placement == nil {
				errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodePartitionRegionExtra,
					Partition: &partition.Partition})
				regionsComplete = false
			}
		}
		var validPlacements []*PartitionRegionPlacement
		for _, placement := range partition.Regions {
			if placement != nil {
				validPlacements = append(validPlacements, placement)
			}
		}
		placementGroups := map[string][]*PartitionRegionPlacement{}
		for _, placement := range validPlacements {
			key := databasePlacementKey(placement.Region.Value())
			placementGroups[key] = append(placementGroups[key], placement)
		}
		placementKeys := make([]string, 0, len(placementGroups))
		for key := range placementGroups {
			placementKeys = append(placementKeys, key)
		}
		sort.Strings(placementKeys)
		for _, key := range placementKeys {
			group := placementGroups[key]
			if len(group) > 1 {
				errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeDuplicatePartitionRegion,
					Region: &group[0].Region, Partition: &partition.Partition})
				regionsComplete = false
			}
		}

		expected := orderedRegions
		expectedKeySet := map[string]struct{}{}
		for _, key := range activeKeys {
			expectedKeySet[key] = struct{}{}
		}
		for _, region := range expected {
			var matches []*PartitionRegionPlacement
			for _, placement := range validPlacements {
				if databasePlacementKey(placement.Region.Value()) == databasePlacementKey(region.Value()) {
					matches = append(matches, placement)
				}
			}
			if len(matches) == 0 {
				errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodePartitionRegionMissing,
					Region: &region, Partition: &partition.Partition})
				regionsComplete = false
				continue
			}
			if len(matches) == 1 {
				databasePlacementEvaluateSeats(matches[0], partition.Partition, region, &errors,
					&replicasExact, &domainsIndependent)
			} else {
				replicasExact = false
				domainsIndependent = false
			}
		}

		sort.Slice(validPlacements, func(i, j int) bool {
			return databasePlacementKey(validPlacements[i].Region.Value()) <
				databasePlacementKey(validPlacements[j].Region.Value())
		})
		for _, placement := range validPlacements {
			if _, present := expectedKeySet[databasePlacementKey(placement.Region.Value())]; !present {
				errors = append(errors, DatabasePlacementError{Code: DatabasePlacementErrorCodePartitionRegionExtra,
					Region: &placement.Region, Partition: &partition.Partition})
				regionsComplete = false
			}
		}
	}

	backupQualified := databasePlacementEvaluateBackup(request.Backup, activeKeys, &errors)
	databasePlacementAddFacts(&facts, true, activeRegionCountValid, uniqueRegions, catalogQualified,
		partitionsPresent, regionsComplete, replicasExact, domainsIndependent, backupQualified)
	return databasePlacementFinish(errors, facts)
}

func databasePlacementOrderedRegions(regions []RegionCode) []RegionCode {
	ordered := make([]RegionCode, len(regions))
	copy(ordered, regions)
	sort.SliceStable(ordered, func(i, j int) bool {
		return databasePlacementKey(ordered[i].Value()) < databasePlacementKey(ordered[j].Value())
	})
	return ordered
}

func databasePlacementEvaluateSeats(placement *PartitionRegionPlacement, partition PartitionId, region RegionCode,
	errors *[]DatabasePlacementError, replicasExact, domainsIndependent *bool) {
	seats := placement.Seats
	if len(seats) < DatabasePlacementPolicyActiveReplicationFactor {
		detail := strconv.Itoa(len(seats))
		*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeSeatMissing,
			Region: &region, Partition: &partition, Detail: &detail})
		*replicasExact = false
	} else if len(seats) > DatabasePlacementPolicyActiveReplicationFactor {
		detail := strconv.Itoa(len(seats))
		*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeSeatExtra,
			Region: &region, Partition: &partition, Detail: &detail})
		*replicasExact = false
	}

	var concrete []ActiveMemberSeat
	for _, seat := range seats {
		if seat == nil {
			*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeSeatNull,
				Region: &region, Partition: &partition})
			*replicasExact = false
			*domainsIndependent = false
			continue
		}
		concrete = append(concrete, *seat)
		if isNullOrWhiteSpace(seat.Member.Value) {
			*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeSeatIdMissing,
				Region: &region, Partition: &partition, Member: &seat.Member})
			*replicasExact = false
		}
		if databasePlacementKey(seat.Region.Value()) != databasePlacementKey(region.Value()) {
			*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeSeatRegionMismatch,
				Region: &region, Partition: &partition, Member: &seat.Member})
			*replicasExact = false
		}
		if databasePlacementKey(seat.Partition.Value) != databasePlacementKey(partition.Value) {
			*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeSeatPartitionMismatch,
				Region: &region, Partition: &partition, Member: &seat.Member})
			*replicasExact = false
		}
		if !seat.IsActive {
			*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeSeatInactive,
				Region: &region, Partition: &partition, Member: &seat.Member})
			*replicasExact = false
			*domainsIndependent = false
		}
		if isNullOrWhiteSpace(seat.FailureDomain.Value) {
			*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeFailureDomainMissing,
				Region: &region, Partition: &partition, Member: &seat.Member})
			*replicasExact = false
			*domainsIndependent = false
		}
	}

	memberGroups := map[string][]ActiveMemberSeat{}
	for _, seat := range concrete {
		key := databasePlacementKey(seat.Member.Value)
		memberGroups[key] = append(memberGroups[key], seat)
	}
	memberKeys := make([]string, 0, len(memberGroups))
	for key := range memberGroups {
		memberKeys = append(memberKeys, key)
	}
	sort.Strings(memberKeys)
	for _, key := range memberKeys {
		group := memberGroups[key]
		if len(group) > 1 {
			sort.SliceStable(group, func(i, j int) bool {
				return group[i].Member.Value < group[j].Member.Value
			})
			*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeDuplicateSeat,
				Region: &region, Partition: &partition, Member: &group[0].Member})
			*replicasExact = false
		}
	}

	var activeDomains []string
	for _, seat := range concrete {
		if seat.IsActive && !isNullOrWhiteSpace(seat.FailureDomain.Value) {
			activeDomains = append(activeDomains, databasePlacementKey(seat.FailureDomain.Value))
		}
	}
	distinctDomains := map[string]struct{}{}
	for _, domain := range activeDomains {
		distinctDomains[domain] = struct{}{}
	}
	if len(distinctDomains) != len(activeDomains) {
		*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeFailureDomainNotIndependent,
			Region: &region, Partition: &partition})
		*domainsIndependent = false
	}
}

func databasePlacementEvaluateBackup(backup *BackupPlacement, activeKeys []string,
	errors *[]DatabasePlacementError) bool {
	if backup == nil {
		return true
	}
	qualified := true
	if isNullOrWhiteSpace(backup.Backup.Value) {
		*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeBackupIdMissing})
		qualified = false
	}
	if isNullOrWhiteSpace(backup.Region.Value()) {
		*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeBackupRegionMissing})
		qualified = false
	}
	for _, key := range activeKeys {
		if key == databasePlacementKey(backup.Region.Value()) {
			*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeBackupOverlapsActiveRegion,
				Region: &backup.Region})
			qualified = false
			break
		}
	}
	if !backup.IsReadOnly {
		*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeBackupMustBeReadOnly,
			Region: &backup.Region})
		qualified = false
	}
	if !backup.IsImmutable {
		*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeBackupMustBeImmutable,
			Region: &backup.Region})
		qualified = false
	}
	if backup.IsVoting {
		*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeBackupMustBeNonVoting,
			Region: &backup.Region})
		qualified = false
	}
	if backup.PromotionPolicy != BackupPromotionPolicyNeverPromote {
		*errors = append(*errors, DatabasePlacementError{Code: DatabasePlacementErrorCodeBackupPromotionForbidden,
			Region: &backup.Region})
		qualified = false
	}
	return qualified
}

func databasePlacementAddFacts(facts *[]DatabasePlacementQualificationFact, requestPresent, regionCount,
	uniqueRegions, catalogQualified, partitionsPresent, regionsComplete, replicasExact, domainsIndependent,
	backupQualified bool) {
	*facts = append(*facts,
		DatabasePlacementQualificationFact{DatabasePlacementFactCodeRequestPresent, requestPresent},
		DatabasePlacementQualificationFact{DatabasePlacementFactCodeActiveRegionCountWithinBounds, regionCount},
		DatabasePlacementQualificationFact{DatabasePlacementFactCodeActiveRegionsUnique, uniqueRegions},
		DatabasePlacementQualificationFact{DatabasePlacementFactCodeActiveRegionsCatalogQualified, catalogQualified},
		DatabasePlacementQualificationFact{DatabasePlacementFactCodeLogicalPartitionsPresent, partitionsPresent},
		DatabasePlacementQualificationFact{DatabasePlacementFactCodeEveryPartitionHasExactlySelectedRegions, regionsComplete},
		DatabasePlacementQualificationFact{DatabasePlacementFactCodeEveryPartitionHasExactReplicationFactor, replicasExact},
		DatabasePlacementQualificationFact{DatabasePlacementFactCodeSeatsIndependentlyFailureDomainPlaced, domainsIndependent},
		DatabasePlacementQualificationFact{DatabasePlacementFactCodeBackupPolicyQualified, backupQualified})
}

func databasePlacementFinish(errors []DatabasePlacementError, facts []DatabasePlacementQualificationFact) *DatabasePlacementDecision {
	ordered := make([]DatabasePlacementError, len(errors))
	copy(ordered, errors)
	sort.SliceStable(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if databasePlacementErrorKeyRegion(left) != databasePlacementErrorKeyRegion(right) {
			return databasePlacementErrorKeyRegion(left) < databasePlacementErrorKeyRegion(right)
		}
		if databasePlacementErrorKeyPartition(left) != databasePlacementErrorKeyPartition(right) {
			return databasePlacementErrorKeyPartition(left) < databasePlacementErrorKeyPartition(right)
		}
		if databasePlacementErrorKeyMember(left) != databasePlacementErrorKeyMember(right) {
			return databasePlacementErrorKeyMember(left) < databasePlacementErrorKeyMember(right)
		}
		return databasePlacementErrorDetail(left) < databasePlacementErrorDetail(right)
	})
	var builder strings.Builder
	builder.WriteString("accepted=")
	if len(ordered) == 0 {
		builder.WriteByte('1')
	} else {
		builder.WriteByte('0')
	}
	for _, err := range ordered {
		builder.WriteByte('|')
		builder.WriteString(strconv.Itoa(int(err.Code)))
		builder.WriteByte(':')
		builder.WriteString(databasePlacementErrorKeyRegion(err))
		builder.WriteByte(':')
		builder.WriteString(databasePlacementErrorKeyPartition(err))
		builder.WriteByte(':')
		builder.WriteString(databasePlacementErrorKeyMember(err))
		builder.WriteByte(':')
		builder.WriteString(databasePlacementErrorDetail(err))
	}
	for _, fact := range facts {
		builder.WriteByte('|')
		builder.WriteString(strconv.Itoa(int(fact.Code)))
		builder.WriteByte('=')
		if fact.Satisfied {
			builder.WriteByte('1')
		} else {
			builder.WriteByte('0')
		}
	}
	return &DatabasePlacementDecision{Errors: ordered, Facts: facts, Fingerprint: builder.String()}
}

func databasePlacementKey(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func databasePlacementErrorKeyRegion(err DatabasePlacementError) string {
	if err.Region == nil {
		return ""
	}
	return databasePlacementKey(err.Region.Value())
}

func databasePlacementErrorKeyPartition(err DatabasePlacementError) string {
	if err.Partition == nil {
		return ""
	}
	return databasePlacementKey(err.Partition.Value)
}

func databasePlacementErrorKeyMember(err DatabasePlacementError) string {
	if err.Member == nil {
		return ""
	}
	return databasePlacementKey(err.Member.Value)
}

func databasePlacementErrorDetail(err DatabasePlacementError) string {
	if err.Detail == nil {
		return ""
	}
	return *err.Detail
}
