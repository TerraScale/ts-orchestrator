package engines

import "sort"

type BudgetEmergencyPosture int

const (
	BudgetEmergencyPostureUnspecified BudgetEmergencyPosture = 0
	BudgetEmergencyPostureNormal      BudgetEmergencyPosture = 1
	BudgetEmergencyPostureEmergency   BudgetEmergencyPosture = 2
)

type BudgetSafetyPurpose int

const (
	BudgetSafetyPurposeUnspecified                        BudgetSafetyPurpose = 0
	BudgetSafetyPurposeOrdinaryCapacity                   BudgetSafetyPurpose = 1
	BudgetSafetyPurposeAvailabilityRepair                 BudgetSafetyPurpose = 2
	BudgetSafetyPurposeDataLossPreventionStorageExpansion BudgetSafetyPurpose = 3
)

type BudgetChangeDirection int

const (
	BudgetChangeDirectionUnspecified BudgetChangeDirection = 0
	BudgetChangeDirectionIncrease    BudgetChangeDirection = 1
	BudgetChangeDirectionDecrease    BudgetChangeDirection = 2
)

type NodeClassCapacityPolicy struct {
	NodeClass BudgetNodeClassId
	Minimum   int
	Maximum   int
	Warm      int
}

func (p NodeClassCapacityPolicy) IsValid() bool {
	return p.NodeClass.IsValid() && p.Minimum >= 0 && p.Maximum >= p.Minimum &&
		p.Warm >= p.Minimum && p.Warm <= p.Maximum
}

type BudgetBandPolicy struct {
	AutomaticCellMaximum   BudgetVector
	AutomaticGlobalMaximum BudgetVector
	ApprovalCellMaximum    BudgetVector
	ApprovalGlobalMaximum  BudgetVector
}

func (p BudgetBandPolicy) IsValid() bool {
	return p.AutomaticCellMaximum.IsValid() && p.AutomaticGlobalMaximum.IsValid() &&
		p.ApprovalCellMaximum.IsValid() && p.ApprovalGlobalMaximum.IsValid() &&
		p.AutomaticCellMaximum.ExceededBy(p.ApprovalCellMaximum) == BudgetDimensionNone &&
		p.AutomaticGlobalMaximum.ExceededBy(p.ApprovalGlobalMaximum) == BudgetDimensionNone
}

type BudgetPolicyError int

const (
	BudgetPolicyErrorUninitialized              BudgetPolicyError = 0
	BudgetPolicyErrorNone                       BudgetPolicyError = 1
	BudgetPolicyErrorInvalidScope               BudgetPolicyError = 2
	BudgetPolicyErrorInvalidPosture             BudgetPolicyError = 3
	BudgetPolicyErrorInvalidEvidenceLimit       BudgetPolicyError = 4
	BudgetPolicyErrorMissingNodeClassPolicy     BudgetPolicyError = 5
	BudgetPolicyErrorInvalidNodeClassPolicy     BudgetPolicyError = 6
	BudgetPolicyErrorDuplicateNodeClassPolicy   BudgetPolicyError = 7
	BudgetPolicyErrorInvalidCeiling             BudgetPolicyError = 8
	BudgetPolicyErrorInvalidBandOrdering        BudgetPolicyError = 9
	BudgetPolicyErrorBudgetExceedsProviderLimit BudgetPolicyError = 10
)

type BudgetPolicy struct {
	Cell                       BudgetCellId
	CostCenter                 BudgetCostCenterId
	ApprovalScope              BudgetApprovalId
	EmergencyPosture           BudgetEmergencyPosture
	MaximumEvidenceAge         BudgetQuantity
	MaximumEvidenceCount       int
	NodeClasses                []NodeClassCapacityPolicy
	CellCeiling                BudgetVector
	GlobalCeiling              BudgetVector
	ProviderAccountCellLimit   BudgetVector
	ProviderAccountGlobalLimit BudgetVector
	Bands                      BudgetBandPolicy
}

// BudgetPolicyTryCreate mirrors BudgetPolicy.TryCreate.
func BudgetPolicyTryCreate(
	cell BudgetCellId,
	costCenter BudgetCostCenterId,
	approvalScope BudgetApprovalId,
	emergencyPosture BudgetEmergencyPosture,
	maximumEvidenceAge BudgetQuantity,
	maximumEvidenceCount int,
	nodeClasses []NodeClassCapacityPolicy,
	cellCeiling *BudgetVector,
	globalCeiling *BudgetVector,
	providerAccountCellLimit *BudgetVector,
	providerAccountGlobalLimit *BudgetVector,
	bands *BudgetBandPolicy) (*BudgetPolicy, BudgetPolicyError) {
	if !cell.IsValid() || !costCenter.IsValid() || !approvalScope.IsValid() {
		return nil, BudgetPolicyErrorInvalidScope
	}
	if emergencyPosture != BudgetEmergencyPostureNormal && emergencyPosture != BudgetEmergencyPostureEmergency {
		return nil, BudgetPolicyErrorInvalidPosture
	}
	if maximumEvidenceCount <= 0 {
		return nil, BudgetPolicyErrorInvalidEvidenceLimit
	}

	if nodeClasses == nil {
		return nil, BudgetPolicyErrorMissingNodeClassPolicy
	}
	limits := maximumEvidenceCount
	if BudgetTechnicalInputLimitsMaximumNodeClassPolicyCount < limits {
		limits = BudgetTechnicalInputLimitsMaximumNodeClassPolicyCount
	}
	nodeClassSnapshot, ok := budgetInputSnapshotTryCopy(nodeClasses, limits)
	if !ok {
		return nil, BudgetPolicyErrorInvalidEvidenceLimit
	}
	var collected []NodeClassCapacityPolicy
	seen := make(map[BudgetNodeClassId]struct{})
	for _, nodeClass := range nodeClassSnapshot {
		if len(collected) >= maximumEvidenceCount {
			return nil, BudgetPolicyErrorInvalidEvidenceLimit
		}
		if !nodeClass.IsValid() {
			return nil, BudgetPolicyErrorInvalidNodeClassPolicy
		}
		if _, duplicate := seen[nodeClass.NodeClass]; duplicate {
			return nil, BudgetPolicyErrorDuplicateNodeClassPolicy
		}
		seen[nodeClass.NodeClass] = struct{}{}
		collected = append(collected, nodeClass)
	}
	if len(collected) == 0 {
		return nil, BudgetPolicyErrorMissingNodeClassPolicy
	}

	if cellCeiling == nil || !cellCeiling.IsValid() || globalCeiling == nil || !globalCeiling.IsValid() ||
		providerAccountCellLimit == nil || !providerAccountCellLimit.IsValid() ||
		providerAccountGlobalLimit == nil || !providerAccountGlobalLimit.IsValid() {
		return nil, BudgetPolicyErrorInvalidCeiling
	}
	if bands == nil || !bands.IsValid() ||
		bands.ApprovalCellMaximum.ExceededBy(*cellCeiling) != BudgetDimensionNone ||
		bands.ApprovalGlobalMaximum.ExceededBy(*globalCeiling) != BudgetDimensionNone {
		return nil, BudgetPolicyErrorInvalidBandOrdering
	}
	if cellCeiling.ExceededBy(*providerAccountCellLimit) != BudgetDimensionNone ||
		globalCeiling.ExceededBy(*providerAccountGlobalLimit) != BudgetDimensionNone {
		return nil, BudgetPolicyErrorBudgetExceedsProviderLimit
	}

	array := make([]NodeClassCapacityPolicy, len(collected))
	copy(array, collected)
	sort.Slice(array, func(i, j int) bool {
		return array[i].NodeClass.Value < array[j].NodeClass.Value
	})
	return &BudgetPolicy{cell, costCenter, approvalScope, emergencyPosture, maximumEvidenceAge,
		maximumEvidenceCount, array, *cellCeiling, *globalCeiling, *providerAccountCellLimit,
		*providerAccountGlobalLimit, *bands}, BudgetPolicyErrorNone
}

// Find ports the internal node-class lookup.
func (p *BudgetPolicy) Find(nodeClass BudgetNodeClassId) *NodeClassCapacityPolicy {
	for index := range p.NodeClasses {
		if p.NodeClasses[index].NodeClass == nodeClass {
			return &p.NodeClasses[index]
		}
	}
	return nil
}
