package engines

type BudgetEvidenceStatus int

const (
	BudgetEvidenceStatusUnknown BudgetEvidenceStatus = 0
	BudgetEvidenceStatusCurrent BudgetEvidenceStatus = 1
	BudgetEvidenceStatusStale   BudgetEvidenceStatus = 2
)

type BudgetUsageScope int

const (
	BudgetUsageScopeUnspecified BudgetUsageScope = 0
	BudgetUsageScopeCell        BudgetUsageScope = 1
	BudgetUsageScopeGlobal      BudgetUsageScope = 2
)

type BudgetUsageObservation struct {
	Scope      BudgetUsageScope
	Cell       BudgetCellId
	CostCenter BudgetCostCenterId
	EvidenceId PriceEvidenceId
	Status     BudgetEvidenceStatus
	Age        BudgetQuantity
	Usage      BudgetVector
}

type NodeClassUsageObservation struct {
	Cell         BudgetCellId
	CostCenter   BudgetCostCenterId
	NodeClass    BudgetNodeClassId
	EvidenceId   PriceEvidenceId
	Status       BudgetEvidenceStatus
	Age          BudgetQuantity
	CurrentCount int
}

type PriceEvidenceObservation struct {
	EvidenceId PriceEvidenceId
	CostCenter BudgetCostCenterId
	Status     BudgetEvidenceStatus
	Age        BudgetQuantity
}

type BudgetProposal struct {
	Resource      BudgetResourceId
	Cell          BudgetCellId
	CostCenter    BudgetCostCenterId
	NodeClass     BudgetNodeClassId
	PriceEvidence PriceEvidenceId
	Direction     BudgetChangeDirection
	Purpose       BudgetSafetyPurpose
	NodeCount     int
	Delta         BudgetVector
}

func (p BudgetProposal) IsWellFormed() bool {
	zero := p.NodeCount > 0 || !p.Delta.Equal(BudgetVectorZero)
	return p.Resource.IsValid() && p.Cell.IsValid() && p.CostCenter.IsValid() && p.NodeClass.IsValid() &&
		p.PriceEvidence.IsValid() &&
		(p.Direction == BudgetChangeDirectionIncrease || p.Direction == BudgetChangeDirectionDecrease) &&
		(p.Purpose == BudgetSafetyPurposeOrdinaryCapacity ||
			p.Purpose == BudgetSafetyPurposeAvailabilityRepair ||
			p.Purpose == BudgetSafetyPurposeDataLossPreventionStorageExpansion) &&
		p.NodeCount >= 0 && p.Delta.IsValid() && zero
}
