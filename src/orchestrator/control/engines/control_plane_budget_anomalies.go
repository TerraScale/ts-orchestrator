package engines

import "sort"

type BudgetResourceAttachment int

const (
	BudgetResourceAttachmentUnspecified   BudgetResourceAttachment = 0
	BudgetResourceAttachmentNotApplicable BudgetResourceAttachment = 1
	BudgetResourceAttachmentAttached      BudgetResourceAttachment = 2
	BudgetResourceAttachmentUnattached    BudgetResourceAttachment = 3
)

func budgetResourceAttachmentIsDefined(value BudgetResourceAttachment) bool {
	return value >= BudgetResourceAttachmentNotApplicable && value <= BudgetResourceAttachmentUnattached
}

type BudgetResourceObservation struct {
	Resource   BudgetResourceId
	Cell       BudgetCellId
	CostCenter BudgetCostCenterId
	EvidenceId PriceEvidenceId
	Status     BudgetEvidenceStatus
	Age        BudgetQuantity
	Desired    bool
	Owned      bool
	Billed     bool
	Attachment BudgetResourceAttachment
}

type BudgetAnomalyKind int

const (
	BudgetAnomalyKindOrphanedOwnedResource           BudgetAnomalyKind = 1
	BudgetAnomalyKindUnattachedResource              BudgetAnomalyKind = 2
	BudgetAnomalyKindDesiredResourceMissing          BudgetAnomalyKind = 3
	BudgetAnomalyKindBillingWithoutOwnedResource     BudgetAnomalyKind = 4
	BudgetAnomalyKindOwnedResourceMissingFromBilling BudgetAnomalyKind = 5
)

type BudgetAnomalyFinding struct {
	Resource BudgetResourceId
	Kind     BudgetAnomalyKind
}

type BudgetAnomalyError int

const (
	BudgetAnomalyErrorUninitialized        BudgetAnomalyError = 0
	BudgetAnomalyErrorNone                 BudgetAnomalyError = 1
	BudgetAnomalyErrorInvalidScope         BudgetAnomalyError = 2
	BudgetAnomalyErrorInvalidEvidenceLimit BudgetAnomalyError = 3
	BudgetAnomalyErrorMissingEvidence      BudgetAnomalyError = 4
	BudgetAnomalyErrorUnknownEvidence      BudgetAnomalyError = 5
	BudgetAnomalyErrorStaleEvidence        BudgetAnomalyError = 6
	BudgetAnomalyErrorDuplicateEvidence    BudgetAnomalyError = 7
	BudgetAnomalyErrorConflictingEvidence  BudgetAnomalyError = 8
)

type BudgetAnomalyResult struct {
	Error    BudgetAnomalyError
	Findings []BudgetAnomalyFinding
}

func (r BudgetAnomalyResult) IsComplete() bool { return r.Error == BudgetAnomalyErrorNone }

var BudgetAnomalyDetector budgetAnomalyDetector

type budgetAnomalyDetector struct{}

func (budgetAnomalyDetector) Detect(
	expectedCell BudgetCellId,
	expectedCostCenter BudgetCostCenterId,
	maximumEvidenceCount int,
	maximumEvidenceAge BudgetQuantity,
	inventoryComplete bool,
	source []BudgetResourceObservation) BudgetAnomalyResult {
	if !expectedCell.IsValid() || !expectedCostCenter.IsValid() {
		return budgetAnomalyError(BudgetAnomalyErrorInvalidScope)
	}
	if maximumEvidenceCount <= 0 {
		return budgetAnomalyError(BudgetAnomalyErrorInvalidEvidenceLimit)
	}
	if !inventoryComplete || source == nil {
		return budgetAnomalyError(BudgetAnomalyErrorMissingEvidence)
	}

	limits := maximumEvidenceCount
	if BudgetTechnicalInputLimitsMaximumEvidenceCount < limits {
		limits = BudgetTechnicalInputLimitsMaximumEvidenceCount
	}
	observationSnapshot, ok := budgetInputSnapshotTryCopy(source, limits)
	if !ok {
		return budgetAnomalyError(BudgetAnomalyErrorInvalidEvidenceLimit)
	}
	var observations []BudgetResourceObservation
	for _, item := range observationSnapshot {
		if len(observations) >= maximumEvidenceCount {
			return budgetAnomalyError(BudgetAnomalyErrorInvalidEvidenceLimit)
		}
		if !item.Resource.IsValid() || !item.EvidenceId.IsValid() ||
			item.Attachment == BudgetResourceAttachmentUnspecified ||
			!budgetResourceAttachmentIsDefined(item.Attachment) {
			return budgetAnomalyError(BudgetAnomalyErrorConflictingEvidence)
		}
		if item.Cell != expectedCell || item.CostCenter != expectedCostCenter {
			return budgetAnomalyError(BudgetAnomalyErrorInvalidScope)
		}
		observations = append(observations, item)
	}

	grouped := make(map[BudgetResourceId][]BudgetResourceObservation)
	for _, item := range observations {
		grouped[item.Resource] = append(grouped[item.Resource], item)
	}
	duplicate := false
	for _, group := range grouped {
		if len(group) <= 1 {
			continue
		}
		first := group[0]
		for _, item := range group {
			if !budgetAnomalySame(first, item) {
				return budgetAnomalyError(BudgetAnomalyErrorConflictingEvidence)
			}
		}
		duplicate = true
	}
	if duplicate {
		return budgetAnomalyError(BudgetAnomalyErrorDuplicateEvidence)
	}
	for _, item := range observations {
		if item.Status == BudgetEvidenceStatusUnknown {
			return budgetAnomalyError(BudgetAnomalyErrorUnknownEvidence)
		}
	}
	for _, item := range observations {
		if item.Status == BudgetEvidenceStatusStale {
			return budgetAnomalyError(BudgetAnomalyErrorStaleEvidence)
		}
	}
	for _, item := range observations {
		if item.Age.Value > maximumEvidenceAge.Value {
			return budgetAnomalyError(BudgetAnomalyErrorStaleEvidence)
		}
	}
	for _, item := range observations {
		if item.Status != BudgetEvidenceStatusCurrent {
			return budgetAnomalyError(BudgetAnomalyErrorUnknownEvidence)
		}
	}

	ordered := make([]BudgetResourceObservation, len(observations))
	copy(ordered, observations)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Resource.Value < ordered[j].Resource.Value
	})
	var findings []BudgetAnomalyFinding
	for _, item := range ordered {
		if item.Owned && !item.Desired {
			findings = append(findings, BudgetAnomalyFinding{item.Resource, BudgetAnomalyKindOrphanedOwnedResource})
		}
		if item.Owned && item.Attachment == BudgetResourceAttachmentUnattached {
			findings = append(findings, BudgetAnomalyFinding{item.Resource, BudgetAnomalyKindUnattachedResource})
		}
		if item.Desired && !item.Owned {
			findings = append(findings, BudgetAnomalyFinding{item.Resource, BudgetAnomalyKindDesiredResourceMissing})
		}
		if item.Billed && !item.Owned {
			findings = append(findings, BudgetAnomalyFinding{item.Resource, BudgetAnomalyKindBillingWithoutOwnedResource})
		}
		if item.Owned && !item.Billed {
			findings = append(findings, BudgetAnomalyFinding{item.Resource, BudgetAnomalyKindOwnedResourceMissingFromBilling})
		}
	}
	if findings == nil {
		findings = []BudgetAnomalyFinding{}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Resource.Value != findings[j].Resource.Value {
			return findings[i].Resource.Value < findings[j].Resource.Value
		}
		return findings[i].Kind < findings[j].Kind
	})
	return BudgetAnomalyResult{Error: BudgetAnomalyErrorNone, Findings: findings}
}

func budgetAnomalyError(err BudgetAnomalyError) BudgetAnomalyResult {
	return BudgetAnomalyResult{Error: err, Findings: []BudgetAnomalyFinding{}}
}

func budgetAnomalySame(left, right BudgetResourceObservation) bool {
	return left.Resource == right.Resource && left.Cell == right.Cell && left.CostCenter == right.CostCenter &&
		left.EvidenceId == right.EvidenceId && left.Status == right.Status && left.Age == right.Age &&
		left.Desired == right.Desired && left.Owned == right.Owned && left.Billed == right.Billed &&
		left.Attachment == right.Attachment
}
