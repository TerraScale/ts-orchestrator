package control

type BudgetDecisionKind int

const (
	BudgetDecisionKindUninitialized    BudgetDecisionKind = 0
	BudgetDecisionKindAutomatic        BudgetDecisionKind = 1
	BudgetDecisionKindApprovalRequired BudgetDecisionKind = 2
	BudgetDecisionKindForbidden        BudgetDecisionKind = 3
	BudgetDecisionKindHeld             BudgetDecisionKind = 4
)

type BudgetDecisionReason int

const (
	BudgetDecisionReasonUninitialized                BudgetDecisionReason = 0
	BudgetDecisionReasonWithinAutomaticBand          BudgetDecisionReason = 1
	BudgetDecisionReasonWarmCapacityProtection       BudgetDecisionReason = 2
	BudgetDecisionReasonApprovalBand                 BudgetDecisionReason = 3
	BudgetDecisionReasonForbiddenBand                BudgetDecisionReason = 4
	BudgetDecisionReasonBudgetCeilingExceeded        BudgetDecisionReason = 5
	BudgetDecisionReasonProviderAccountLimitExceeded BudgetDecisionReason = 6
	BudgetDecisionReasonNodeClassMinimumViolated     BudgetDecisionReason = 7
	BudgetDecisionReasonNodeClassMaximumExceeded     BudgetDecisionReason = 8
	BudgetDecisionReasonEmergencyNonSafetyGrowth     BudgetDecisionReason = 9
	BudgetDecisionReasonEmergencyDecreaseHeld        BudgetDecisionReason = 10
	BudgetDecisionReasonEmergencyDataLossPrevention  BudgetDecisionReason = 11
	BudgetDecisionReasonInvalidPolicy                BudgetDecisionReason = 12
	BudgetDecisionReasonMalformedProposal            BudgetDecisionReason = 13
	BudgetDecisionReasonWrongScope                   BudgetDecisionReason = 14
	BudgetDecisionReasonUnknownNodeClass             BudgetDecisionReason = 15
	BudgetDecisionReasonMissingEvidence              BudgetDecisionReason = 16
	BudgetDecisionReasonUnknownEvidence              BudgetDecisionReason = 17
	BudgetDecisionReasonStaleEvidence                BudgetDecisionReason = 18
	BudgetDecisionReasonDuplicateEvidence            BudgetDecisionReason = 19
	BudgetDecisionReasonConflictingEvidence          BudgetDecisionReason = 20
	BudgetDecisionReasonEvidenceLimitExceeded        BudgetDecisionReason = 21
	BudgetDecisionReasonArithmeticOverflow           BudgetDecisionReason = 22
	BudgetDecisionReasonArithmeticUnderflow          BudgetDecisionReason = 23
	BudgetDecisionReasonInvalidEmergencySafetyClaim  BudgetDecisionReason = 24
)

type BudgetApprovalScope struct {
	ApprovalId BudgetApprovalId
	Cell       BudgetCellId
	CostCenter BudgetCostCenterId
	NodeClass  BudgetNodeClassId
	Resource   BudgetResourceId
	Purpose    BudgetSafetyPurpose
}

type BudgetDecisionSubject struct {
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

type BudgetDecisionBasis struct {
	Policy        *BudgetPolicy
	CellUsage     BudgetUsageObservation
	GlobalUsage   BudgetUsageObservation
	NodeUsage     NodeClassUsageObservation
	PriceEvidence PriceEvidenceObservation
}

type BudgetDecisionTrace struct {
	CurrentCell                BudgetVector
	ProjectedCell              BudgetVector
	CurrentGlobal              BudgetVector
	ProjectedGlobal            BudgetVector
	Delta                      BudgetVector
	AutomaticCellMaximum       BudgetVector
	AutomaticGlobalMaximum     BudgetVector
	ApprovalCellMaximum        BudgetVector
	ApprovalGlobalMaximum      BudgetVector
	CellCeiling                BudgetVector
	GlobalCeiling              BudgetVector
	ProviderAccountCellLimit   BudgetVector
	ProviderAccountGlobalLimit BudgetVector
	CurrentNodeCount           int
	ProjectedNodeCount         int
	MinimumNodeCount           int
	WarmNodeCount              int
	MaximumNodeCount           int
	MaximumEvidenceAge         BudgetQuantity
	CellEvidenceAge            BudgetQuantity
	GlobalEvidenceAge          BudgetQuantity
	NodeEvidenceAge            BudgetQuantity
	PriceEvidenceAge           BudgetQuantity
	BindingDimensions          BudgetDimension
}

type BudgetDecision struct {
	Kind          BudgetDecisionKind
	Reason        BudgetDecisionReason
	Trace         *BudgetDecisionTrace
	Subject       *BudgetDecisionSubject
	Basis         *BudgetDecisionBasis
	ApprovalScope *BudgetApprovalScope
}

func (d BudgetDecision) IsAuthorized() bool { return d.Kind == BudgetDecisionKindAutomatic }

func budgetDecisionHeld(reason BudgetDecisionReason) BudgetDecision {
	return BudgetDecision{Kind: BudgetDecisionKindHeld, Reason: reason}
}

func budgetDecisionCreate(kind BudgetDecisionKind, reason BudgetDecisionReason, trace BudgetDecisionTrace,
	proposal BudgetProposal, basis *BudgetDecisionBasis, approvalScope *BudgetApprovalScope) BudgetDecision {
	return BudgetDecision{Kind: kind, Reason: reason, Trace: &trace,
		Subject: &BudgetDecisionSubject{proposal.Resource, proposal.Cell, proposal.CostCenter,
			proposal.NodeClass, proposal.PriceEvidence, proposal.Direction, proposal.Purpose,
			proposal.NodeCount, proposal.Delta}, Basis: basis, ApprovalScope: approvalScope}
}

var BudgetAuthorizationEngine budgetAuthorizationEngine

type budgetAuthorizationEngine struct{}

func (budgetAuthorizationEngine) Evaluate(
	policy *BudgetPolicy,
	proposal *BudgetProposal,
	usageEvidence []BudgetUsageObservation,
	nodeEvidence []NodeClassUsageObservation,
	priceEvidence []PriceEvidenceObservation) BudgetDecision {
	if policy == nil {
		return budgetDecisionHeld(BudgetDecisionReasonInvalidPolicy)
	}
	if proposal == nil || !proposal.IsWellFormed() {
		return budgetDecisionHeld(BudgetDecisionReasonMalformedProposal)
	}
	if proposal.Cell != policy.Cell || proposal.CostCenter != policy.CostCenter {
		return budgetDecisionHeld(BudgetDecisionReasonWrongScope)
	}
	nodePolicy := policy.Find(proposal.NodeClass)
	if nodePolicy == nil {
		return budgetDecisionHeld(BudgetDecisionReasonUnknownNodeClass)
	}

	evidence := budgetCollectEvidence(policy, *proposal, usageEvidence, nodeEvidence, priceEvidence)
	if evidence.err != BudgetDecisionReasonUninitialized {
		return budgetDecisionHeld(evidence.err)
	}
	if evidence.cellUsage == nil || evidence.globalUsage == nil || evidence.nodeUsage == nil ||
		evidence.priceUsage == nil {
		return budgetDecisionHeld(BudgetDecisionReasonMissingEvidence)
	}
	cellUsage, globalUsage, nodeUsage, priceUsage := *evidence.cellUsage, *evidence.globalUsage,
		*evidence.nodeUsage, *evidence.priceUsage

	add := proposal.Direction == BudgetChangeDirectionIncrease
	projectedCell, cellCombined := combineBudgetVector(cellUsage.Usage, proposal.Delta, add)
	projectedGlobal, globalCombined := combineBudgetVector(globalUsage.Usage, proposal.Delta, add)
	if !cellCombined || !globalCombined {
		if add {
			return budgetDecisionHeld(BudgetDecisionReasonArithmeticOverflow)
		}
		return budgetDecisionHeld(BudgetDecisionReasonArithmeticUnderflow)
	}

	projectedNodes, nodesOk := checkedAddInt64(int64(nodeUsage.CurrentCount), int64(proposal.NodeCount))
	if add {
		if !nodesOk {
			return budgetDecisionHeld(BudgetDecisionReasonArithmeticOverflow)
		}
	} else {
		difference := int64(nodeUsage.CurrentCount) - int64(proposal.NodeCount)
		if (int64(proposal.NodeCount) > 0 && difference > int64(nodeUsage.CurrentCount)) ||
			(int64(proposal.NodeCount) < 0 && difference < int64(nodeUsage.CurrentCount)) {
			return budgetDecisionHeld(BudgetDecisionReasonArithmeticUnderflow)
		}
		projectedNodes = difference
	}
	if !add {
		// checked subtract already validated above
		_ = nodesOk
	}
	if projectedNodes < 0 {
		return budgetDecisionHeld(BudgetDecisionReasonArithmeticUnderflow)
	}

	providerExceeded := projectedCell.ExceededBy(policy.ProviderAccountCellLimit) |
		projectedGlobal.ExceededBy(policy.ProviderAccountGlobalLimit)
	trace := BudgetDecisionTrace{
		CurrentCell: cellUsage.Usage, ProjectedCell: projectedCell, CurrentGlobal: globalUsage.Usage,
		ProjectedGlobal: projectedGlobal, Delta: proposal.Delta,
		AutomaticCellMaximum:   policy.Bands.AutomaticCellMaximum,
		AutomaticGlobalMaximum: policy.Bands.AutomaticGlobalMaximum,
		ApprovalCellMaximum:    policy.Bands.ApprovalCellMaximum,
		ApprovalGlobalMaximum:  policy.Bands.ApprovalGlobalMaximum,
		CellCeiling:            policy.CellCeiling, GlobalCeiling: policy.GlobalCeiling,
		ProviderAccountCellLimit:   policy.ProviderAccountCellLimit,
		ProviderAccountGlobalLimit: policy.ProviderAccountGlobalLimit,
		CurrentNodeCount:           nodeUsage.CurrentCount, ProjectedNodeCount: int(projectedNodes),
		MinimumNodeCount: nodePolicy.Minimum, WarmNodeCount: nodePolicy.Warm,
		MaximumNodeCount: nodePolicy.Maximum, MaximumEvidenceAge: policy.MaximumEvidenceAge,
		CellEvidenceAge: cellUsage.Age, GlobalEvidenceAge: globalUsage.Age,
		NodeEvidenceAge: nodeUsage.Age, PriceEvidenceAge: priceUsage.Age,
		BindingDimensions: providerExceeded,
	}
	basis := &BudgetDecisionBasis{policy, cellUsage, globalUsage, nodeUsage, priceUsage}
	if providerExceeded != BudgetDimensionNone {
		return budgetDecisionCreate(BudgetDecisionKindForbidden, BudgetDecisionReasonProviderAccountLimitExceeded,
			trace, *proposal, basis, nil)
	}

	if policy.EmergencyPosture == BudgetEmergencyPostureEmergency {
		if !add {
			return budgetDecisionCreate(BudgetDecisionKindHeld, BudgetDecisionReasonEmergencyDecreaseHeld,
				trace, *proposal, basis, nil)
		}
		if proposal.Purpose == BudgetSafetyPurposeDataLossPreventionStorageExpansion {
			if proposal.NodeCount != 0 || !proposal.Delta.IsStorageSafetyDomainIncrease() {
				return budgetDecisionCreate(BudgetDecisionKindHeld, BudgetDecisionReasonInvalidEmergencySafetyClaim,
					trace, *proposal, basis, nil)
			}
			return budgetDecisionCreate(BudgetDecisionKindAutomatic, BudgetDecisionReasonEmergencyDataLossPrevention,
				trace, *proposal, basis, nil)
		}
		if proposal.Purpose != BudgetSafetyPurposeAvailabilityRepair {
			return budgetDecisionCreate(BudgetDecisionKindForbidden, BudgetDecisionReasonEmergencyNonSafetyGrowth,
				trace, *proposal, basis, nil)
		}
	}

	if projectedNodes < int64(nodePolicy.Minimum) {
		return budgetDecisionCreate(BudgetDecisionKindForbidden, BudgetDecisionReasonNodeClassMinimumViolated,
			trace, *proposal, basis, nil)
	}
	if projectedNodes > int64(nodePolicy.Maximum) {
		return budgetDecisionCreate(BudgetDecisionKindForbidden, BudgetDecisionReasonNodeClassMaximumExceeded,
			trace, *proposal, basis, nil)
	}

	budgetExceeded := projectedCell.ExceededBy(policy.CellCeiling) |
		projectedGlobal.ExceededBy(policy.GlobalCeiling)
	if budgetExceeded != BudgetDimensionNone {
		trace.BindingDimensions = budgetExceeded
		return budgetDecisionCreate(BudgetDecisionKindForbidden, BudgetDecisionReasonBudgetCeilingExceeded,
			trace, *proposal, basis, nil)
	}

	approvalExceeded := projectedCell.ExceededBy(policy.Bands.ApprovalCellMaximum) |
		projectedGlobal.ExceededBy(policy.Bands.ApprovalGlobalMaximum)
	if approvalExceeded != BudgetDimensionNone {
		trace.BindingDimensions = approvalExceeded
		return budgetDecisionCreate(BudgetDecisionKindForbidden, BudgetDecisionReasonForbiddenBand,
			trace, *proposal, basis, nil)
	}

	automaticExceeded := projectedCell.ExceededBy(policy.Bands.AutomaticCellMaximum) |
		projectedGlobal.ExceededBy(policy.Bands.AutomaticGlobalMaximum)
	warmProtected := !add && projectedNodes < int64(nodePolicy.Warm)
	if automaticExceeded != BudgetDimensionNone || warmProtected {
		trace.BindingDimensions = automaticExceeded
		scope := &BudgetApprovalScope{policy.ApprovalScope, policy.Cell, policy.CostCenter,
			proposal.NodeClass, proposal.Resource, proposal.Purpose}
		reason := BudgetDecisionReasonApprovalBand
		if warmProtected {
			reason = BudgetDecisionReasonWarmCapacityProtection
		}
		return budgetDecisionCreate(BudgetDecisionKindApprovalRequired, reason, trace, *proposal, basis, scope)
	}

	return budgetDecisionCreate(BudgetDecisionKindAutomatic, BudgetDecisionReasonWithinAutomaticBand,
		trace, *proposal, basis, nil)
}

func combineBudgetVector(usage, delta BudgetVector, add bool) (BudgetVector, bool) {
	if add {
		return usage.TryAdd(delta)
	}
	return usage.TrySubtract(delta)
}

type budgetCollectedEvidence struct {
	err         BudgetDecisionReason
	cellUsage   *BudgetUsageObservation
	globalUsage *BudgetUsageObservation
	nodeUsage   *NodeClassUsageObservation
	priceUsage  *PriceEvidenceObservation
}

func budgetEvidenceError(err BudgetDecisionReason) budgetCollectedEvidence {
	return budgetCollectedEvidence{err: err}
}

func budgetCollectEvidence(policy *BudgetPolicy, proposal BudgetProposal,
	usageSource []BudgetUsageObservation, nodeSource []NodeClassUsageObservation,
	priceSource []PriceEvidenceObservation) budgetCollectedEvidence {
	if usageSource == nil || nodeSource == nil || priceSource == nil {
		return budgetEvidenceError(BudgetDecisionReasonMissingEvidence)
	}
	technicalMaximum := policy.MaximumEvidenceCount
	if BudgetTechnicalInputLimitsMaximumEvidenceCount < technicalMaximum {
		technicalMaximum = BudgetTechnicalInputLimitsMaximumEvidenceCount
	}
	usageSnapshot, usageOk := budgetInputSnapshotTryCopy(usageSource, technicalMaximum)
	if !usageOk {
		return budgetEvidenceError(BudgetDecisionReasonEvidenceLimitExceeded)
	}
	nodeSnapshot, nodeOk := budgetInputSnapshotTryCopy(nodeSource, technicalMaximum-len(usageSnapshot))
	if !nodeOk {
		return budgetEvidenceError(BudgetDecisionReasonEvidenceLimitExceeded)
	}
	priceSnapshot, priceOk := budgetInputSnapshotTryCopy(priceSource,
		technicalMaximum-len(usageSnapshot)-len(nodeSnapshot))
	if !priceOk {
		return budgetEvidenceError(BudgetDecisionReasonEvidenceLimitExceeded)
	}
	count := 0
	var usage []BudgetUsageObservation
	var nodes []NodeClassUsageObservation
	var prices []PriceEvidenceObservation
	for _, item := range usageSnapshot {
		take := budgetEvidenceTake(policy.MaximumEvidenceCount, &count)
		if take != BudgetDecisionReasonUninitialized {
			return budgetEvidenceError(take)
		}
		usage = append(usage, item)
	}
	for _, item := range nodeSnapshot {
		take := budgetEvidenceTake(policy.MaximumEvidenceCount, &count)
		if take != BudgetDecisionReasonUninitialized {
			return budgetEvidenceError(take)
		}
		nodes = append(nodes, item)
	}
	for _, item := range priceSnapshot {
		take := budgetEvidenceTake(policy.MaximumEvidenceCount, &count)
		if take != BudgetDecisionReasonUninitialized {
			return budgetEvidenceError(take)
		}
		prices = append(prices, item)
	}

	for _, item := range usage {
		if item.CostCenter != policy.CostCenter ||
			(item.Scope == BudgetUsageScopeCell && item.Cell != policy.Cell) ||
			(item.Scope == BudgetUsageScopeGlobal && item.Cell.IsValid()) ||
			(item.Scope != BudgetUsageScopeCell && item.Scope != BudgetUsageScopeGlobal) {
			return budgetEvidenceError(BudgetDecisionReasonWrongScope)
		}
	}
	for _, item := range nodes {
		if item.Cell != policy.Cell || item.CostCenter != policy.CostCenter {
			return budgetEvidenceError(BudgetDecisionReasonWrongScope)
		}
	}
	for _, item := range prices {
		if item.CostCenter != policy.CostCenter {
			return budgetEvidenceError(BudgetDecisionReasonWrongScope)
		}
	}
	for _, item := range usage {
		if !item.EvidenceId.IsValid() || !item.Usage.IsValid() {
			return budgetEvidenceError(BudgetDecisionReasonConflictingEvidence)
		}
	}
	for _, item := range nodes {
		if !item.NodeClass.IsValid() || !item.EvidenceId.IsValid() || item.CurrentCount < 0 {
			return budgetEvidenceError(BudgetDecisionReasonConflictingEvidence)
		}
	}
	for _, item := range prices {
		if !item.EvidenceId.IsValid() {
			return budgetEvidenceError(BudgetDecisionReasonConflictingEvidence)
		}
	}

	usageGroupError := budgetFindUsageGroupError(usage)
	nodeGroupError := budgetFindNodeGroupError(nodes)
	priceGroupError := budgetFindPriceGroupError(prices)
	for _, groupError := range []BudgetDecisionReason{usageGroupError, nodeGroupError, priceGroupError} {
		if groupError == BudgetDecisionReasonConflictingEvidence {
			return budgetEvidenceError(BudgetDecisionReasonConflictingEvidence)
		}
	}
	for _, groupError := range []BudgetDecisionReason{usageGroupError, nodeGroupError, priceGroupError} {
		if groupError == BudgetDecisionReasonDuplicateEvidence {
			return budgetEvidenceError(BudgetDecisionReasonDuplicateEvidence)
		}
	}

	cell, cellError := budgetSelectUsage(usage, BudgetUsageScopeCell)
	if cellError != BudgetDecisionReasonUninitialized {
		return budgetEvidenceError(cellError)
	}
	global, globalError := budgetSelectUsage(usage, BudgetUsageScopeGlobal)
	if globalError != BudgetDecisionReasonUninitialized {
		return budgetEvidenceError(globalError)
	}
	node, nodeError := budgetSelectNode(nodes, proposal.NodeClass)
	if nodeError != BudgetDecisionReasonUninitialized {
		return budgetEvidenceError(nodeError)
	}
	price, priceError := budgetSelectPrice(prices, proposal.PriceEvidence)
	if priceError != BudgetDecisionReasonUninitialized {
		return budgetEvidenceError(priceError)
	}

	allStatuses := make([]BudgetEvidenceStatus, 0, len(usage)+len(nodes)+len(prices))
	for _, item := range usage {
		allStatuses = append(allStatuses, item.Status)
	}
	for _, item := range nodes {
		allStatuses = append(allStatuses, item.Status)
	}
	for _, item := range prices {
		allStatuses = append(allStatuses, item.Status)
	}
	for _, status := range allStatuses {
		if status == BudgetEvidenceStatusUnknown {
			return budgetEvidenceError(BudgetDecisionReasonUnknownEvidence)
		}
	}
	for _, status := range allStatuses {
		if status == BudgetEvidenceStatusStale {
			return budgetEvidenceError(BudgetDecisionReasonStaleEvidence)
		}
	}
	for _, status := range allStatuses {
		if status != BudgetEvidenceStatusCurrent {
			return budgetEvidenceError(BudgetDecisionReasonUnknownEvidence)
		}
	}
	for _, item := range usage {
		if item.Age.Value > policy.MaximumEvidenceAge.Value {
			return budgetEvidenceError(BudgetDecisionReasonStaleEvidence)
		}
	}
	for _, item := range nodes {
		if item.Age.Value > policy.MaximumEvidenceAge.Value {
			return budgetEvidenceError(BudgetDecisionReasonStaleEvidence)
		}
	}
	for _, item := range prices {
		if item.Age.Value > policy.MaximumEvidenceAge.Value {
			return budgetEvidenceError(BudgetDecisionReasonStaleEvidence)
		}
	}
	return budgetCollectedEvidence{err: BudgetDecisionReasonUninitialized, cellUsage: cell,
		globalUsage: global, nodeUsage: node, priceUsage: price}
}

func budgetEvidenceTake(maximum int, count *int) BudgetDecisionReason {
	if *count >= maximum {
		return BudgetDecisionReasonEvidenceLimitExceeded
	}
	*count++
	return BudgetDecisionReasonUninitialized
}

func budgetSelectUsage(items []BudgetUsageObservation, scope BudgetUsageScope) (*BudgetUsageObservation, BudgetDecisionReason) {
	var matches []BudgetUsageObservation
	for _, item := range items {
		if item.Scope == scope {
			matches = append(matches, item)
		}
	}
	if len(matches) == 0 {
		return nil, BudgetDecisionReasonMissingEvidence
	}
	if len(matches) > 1 {
		allSame := true
		for _, item := range matches {
			if item.Status != matches[0].Status || item.EvidenceId != matches[0].EvidenceId ||
				item.Age != matches[0].Age || !item.Usage.Equal(matches[0].Usage) {
				allSame = false
				break
			}
		}
		if allSame {
			return nil, BudgetDecisionReasonDuplicateEvidence
		}
		return nil, BudgetDecisionReasonConflictingEvidence
	}
	return &matches[0], BudgetDecisionReasonUninitialized
}

func budgetSelectNode(items []NodeClassUsageObservation, nodeClass BudgetNodeClassId) (*NodeClassUsageObservation, BudgetDecisionReason) {
	var matches []NodeClassUsageObservation
	for _, item := range items {
		if item.NodeClass == nodeClass {
			matches = append(matches, item)
		}
	}
	if len(matches) == 0 {
		return nil, BudgetDecisionReasonMissingEvidence
	}
	if len(matches) > 1 {
		allSame := true
		for _, item := range matches {
			if item.Status != matches[0].Status || item.EvidenceId != matches[0].EvidenceId ||
				item.Age != matches[0].Age || item.CurrentCount != matches[0].CurrentCount {
				allSame = false
				break
			}
		}
		if allSame {
			return nil, BudgetDecisionReasonDuplicateEvidence
		}
		return nil, BudgetDecisionReasonConflictingEvidence
	}
	return &matches[0], BudgetDecisionReasonUninitialized
}

func budgetSelectPrice(items []PriceEvidenceObservation, id PriceEvidenceId) (*PriceEvidenceObservation, BudgetDecisionReason) {
	var matches []PriceEvidenceObservation
	for _, item := range items {
		if item.EvidenceId == id {
			matches = append(matches, item)
		}
	}
	if len(matches) == 0 {
		return nil, BudgetDecisionReasonMissingEvidence
	}
	if len(matches) > 1 {
		allSame := true
		for _, item := range matches {
			if item.Status != matches[0].Status || item.Age != matches[0].Age {
				allSame = false
				break
			}
		}
		if allSame {
			return nil, BudgetDecisionReasonDuplicateEvidence
		}
		return nil, BudgetDecisionReasonConflictingEvidence
	}
	return &matches[0], BudgetDecisionReasonUninitialized
}

func budgetFindNodeGroupError(items []NodeClassUsageObservation) BudgetDecisionReason {
	grouped := make(map[BudgetNodeClassId][]NodeClassUsageObservation)
	for _, item := range items {
		grouped[item.NodeClass] = append(grouped[item.NodeClass], item)
	}
	duplicate := false
	for _, group := range grouped {
		if len(group) <= 1 {
			continue
		}
		first := group[0]
		for _, item := range group {
			if item.Status != first.Status || item.EvidenceId != first.EvidenceId ||
				item.CurrentCount != first.CurrentCount || item.Age != first.Age {
				return BudgetDecisionReasonConflictingEvidence
			}
		}
		duplicate = true
	}
	if duplicate {
		return BudgetDecisionReasonDuplicateEvidence
	}
	return BudgetDecisionReasonUninitialized
}

func budgetFindPriceGroupError(items []PriceEvidenceObservation) BudgetDecisionReason {
	grouped := make(map[PriceEvidenceId][]PriceEvidenceObservation)
	for _, item := range items {
		grouped[item.EvidenceId] = append(grouped[item.EvidenceId], item)
	}
	duplicate := false
	for _, group := range grouped {
		if len(group) <= 1 {
			continue
		}
		first := group[0]
		for _, item := range group {
			if item.Status != first.Status || item.Age != first.Age {
				return BudgetDecisionReasonConflictingEvidence
			}
		}
		duplicate = true
	}
	if duplicate {
		return BudgetDecisionReasonDuplicateEvidence
	}
	return BudgetDecisionReasonUninitialized
}

func budgetFindUsageGroupError(items []BudgetUsageObservation) BudgetDecisionReason {
	grouped := make(map[BudgetUsageScope][]BudgetUsageObservation)
	for _, item := range items {
		grouped[item.Scope] = append(grouped[item.Scope], item)
	}
	duplicate := false
	for _, group := range grouped {
		if len(group) <= 1 {
			continue
		}
		first := group[0]
		for _, item := range group {
			if item.Status != first.Status || item.EvidenceId != first.EvidenceId ||
				item.Age != first.Age || !item.Usage.Equal(first.Usage) {
				return BudgetDecisionReasonConflictingEvidence
			}
		}
		duplicate = true
	}
	if duplicate {
		return BudgetDecisionReasonDuplicateEvidence
	}
	return BudgetDecisionReasonUninitialized
}
