using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.Budgets;

public enum BudgetDecisionKind
{
    Uninitialized = 0,
    Automatic,
    ApprovalRequired,
    Forbidden,
    Held,
}

public enum BudgetDecisionReason
{
    Uninitialized = 0,
    WithinAutomaticBand,
    WarmCapacityProtection,
    ApprovalBand,
    ForbiddenBand,
    BudgetCeilingExceeded,
    ProviderAccountLimitExceeded,
    NodeClassMinimumViolated,
    NodeClassMaximumExceeded,
    EmergencyNonSafetyGrowth,
    EmergencyDecreaseHeld,
    EmergencyDataLossPrevention,
    InvalidPolicy,
    MalformedProposal,
    WrongScope,
    UnknownNodeClass,
    MissingEvidence,
    UnknownEvidence,
    StaleEvidence,
    DuplicateEvidence,
    ConflictingEvidence,
    EvidenceLimitExceeded,
    ArithmeticOverflow,
    ArithmeticUnderflow,
    InvalidEmergencySafetyClaim,
}

public sealed class BudgetApprovalScope
{
    internal BudgetApprovalScope(
        BudgetApprovalId approvalId,
        BudgetCellId cell,
        BudgetCostCenterId costCenter,
        BudgetNodeClassId nodeClass,
        BudgetResourceId resource,
        BudgetSafetyPurpose purpose)
    {
        ApprovalId = approvalId;
        Cell = cell;
        CostCenter = costCenter;
        NodeClass = nodeClass;
        Resource = resource;
        Purpose = purpose;
    }
    public BudgetApprovalId ApprovalId { get; }
    public BudgetCellId Cell { get; }
    public BudgetCostCenterId CostCenter { get; }
    public BudgetNodeClassId NodeClass { get; }
    public BudgetResourceId Resource { get; }
    public BudgetSafetyPurpose Purpose { get; }
    public override string ToString() => "<budget-approval-scope>";
}

public sealed class BudgetDecisionSubject
{
    internal BudgetDecisionSubject(BudgetProposal proposal)
    {
        Resource = proposal.Resource;
        Cell = proposal.Cell;
        CostCenter = proposal.CostCenter;
        NodeClass = proposal.NodeClass;
        PriceEvidence = proposal.PriceEvidence;
        Direction = proposal.Direction;
        Purpose = proposal.Purpose;
        NodeCount = proposal.NodeCount;
        Delta = proposal.Delta;
    }

    public BudgetResourceId Resource { get; }
    public BudgetCellId Cell { get; }
    public BudgetCostCenterId CostCenter { get; }
    public BudgetNodeClassId NodeClass { get; }
    public PriceEvidenceId PriceEvidence { get; }
    public BudgetChangeDirection Direction { get; }
    public BudgetSafetyPurpose Purpose { get; }
    public int NodeCount { get; }
    public BudgetVector Delta { get; }
    public override string ToString() => "<budget-decision-subject>";
}

public sealed class BudgetDecisionTrace
{
    internal BudgetDecisionTrace(
        BudgetVector currentCell,
        BudgetVector projectedCell,
        BudgetVector currentGlobal,
        BudgetVector projectedGlobal,
        BudgetVector delta,
        BudgetVector automaticCellMaximum,
        BudgetVector automaticGlobalMaximum,
        BudgetVector approvalCellMaximum,
        BudgetVector approvalGlobalMaximum,
        BudgetVector cellCeiling,
        BudgetVector globalCeiling,
        BudgetVector providerAccountCellLimit,
        BudgetVector providerAccountGlobalLimit,
        int currentNodeCount,
        int projectedNodeCount,
        int minimumNodeCount,
        int warmNodeCount,
        int maximumNodeCount,
        BudgetQuantity maximumEvidenceAge,
        BudgetQuantity cellEvidenceAge,
        BudgetQuantity globalEvidenceAge,
        BudgetQuantity nodeEvidenceAge,
        BudgetQuantity priceEvidenceAge,
        BudgetDimension bindingDimensions)
    {
        CurrentCell = currentCell;
        ProjectedCell = projectedCell;
        CurrentGlobal = currentGlobal;
        ProjectedGlobal = projectedGlobal;
        Delta = delta;
        AutomaticCellMaximum = automaticCellMaximum;
        AutomaticGlobalMaximum = automaticGlobalMaximum;
        ApprovalCellMaximum = approvalCellMaximum;
        ApprovalGlobalMaximum = approvalGlobalMaximum;
        CellCeiling = cellCeiling;
        GlobalCeiling = globalCeiling;
        ProviderAccountCellLimit = providerAccountCellLimit;
        ProviderAccountGlobalLimit = providerAccountGlobalLimit;
        CurrentNodeCount = currentNodeCount;
        ProjectedNodeCount = projectedNodeCount;
        MinimumNodeCount = minimumNodeCount;
        WarmNodeCount = warmNodeCount;
        MaximumNodeCount = maximumNodeCount;
        MaximumEvidenceAge = maximumEvidenceAge;
        CellEvidenceAge = cellEvidenceAge;
        GlobalEvidenceAge = globalEvidenceAge;
        NodeEvidenceAge = nodeEvidenceAge;
        PriceEvidenceAge = priceEvidenceAge;
        BindingDimensions = bindingDimensions;
    }
    public BudgetVector CurrentCell { get; }
    public BudgetVector ProjectedCell { get; }
    public BudgetVector CurrentGlobal { get; }
    public BudgetVector ProjectedGlobal { get; }
    public BudgetVector Delta { get; }
    public BudgetVector AutomaticCellMaximum { get; }
    public BudgetVector AutomaticGlobalMaximum { get; }
    public BudgetVector ApprovalCellMaximum { get; }
    public BudgetVector ApprovalGlobalMaximum { get; }
    public BudgetVector CellCeiling { get; }
    public BudgetVector GlobalCeiling { get; }
    public BudgetVector ProviderAccountCellLimit { get; }
    public BudgetVector ProviderAccountGlobalLimit { get; }
    public int CurrentNodeCount { get; }
    public int ProjectedNodeCount { get; }
    public int MinimumNodeCount { get; }
    public int WarmNodeCount { get; }
    public int MaximumNodeCount { get; }
    public BudgetQuantity MaximumEvidenceAge { get; }
    public BudgetQuantity CellEvidenceAge { get; }
    public BudgetQuantity GlobalEvidenceAge { get; }
    public BudgetQuantity NodeEvidenceAge { get; }
    public BudgetQuantity PriceEvidenceAge { get; }
    public BudgetDimension BindingDimensions { get; }
    public override string ToString() => string.Create(CultureInfo.InvariantCulture,
        $"currentCell=[{CurrentCell}];projectedCell=[{ProjectedCell}];currentGlobal=[{CurrentGlobal}];"
        + $"projectedGlobal=[{ProjectedGlobal}];delta=[{Delta}];automaticCell=[{AutomaticCellMaximum}];automaticGlobal=[{AutomaticGlobalMaximum}];"
        + $"approvalCell=[{ApprovalCellMaximum}];approvalGlobal=[{ApprovalGlobalMaximum}];cellCeiling=[{CellCeiling}];globalCeiling=[{GlobalCeiling}];"
        + $"providerCell=[{ProviderAccountCellLimit}];providerGlobal=[{ProviderAccountGlobalLimit}];"
        + $"nodes={CurrentNodeCount}->{ProjectedNodeCount};nodeBounds={MinimumNodeCount}/{WarmNodeCount}/{MaximumNodeCount};"
        + $"evidenceAge={CellEvidenceAge.Value}/{GlobalEvidenceAge.Value}/{NodeEvidenceAge.Value}/{PriceEvidenceAge.Value};maxEvidenceAge={MaximumEvidenceAge.Value};"
        + $"binding={(int)BindingDimensions}");
}

public readonly record struct BudgetDecision
{
    private BudgetDecision(BudgetDecisionKind kind, BudgetDecisionReason reason, BudgetDecisionTrace? trace,
        BudgetDecisionSubject? subject, BudgetApprovalScope? approvalScope)
    {
        Kind = kind;
        Reason = reason;
        Trace = trace;
        Subject = subject;
        ApprovalScope = approvalScope;
    }
    public BudgetDecisionKind Kind { get; }
    public BudgetDecisionReason Reason { get; }
    public BudgetDecisionTrace? Trace { get; }
    public BudgetDecisionSubject? Subject { get; }
    public BudgetApprovalScope? ApprovalScope { get; }
    public bool IsAuthorized => Kind == BudgetDecisionKind.Automatic;
    internal static BudgetDecision Held(BudgetDecisionReason reason) => new(BudgetDecisionKind.Held, reason, null, null, null);
    internal static BudgetDecision Create(BudgetDecisionKind kind, BudgetDecisionReason reason, BudgetDecisionTrace trace,
        BudgetProposal proposal, BudgetApprovalScope? approvalScope = null) =>
        new(kind, reason, trace, new BudgetDecisionSubject(proposal), approvalScope);
    public override string ToString() => Trace is null
        ? $"kind={Kind};reason={Reason}"
        : $"kind={Kind};reason={Reason};trace=[{Trace}]";
}

public static class BudgetAuthorizationEngine
{
    public static BudgetDecision Evaluate(
        BudgetPolicy? policy,
        BudgetProposal? proposal,
        IEnumerable<BudgetUsageObservation?>? usageEvidence,
        IEnumerable<NodeClassUsageObservation?>? nodeEvidence,
        IEnumerable<PriceEvidenceObservation?>? priceEvidence)
    {
        if (policy is null)
        {
            return BudgetDecision.Held(BudgetDecisionReason.InvalidPolicy);
        }
        if (proposal is null || !proposal.IsWellFormed)
        {
            return BudgetDecision.Held(BudgetDecisionReason.MalformedProposal);
        }
        if (proposal.Cell != policy.Cell || proposal.CostCenter != policy.CostCenter)
        {
            return BudgetDecision.Held(BudgetDecisionReason.WrongScope);
        }
        var nodePolicy = policy.Find(proposal.NodeClass);
        if (nodePolicy is null)
        {
            return BudgetDecision.Held(BudgetDecisionReason.UnknownNodeClass);
        }

        var evidence = Collect(policy, proposal, usageEvidence, nodeEvidence, priceEvidence);
        if (evidence.Error != BudgetDecisionReason.Uninitialized)
        {
            return BudgetDecision.Held(evidence.Error);
        }

        var add = proposal.Direction == BudgetChangeDirection.Increase;
        var cellCombined = add
            ? evidence.CellUsage!.Usage.TryAdd(proposal.Delta, out var projectedCell)
            : evidence.CellUsage!.Usage.TrySubtract(proposal.Delta, out projectedCell);
        var globalCombined = add
            ? evidence.GlobalUsage!.Usage.TryAdd(proposal.Delta, out var projectedGlobal)
            : evidence.GlobalUsage!.Usage.TrySubtract(proposal.Delta, out projectedGlobal);
        if (!cellCombined || !globalCombined)
        {
            return BudgetDecision.Held(add ? BudgetDecisionReason.ArithmeticOverflow : BudgetDecisionReason.ArithmeticUnderflow);
        }

        int projectedNodes;
        try
        {
            projectedNodes = add
                ? checked(evidence.NodeUsage!.CurrentCount + proposal.NodeCount)
                : checked(evidence.NodeUsage!.CurrentCount - proposal.NodeCount);
        }
        catch (OverflowException)
        {
            return BudgetDecision.Held(add ? BudgetDecisionReason.ArithmeticOverflow : BudgetDecisionReason.ArithmeticUnderflow);
        }
        if (projectedNodes < 0)
        {
            return BudgetDecision.Held(BudgetDecisionReason.ArithmeticUnderflow);
        }

        var providerExceeded = projectedCell!.ExceededBy(policy.ProviderAccountCellLimit)
            | projectedGlobal!.ExceededBy(policy.ProviderAccountGlobalLimit);
        var trace = new BudgetDecisionTrace(
            evidence.CellUsage.Usage, projectedCell, evidence.GlobalUsage.Usage, projectedGlobal, proposal.Delta,
            policy.Bands.AutomaticCellMaximum, policy.Bands.AutomaticGlobalMaximum,
            policy.Bands.ApprovalCellMaximum, policy.Bands.ApprovalGlobalMaximum,
            policy.CellCeiling, policy.GlobalCeiling, policy.ProviderAccountCellLimit, policy.ProviderAccountGlobalLimit,
            evidence.NodeUsage.CurrentCount, projectedNodes,
            nodePolicy.Minimum, nodePolicy.Warm, nodePolicy.Maximum, policy.MaximumEvidenceAge,
            evidence.CellUsage.Age, evidence.GlobalUsage.Age, evidence.NodeUsage.Age, evidence.PriceUsage!.Age,
            providerExceeded);
        if (providerExceeded != BudgetDimension.None)
        {
            return BudgetDecision.Create(BudgetDecisionKind.Forbidden, BudgetDecisionReason.ProviderAccountLimitExceeded, trace, proposal);
        }

        if (policy.EmergencyPosture == BudgetEmergencyPosture.Emergency)
        {
            if (!add)
            {
                return BudgetDecision.Create(BudgetDecisionKind.Held, BudgetDecisionReason.EmergencyDecreaseHeld, trace, proposal);
            }
            if (proposal.Purpose == BudgetSafetyPurpose.DataLossPreventionStorageExpansion)
            {
                if (proposal.NodeCount != 0 || !proposal.Delta.IsStorageSafetyDomainIncrease)
                {
                    return BudgetDecision.Create(BudgetDecisionKind.Held, BudgetDecisionReason.InvalidEmergencySafetyClaim, trace, proposal);
                }
                return BudgetDecision.Create(BudgetDecisionKind.Automatic, BudgetDecisionReason.EmergencyDataLossPrevention, trace, proposal);
            }
            if (proposal.Purpose != BudgetSafetyPurpose.AvailabilityRepair)
            {
                return BudgetDecision.Create(BudgetDecisionKind.Forbidden, BudgetDecisionReason.EmergencyNonSafetyGrowth, trace, proposal);
            }
        }

        if (projectedNodes < nodePolicy.Minimum)
        {
            return BudgetDecision.Create(BudgetDecisionKind.Forbidden, BudgetDecisionReason.NodeClassMinimumViolated, trace, proposal);
        }
        if (projectedNodes > nodePolicy.Maximum)
        {
            return BudgetDecision.Create(BudgetDecisionKind.Forbidden, BudgetDecisionReason.NodeClassMaximumExceeded, trace, proposal);
        }

        var budgetExceeded = projectedCell.ExceededBy(policy.CellCeiling)
            | projectedGlobal.ExceededBy(policy.GlobalCeiling);
        if (budgetExceeded != BudgetDimension.None)
        {
            trace = ReplaceBinding(trace, budgetExceeded);
            return BudgetDecision.Create(BudgetDecisionKind.Forbidden, BudgetDecisionReason.BudgetCeilingExceeded, trace, proposal);
        }

        var approvalExceeded = projectedCell.ExceededBy(policy.Bands.ApprovalCellMaximum)
            | projectedGlobal.ExceededBy(policy.Bands.ApprovalGlobalMaximum);
        if (approvalExceeded != BudgetDimension.None)
        {
            trace = ReplaceBinding(trace, approvalExceeded);
            return BudgetDecision.Create(BudgetDecisionKind.Forbidden, BudgetDecisionReason.ForbiddenBand, trace, proposal);
        }

        var automaticExceeded = projectedCell.ExceededBy(policy.Bands.AutomaticCellMaximum)
            | projectedGlobal.ExceededBy(policy.Bands.AutomaticGlobalMaximum);
        var warmProtected = !add && projectedNodes < nodePolicy.Warm;
        if (automaticExceeded != BudgetDimension.None || warmProtected)
        {
            trace = ReplaceBinding(trace, automaticExceeded);
            var scope = new BudgetApprovalScope(policy.ApprovalScope, policy.Cell, policy.CostCenter,
                proposal.NodeClass, proposal.Resource, proposal.Purpose);
            return BudgetDecision.Create(BudgetDecisionKind.ApprovalRequired,
                warmProtected ? BudgetDecisionReason.WarmCapacityProtection : BudgetDecisionReason.ApprovalBand,
                trace, proposal, scope);
        }

        return BudgetDecision.Create(BudgetDecisionKind.Automatic, BudgetDecisionReason.WithinAutomaticBand, trace, proposal);
    }

    private static BudgetDecisionTrace ReplaceBinding(BudgetDecisionTrace trace, BudgetDimension binding) =>
        new(trace.CurrentCell, trace.ProjectedCell, trace.CurrentGlobal, trace.ProjectedGlobal, trace.Delta,
            trace.AutomaticCellMaximum, trace.AutomaticGlobalMaximum, trace.ApprovalCellMaximum, trace.ApprovalGlobalMaximum,
            trace.CellCeiling, trace.GlobalCeiling, trace.ProviderAccountCellLimit, trace.ProviderAccountGlobalLimit,
            trace.CurrentNodeCount, trace.ProjectedNodeCount,
            trace.MinimumNodeCount, trace.WarmNodeCount, trace.MaximumNodeCount, trace.MaximumEvidenceAge,
            trace.CellEvidenceAge, trace.GlobalEvidenceAge, trace.NodeEvidenceAge, trace.PriceEvidenceAge, binding);

    private static CollectedEvidence Collect(
        BudgetPolicy policy,
        BudgetProposal proposal,
        IEnumerable<BudgetUsageObservation?>? usageSource,
        IEnumerable<NodeClassUsageObservation?>? nodeSource,
        IEnumerable<PriceEvidenceObservation?>? priceSource)
    {
        if (usageSource is null || nodeSource is null || priceSource is null)
        {
            return new(BudgetDecisionReason.MissingEvidence, null, null, null, null);
        }
        var technicalMaximum = Math.Min(policy.MaximumEvidenceCount, BudgetTechnicalInputLimits.MaximumEvidenceCount);
        if (!BudgetInputSnapshot.TryCopy(usageSource, technicalMaximum, out var usageSnapshot)
            || !BudgetInputSnapshot.TryCopy(nodeSource, technicalMaximum - usageSnapshot.Length, out var nodeSnapshot)
            || !BudgetInputSnapshot.TryCopy(priceSource, technicalMaximum - usageSnapshot.Length - nodeSnapshot.Length, out var priceSnapshot))
        {
            return new(BudgetDecisionReason.EvidenceLimitExceeded, null, null, null, null);
        }
        var count = 0;
        var usage = new List<BudgetUsageObservation>();
        var nodes = new List<NodeClassUsageObservation>();
        var prices = new List<PriceEvidenceObservation>();
        foreach (var item in usageSnapshot)
        {
            if (!Take(item, policy.MaximumEvidenceCount, ref count, out var error)) return new(error, null, null, null, null);
            usage.Add(item!);
        }
        foreach (var item in nodeSnapshot)
        {
            if (!Take(item, policy.MaximumEvidenceCount, ref count, out var error)) return new(error, null, null, null, null);
            nodes.Add(item!);
        }
        foreach (var item in priceSnapshot)
        {
            if (!Take(item, policy.MaximumEvidenceCount, ref count, out var error)) return new(error, null, null, null, null);
            prices.Add(item!);
        }

        if (usage.Any(item => item.CostCenter != policy.CostCenter
                || item.Scope == BudgetUsageScope.Cell && item.Cell != policy.Cell
                || item.Scope == BudgetUsageScope.Global && item.Cell.IsValid
                || item.Scope is not (BudgetUsageScope.Cell or BudgetUsageScope.Global))
            || nodes.Any(item => item.Cell != policy.Cell || item.CostCenter != policy.CostCenter)
            || prices.Any(item => item.CostCenter != policy.CostCenter))
        {
            return new(BudgetDecisionReason.WrongScope, null, null, null, null);
        }
        if (usage.Any(item => !item.EvidenceId.IsValid || item.Usage is not { IsValid: true })
            || nodes.Any(item => !item.NodeClass.IsValid || !item.EvidenceId.IsValid || item.CurrentCount < 0)
            || prices.Any(item => !item.EvidenceId.IsValid))
        {
            return new(BudgetDecisionReason.ConflictingEvidence, null, null, null, null);
        }

        var groupErrors = new[] { FindUsageGroupError(usage), FindNodeGroupError(nodes), FindPriceGroupError(prices) };
        if (groupErrors.Contains(BudgetDecisionReason.ConflictingEvidence))
            return new(BudgetDecisionReason.ConflictingEvidence, null, null, null, null);
        if (groupErrors.Contains(BudgetDecisionReason.DuplicateEvidence))
            return new(BudgetDecisionReason.DuplicateEvidence, null, null, null, null);

        var cell = SelectUsage(usage, BudgetUsageScope.Cell, out var cellError);
        if (cellError != BudgetDecisionReason.Uninitialized) return new(cellError, null, null, null, null);
        var global = SelectUsage(usage, BudgetUsageScope.Global, out var globalError);
        if (globalError != BudgetDecisionReason.Uninitialized) return new(globalError, null, null, null, null);
        var node = SelectNode(nodes, proposal.NodeClass, out var nodeError);
        if (nodeError != BudgetDecisionReason.Uninitialized) return new(nodeError, null, null, null, null);
        var price = SelectPrice(prices, proposal.PriceEvidence, out var priceError);
        if (priceError != BudgetDecisionReason.Uninitialized) return new(priceError, null, null, null, null);

        var allStatuses = usage.Select(static item => item.Status)
            .Concat(nodes.Select(static item => item.Status)).Concat(prices.Select(static item => item.Status));
        if (allStatuses.Any(static status => status == BudgetEvidenceStatus.Unknown))
            return new(BudgetDecisionReason.UnknownEvidence, null, null, null, null);
        if (allStatuses.Any(static status => status == BudgetEvidenceStatus.Stale))
            return new(BudgetDecisionReason.StaleEvidence, null, null, null, null);
        if (allStatuses.Any(static status => status != BudgetEvidenceStatus.Current))
            return new(BudgetDecisionReason.UnknownEvidence, null, null, null, null);
        if (usage.Any(item => item.Age.Value > policy.MaximumEvidenceAge.Value)
            || nodes.Any(item => item.Age.Value > policy.MaximumEvidenceAge.Value)
            || prices.Any(item => item.Age.Value > policy.MaximumEvidenceAge.Value))
            return new(BudgetDecisionReason.StaleEvidence, null, null, null, null);
        return new(BudgetDecisionReason.Uninitialized, cell, global, node, price);
    }

    private static bool Take<T>(T? item, int maximum, ref int count, out BudgetDecisionReason error) where T : class
    {
        if (count >= maximum)
        {
            error = BudgetDecisionReason.EvidenceLimitExceeded;
            return false;
        }
        count++;
        if (item is null)
        {
            error = BudgetDecisionReason.MissingEvidence;
            return false;
        }
        error = BudgetDecisionReason.Uninitialized;
        return true;
    }

    private static BudgetUsageObservation? SelectUsage(
        List<BudgetUsageObservation> items, BudgetUsageScope scope, out BudgetDecisionReason error)
    {
        var matches = items.Where(item => item.Scope == scope).ToArray();
        if (matches.Length == 0) { error = BudgetDecisionReason.MissingEvidence; return null; }
        if (matches.Length > 1)
        {
            error = matches.All(item => item.Status == matches[0].Status && item.EvidenceId == matches[0].EvidenceId
                && item.Age == matches[0].Age && Equals(item.Usage, matches[0].Usage))
                ? BudgetDecisionReason.DuplicateEvidence : BudgetDecisionReason.ConflictingEvidence;
            return null;
        }
        error = BudgetDecisionReason.Uninitialized;
        return matches[0];
    }

    private static NodeClassUsageObservation? SelectNode(
        List<NodeClassUsageObservation> items, BudgetNodeClassId nodeClass, out BudgetDecisionReason error)
    {
        var matches = items.Where(item => item.NodeClass == nodeClass).ToArray();
        if (matches.Length == 0) { error = BudgetDecisionReason.MissingEvidence; return null; }
        if (matches.Length > 1)
        {
            error = matches.All(item => item.Status == matches[0].Status && item.EvidenceId == matches[0].EvidenceId
                && item.Age == matches[0].Age && item.CurrentCount == matches[0].CurrentCount)
                ? BudgetDecisionReason.DuplicateEvidence : BudgetDecisionReason.ConflictingEvidence;
            return null;
        }
        error = BudgetDecisionReason.Uninitialized;
        return matches[0];
    }

    private static PriceEvidenceObservation? SelectPrice(
        List<PriceEvidenceObservation> items, PriceEvidenceId id, out BudgetDecisionReason error)
    {
        var matches = items.Where(item => item.EvidenceId == id).ToArray();
        if (matches.Length == 0) { error = BudgetDecisionReason.MissingEvidence; return null; }
        if (matches.Length > 1)
        {
            error = matches.All(item => item.Status == matches[0].Status && item.Age == matches[0].Age)
                ? BudgetDecisionReason.DuplicateEvidence : BudgetDecisionReason.ConflictingEvidence;
            return null;
        }
        error = BudgetDecisionReason.Uninitialized;
        return matches[0];
    }

    private static BudgetDecisionReason FindNodeGroupError(IEnumerable<NodeClassUsageObservation> items)
    {
        var duplicate = false;
        foreach (var group in items.GroupBy(static item => item.NodeClass))
        {
            if (group.Count() <= 1) continue;
            var first = group.First();
            if (!group.All(item => item.Status == first.Status && item.EvidenceId == first.EvidenceId
                && item.CurrentCount == first.CurrentCount && item.Age == first.Age))
                return BudgetDecisionReason.ConflictingEvidence;
            duplicate = true;
        }
        return duplicate ? BudgetDecisionReason.DuplicateEvidence : BudgetDecisionReason.Uninitialized;
    }

    private static BudgetDecisionReason FindPriceGroupError(IEnumerable<PriceEvidenceObservation> items)
    {
        var duplicate = false;
        foreach (var group in items.GroupBy(static item => item.EvidenceId))
        {
            if (group.Count() <= 1) continue;
            var first = group.First();
            if (!group.All(item => item.Status == first.Status && item.Age == first.Age))
                return BudgetDecisionReason.ConflictingEvidence;
            duplicate = true;
        }
        return duplicate ? BudgetDecisionReason.DuplicateEvidence : BudgetDecisionReason.Uninitialized;
    }

    private static BudgetDecisionReason FindUsageGroupError(IEnumerable<BudgetUsageObservation> items)
    {
        var duplicate = false;
        foreach (var group in items.GroupBy(static item => item.Scope))
        {
            if (group.Count() <= 1) continue;
            var first = group.First();
            if (!group.All(item => item.Status == first.Status && item.EvidenceId == first.EvidenceId
                && item.Age == first.Age && Equals(item.Usage, first.Usage)))
                return BudgetDecisionReason.ConflictingEvidence;
            duplicate = true;
        }
        return duplicate ? BudgetDecisionReason.DuplicateEvidence : BudgetDecisionReason.Uninitialized;
    }

    private sealed record CollectedEvidence(
        BudgetDecisionReason Error,
        BudgetUsageObservation? CellUsage,
        BudgetUsageObservation? GlobalUsage,
        NodeClassUsageObservation? NodeUsage,
        PriceEvidenceObservation? PriceUsage);
}
