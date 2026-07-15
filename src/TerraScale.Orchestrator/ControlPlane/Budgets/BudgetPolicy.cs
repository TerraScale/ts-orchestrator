using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Budgets;

public enum BudgetEmergencyPosture
{
    Unspecified = 0,
    Normal,
    Emergency,
}

public enum BudgetSafetyPurpose
{
    Unspecified = 0,
    OrdinaryCapacity,
    AvailabilityRepair,
    DataLossPreventionStorageExpansion,
}

public enum BudgetChangeDirection
{
    Unspecified = 0,
    Increase,
    Decrease,
}

public sealed record NodeClassCapacityPolicy
{
    public NodeClassCapacityPolicy(BudgetNodeClassId nodeClass, int minimum, int maximum, int warm)
    {
        NodeClass = nodeClass;
        Minimum = minimum;
        Maximum = maximum;
        Warm = warm;
    }
    public BudgetNodeClassId NodeClass { get; }
    public int Minimum { get; }
    public int Maximum { get; }
    public int Warm { get; }
    internal bool IsValid => NodeClass.IsValid && Minimum >= 0 && Maximum >= Minimum && Warm >= Minimum && Warm <= Maximum;
}

public sealed class BudgetBandPolicy
{
    public BudgetBandPolicy(
        BudgetVector automaticCellMaximum,
        BudgetVector automaticGlobalMaximum,
        BudgetVector approvalCellMaximum,
        BudgetVector approvalGlobalMaximum)
    {
        AutomaticCellMaximum = automaticCellMaximum;
        AutomaticGlobalMaximum = automaticGlobalMaximum;
        ApprovalCellMaximum = approvalCellMaximum;
        ApprovalGlobalMaximum = approvalGlobalMaximum;
    }
    public BudgetVector AutomaticCellMaximum { get; }
    public BudgetVector AutomaticGlobalMaximum { get; }
    public BudgetVector ApprovalCellMaximum { get; }
    public BudgetVector ApprovalGlobalMaximum { get; }
    internal bool IsValid =>
        AutomaticCellMaximum is { IsValid: true }
        && AutomaticGlobalMaximum is { IsValid: true }
        && ApprovalCellMaximum is { IsValid: true }
        && ApprovalGlobalMaximum is { IsValid: true }
        && AutomaticCellMaximum.ExceededBy(ApprovalCellMaximum) == BudgetDimension.None
        && AutomaticGlobalMaximum.ExceededBy(ApprovalGlobalMaximum) == BudgetDimension.None;
}

public enum BudgetPolicyError
{
    Uninitialized = 0,
    None,
    InvalidScope,
    InvalidPosture,
    InvalidEvidenceLimit,
    MissingNodeClassPolicy,
    InvalidNodeClassPolicy,
    DuplicateNodeClassPolicy,
    InvalidCeiling,
    InvalidBandOrdering,
    BudgetExceedsProviderLimit,
}

public sealed class BudgetPolicy
{
    private readonly NodeClassCapacityPolicy[] _nodeClasses;
    private readonly ReadOnlyCollection<NodeClassCapacityPolicy> _nodeClassView;

    private BudgetPolicy(
        BudgetCellId cell,
        BudgetCostCenterId costCenter,
        BudgetApprovalId approvalScope,
        BudgetEmergencyPosture emergencyPosture,
        BudgetQuantity maximumEvidenceAge,
        int maximumEvidenceCount,
        NodeClassCapacityPolicy[] nodeClasses,
        BudgetVector cellCeiling,
        BudgetVector globalCeiling,
        BudgetVector providerAccountCellLimit,
        BudgetVector providerAccountGlobalLimit,
        BudgetBandPolicy bands)
    {
        Cell = cell;
        CostCenter = costCenter;
        ApprovalScope = approvalScope;
        EmergencyPosture = emergencyPosture;
        MaximumEvidenceAge = maximumEvidenceAge;
        MaximumEvidenceCount = maximumEvidenceCount;
        _nodeClasses = nodeClasses;
        _nodeClassView = Array.AsReadOnly(_nodeClasses);
        CellCeiling = cellCeiling;
        GlobalCeiling = globalCeiling;
        ProviderAccountCellLimit = providerAccountCellLimit;
        ProviderAccountGlobalLimit = providerAccountGlobalLimit;
        Bands = bands;
    }

    public BudgetCellId Cell { get; }
    public BudgetCostCenterId CostCenter { get; }
    public BudgetApprovalId ApprovalScope { get; }
    public BudgetEmergencyPosture EmergencyPosture { get; }
    public BudgetQuantity MaximumEvidenceAge { get; }
    public int MaximumEvidenceCount { get; }
    public IReadOnlyList<NodeClassCapacityPolicy> NodeClasses => _nodeClassView;
    public BudgetVector CellCeiling { get; }
    public BudgetVector GlobalCeiling { get; }
    public BudgetVector ProviderAccountCellLimit { get; }
    public BudgetVector ProviderAccountGlobalLimit { get; }
    public BudgetBandPolicy Bands { get; }

    public static bool TryCreate(
        BudgetCellId cell,
        BudgetCostCenterId costCenter,
        BudgetApprovalId approvalScope,
        BudgetEmergencyPosture emergencyPosture,
        BudgetQuantity maximumEvidenceAge,
        int maximumEvidenceCount,
        IEnumerable<NodeClassCapacityPolicy?>? nodeClasses,
        BudgetVector? cellCeiling,
        BudgetVector? globalCeiling,
        BudgetVector? providerAccountCellLimit,
        BudgetVector? providerAccountGlobalLimit,
        BudgetBandPolicy? bands,
        out BudgetPolicy? result,
        out BudgetPolicyError error)
    {
        result = null;
        if (!cell.IsValid || !costCenter.IsValid || !approvalScope.IsValid)
        {
            error = BudgetPolicyError.InvalidScope;
            return false;
        }
        if (emergencyPosture is not (BudgetEmergencyPosture.Normal or BudgetEmergencyPosture.Emergency))
        {
            error = BudgetPolicyError.InvalidPosture;
            return false;
        }
        if (maximumEvidenceCount <= 0)
        {
            error = BudgetPolicyError.InvalidEvidenceLimit;
            return false;
        }

        var collected = new List<NodeClassCapacityPolicy>();
        var seen = new HashSet<BudgetNodeClassId>();
        if (nodeClasses is null)
        {
            error = BudgetPolicyError.MissingNodeClassPolicy;
            return false;
        }
        if (!BudgetInputSnapshot.TryCopy(nodeClasses,
                Math.Min(maximumEvidenceCount, BudgetTechnicalInputLimits.MaximumNodeClassPolicyCount), out var nodeClassSnapshot))
        {
            error = BudgetPolicyError.InvalidEvidenceLimit;
            return false;
        }
        foreach (var nodeClass in nodeClassSnapshot)
        {
            if (collected.Count >= maximumEvidenceCount)
            {
                error = BudgetPolicyError.InvalidEvidenceLimit;
                return false;
            }
            if (nodeClass is null || !nodeClass.IsValid)
            {
                error = BudgetPolicyError.InvalidNodeClassPolicy;
                return false;
            }
            if (!seen.Add(nodeClass.NodeClass))
            {
                error = BudgetPolicyError.DuplicateNodeClassPolicy;
                return false;
            }
            collected.Add(nodeClass);
        }
        if (collected.Count == 0)
        {
            error = BudgetPolicyError.MissingNodeClassPolicy;
            return false;
        }

        if (cellCeiling is not { IsValid: true } || globalCeiling is not { IsValid: true }
            || providerAccountCellLimit is not { IsValid: true } || providerAccountGlobalLimit is not { IsValid: true })
        {
            error = BudgetPolicyError.InvalidCeiling;
            return false;
        }
        if (bands is null || !bands.IsValid
            || bands.ApprovalCellMaximum.ExceededBy(cellCeiling) != BudgetDimension.None
            || bands.ApprovalGlobalMaximum.ExceededBy(globalCeiling) != BudgetDimension.None)
        {
            error = BudgetPolicyError.InvalidBandOrdering;
            return false;
        }
        if (cellCeiling.ExceededBy(providerAccountCellLimit) != BudgetDimension.None
            || globalCeiling.ExceededBy(providerAccountGlobalLimit) != BudgetDimension.None)
        {
            error = BudgetPolicyError.BudgetExceedsProviderLimit;
            return false;
        }

        var array = collected.OrderBy(static item => item.NodeClass.Value, StringComparer.Ordinal).ToArray();
        result = new BudgetPolicy(cell, costCenter, approvalScope, emergencyPosture, maximumEvidenceAge, maximumEvidenceCount,
            array, cellCeiling, globalCeiling, providerAccountCellLimit, providerAccountGlobalLimit, bands);
        error = BudgetPolicyError.None;
        return true;
    }

    internal NodeClassCapacityPolicy? Find(BudgetNodeClassId nodeClass) =>
        _nodeClasses.FirstOrDefault(item => item.NodeClass == nodeClass);
}
