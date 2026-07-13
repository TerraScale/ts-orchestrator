namespace TerraScale.Orchestrator.ControlPlane.Budgets;

public enum BudgetEvidenceStatus
{
    Unknown = 0,
    Current,
    Stale,
}

public enum BudgetUsageScope
{
    Unspecified = 0,
    Cell,
    Global,
}

public sealed class BudgetUsageObservation
{
    public BudgetUsageObservation(
        BudgetUsageScope scope,
        BudgetCellId cell,
        BudgetCostCenterId costCenter,
        PriceEvidenceId evidenceId,
        BudgetEvidenceStatus status,
        BudgetQuantity age,
        BudgetVector usage)
    {
        Scope = scope;
        Cell = cell;
        CostCenter = costCenter;
        EvidenceId = evidenceId;
        Status = status;
        Age = age;
        Usage = usage;
    }
    public BudgetUsageScope Scope { get; }
    public BudgetCellId Cell { get; }
    public BudgetCostCenterId CostCenter { get; }
    public PriceEvidenceId EvidenceId { get; }
    public BudgetEvidenceStatus Status { get; }
    public BudgetQuantity Age { get; }
    public BudgetVector Usage { get; }
}

public sealed class NodeClassUsageObservation
{
    public NodeClassUsageObservation(
        BudgetCellId cell,
        BudgetCostCenterId costCenter,
        BudgetNodeClassId nodeClass,
        PriceEvidenceId evidenceId,
        BudgetEvidenceStatus status,
        BudgetQuantity age,
        int currentCount)
    {
        Cell = cell;
        CostCenter = costCenter;
        NodeClass = nodeClass;
        EvidenceId = evidenceId;
        Status = status;
        Age = age;
        CurrentCount = currentCount;
    }
    public BudgetCellId Cell { get; }
    public BudgetCostCenterId CostCenter { get; }
    public BudgetNodeClassId NodeClass { get; }
    public PriceEvidenceId EvidenceId { get; }
    public BudgetEvidenceStatus Status { get; }
    public BudgetQuantity Age { get; }
    public int CurrentCount { get; }
}

public sealed class PriceEvidenceObservation
{
    public PriceEvidenceObservation(
        PriceEvidenceId evidenceId,
        BudgetCostCenterId costCenter,
        BudgetEvidenceStatus status,
        BudgetQuantity age)
    {
        EvidenceId = evidenceId;
        CostCenter = costCenter;
        Status = status;
        Age = age;
    }
    public PriceEvidenceId EvidenceId { get; }
    public BudgetCostCenterId CostCenter { get; }
    public BudgetEvidenceStatus Status { get; }
    public BudgetQuantity Age { get; }
}

public sealed class BudgetProposal
{
    public BudgetProposal(
        BudgetResourceId resource,
        BudgetCellId cell,
        BudgetCostCenterId costCenter,
        BudgetNodeClassId nodeClass,
        PriceEvidenceId priceEvidence,
        BudgetChangeDirection direction,
        BudgetSafetyPurpose purpose,
        int nodeCount,
        BudgetVector delta)
    {
        Resource = resource;
        Cell = cell;
        CostCenter = costCenter;
        NodeClass = nodeClass;
        PriceEvidence = priceEvidence;
        Direction = direction;
        Purpose = purpose;
        NodeCount = nodeCount;
        Delta = delta;
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

    internal bool IsWellFormed => Resource.IsValid && Cell.IsValid && CostCenter.IsValid && NodeClass.IsValid
        && PriceEvidence.IsValid && Direction is BudgetChangeDirection.Increase or BudgetChangeDirection.Decrease
        && Purpose is not BudgetSafetyPurpose.Unspecified && NodeCount >= 0 && Delta is { IsValid: true }
        && (NodeCount > 0 || !Delta.Equals(BudgetVector.Zero));
}
