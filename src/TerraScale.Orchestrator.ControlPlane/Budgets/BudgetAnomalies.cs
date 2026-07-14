using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Budgets;

public enum BudgetResourceAttachment
{
    Unspecified = 0,
    NotApplicable,
    Attached,
    Unattached,
}

public sealed class BudgetResourceObservation
{
    public BudgetResourceObservation(
        BudgetResourceId resource,
        BudgetCellId cell,
        BudgetCostCenterId costCenter,
        PriceEvidenceId evidenceId,
        BudgetEvidenceStatus status,
        BudgetQuantity age,
        bool desired,
        bool owned,
        bool billed,
        BudgetResourceAttachment attachment)
    {
        Resource = resource;
        Cell = cell;
        CostCenter = costCenter;
        EvidenceId = evidenceId;
        Status = status;
        Age = age;
        Desired = desired;
        Owned = owned;
        Billed = billed;
        Attachment = attachment;
    }
    public BudgetResourceId Resource { get; }
    public BudgetCellId Cell { get; }
    public BudgetCostCenterId CostCenter { get; }
    public PriceEvidenceId EvidenceId { get; }
    public BudgetEvidenceStatus Status { get; }
    public BudgetQuantity Age { get; }
    public bool Desired { get; }
    public bool Owned { get; }
    public bool Billed { get; }
    public BudgetResourceAttachment Attachment { get; }
}

public enum BudgetAnomalyKind
{
    OrphanedOwnedResource = 1,
    UnattachedResource,
    DesiredResourceMissing,
    BillingWithoutOwnedResource,
    OwnedResourceMissingFromBilling,
}

public readonly record struct BudgetAnomalyFinding(BudgetResourceId Resource, BudgetAnomalyKind Kind)
{
    public override string ToString() => $"<budget-anomaly:{Kind}>";
}

public enum BudgetAnomalyError
{
    Uninitialized = 0,
    None,
    InvalidScope,
    InvalidEvidenceLimit,
    MissingEvidence,
    UnknownEvidence,
    StaleEvidence,
    DuplicateEvidence,
    ConflictingEvidence,
}

public sealed class BudgetAnomalyResult
{
    internal BudgetAnomalyResult(BudgetAnomalyError error, BudgetAnomalyFinding[] findings)
    {
        Error = error;
        Findings = new ReadOnlyCollection<BudgetAnomalyFinding>(findings);
    }
    public BudgetAnomalyError Error { get; }
    public bool IsComplete => Error == BudgetAnomalyError.None;
    public IReadOnlyList<BudgetAnomalyFinding> Findings { get; }
    public override string ToString() => $"error={Error};findingCount={Findings.Count}";
}

public static class BudgetAnomalyDetector
{
    public static BudgetAnomalyResult Detect(
        BudgetCellId expectedCell,
        BudgetCostCenterId expectedCostCenter,
        int maximumEvidenceCount,
        BudgetQuantity maximumEvidenceAge,
        bool inventoryComplete,
        IEnumerable<BudgetResourceObservation?>? source)
    {
        if (!expectedCell.IsValid || !expectedCostCenter.IsValid)
            return Error(BudgetAnomalyError.InvalidScope);
        if (maximumEvidenceCount <= 0)
            return Error(BudgetAnomalyError.InvalidEvidenceLimit);
        if (!inventoryComplete || source is null)
            return Error(BudgetAnomalyError.MissingEvidence);

        if (!BudgetInputSnapshot.TryCopy(source,
                Math.Min(maximumEvidenceCount, BudgetTechnicalInputLimits.MaximumEvidenceCount), out var observationSnapshot))
            return Error(BudgetAnomalyError.InvalidEvidenceLimit);
        var observations = new List<BudgetResourceObservation>();
        foreach (var item in observationSnapshot)
        {
            if (observations.Count >= maximumEvidenceCount)
                return Error(BudgetAnomalyError.InvalidEvidenceLimit);
            if (item is null)
                return Error(BudgetAnomalyError.MissingEvidence);
            if (!item.Resource.IsValid || !item.EvidenceId.IsValid
                || item.Attachment is BudgetResourceAttachment.Unspecified
                || !Enum.IsDefined(item.Attachment))
                return Error(BudgetAnomalyError.ConflictingEvidence);
            if (item.Cell != expectedCell || item.CostCenter != expectedCostCenter)
                return Error(BudgetAnomalyError.InvalidScope);
            observations.Add(item);
        }

        var duplicate = false;
        foreach (var group in observations.GroupBy(static item => item.Resource))
        {
            if (group.Count() <= 1) continue;
            var first = group.First();
            if (!group.All(item => Same(first, item)))
                return Error(BudgetAnomalyError.ConflictingEvidence);
            duplicate = true;
        }
        if (duplicate) return Error(BudgetAnomalyError.DuplicateEvidence);
        if (observations.Any(static item => item.Status == BudgetEvidenceStatus.Unknown))
            return Error(BudgetAnomalyError.UnknownEvidence);
        if (observations.Any(static item => item.Status == BudgetEvidenceStatus.Stale))
            return Error(BudgetAnomalyError.StaleEvidence);
        if (observations.Any(item => item.Age.Value > maximumEvidenceAge.Value))
            return Error(BudgetAnomalyError.StaleEvidence);
        if (observations.Any(static item => item.Status != BudgetEvidenceStatus.Current))
            return Error(BudgetAnomalyError.UnknownEvidence);

        var findings = new List<BudgetAnomalyFinding>();
        foreach (var item in observations.OrderBy(static item => item.Resource.Value, StringComparer.Ordinal))
        {
            if (item.Owned && !item.Desired)
                findings.Add(new(item.Resource, BudgetAnomalyKind.OrphanedOwnedResource));
            if (item.Owned && item.Attachment == BudgetResourceAttachment.Unattached)
                findings.Add(new(item.Resource, BudgetAnomalyKind.UnattachedResource));
            if (item.Desired && !item.Owned)
                findings.Add(new(item.Resource, BudgetAnomalyKind.DesiredResourceMissing));
            if (item.Billed && !item.Owned)
                findings.Add(new(item.Resource, BudgetAnomalyKind.BillingWithoutOwnedResource));
            if (item.Owned && !item.Billed)
                findings.Add(new(item.Resource, BudgetAnomalyKind.OwnedResourceMissingFromBilling));
        }
        return new BudgetAnomalyResult(BudgetAnomalyError.None,
            findings.OrderBy(static item => item.Resource.Value, StringComparer.Ordinal).ThenBy(static item => item.Kind).ToArray());
    }

    private static BudgetAnomalyResult Error(BudgetAnomalyError error) => new(error, []);
    private static bool Same(BudgetResourceObservation left, BudgetResourceObservation right) =>
        left.Resource == right.Resource && left.Cell == right.Cell && left.CostCenter == right.CostCenter
        && left.EvidenceId == right.EvidenceId && left.Status == right.Status && left.Age == right.Age && left.Desired == right.Desired
        && left.Owned == right.Owned && left.Billed == right.Billed && left.Attachment == right.Attachment;
}
