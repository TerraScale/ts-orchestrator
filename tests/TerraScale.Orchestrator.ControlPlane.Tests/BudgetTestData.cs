using TerraScale.Orchestrator.ControlPlane.Budgets;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

internal static class BudgetTestData
{
    public const int IdLimit = 64;
    public static BudgetCellId Cell(string value = "gru") { BudgetCellId.TryCreate(value, IdLimit, out var result); return result; }
    public static BudgetNodeClassId NodeClass(string value = "a1-compact") { BudgetNodeClassId.TryCreate(value, IdLimit, out var result); return result; }
    public static BudgetCostCenterId CostCenter(string value = "platform") { BudgetCostCenterId.TryCreate(value, IdLimit, out var result); return result; }
    public static BudgetResourceId Resource(string value = "node-42") { BudgetResourceId.TryCreate(value, IdLimit, out var result); return result; }
    public static PriceEvidenceId Evidence(string value = "price-v1") { PriceEvidenceId.TryCreate(value, IdLimit, out var result); return result; }
    public static BudgetApprovalId Approval(string value = "platform-approval") { BudgetApprovalId.TryCreate(value, IdLimit, out var result); return result; }
    public static BudgetQuantity Q(long value) { BudgetQuantity.TryCreate(value, out var result); return result; }

    public static BudgetVector Vector(long value) =>
        new(Q(value), Q(value), Q(value), Q(value), Q(value), Q(value), Q(value), Q(value), Q(value));

    public static BudgetVector VectorAt(int dimension, long value)
    {
        var values = new long[9];
        values[dimension] = value;
        return new(Q(values[0]), Q(values[1]), Q(values[2]), Q(values[3]), Q(values[4]),
            Q(values[5]), Q(values[6]), Q(values[7]), Q(values[8]));
    }

    public static BudgetPolicy Policy(
        BudgetEmergencyPosture posture = BudgetEmergencyPosture.Normal,
        BudgetVector? automatic = null,
        BudgetVector? approval = null,
        BudgetVector? ceiling = null,
        BudgetVector? provider = null,
        int maximumEvidence = 16,
        IEnumerable<NodeClassCapacityPolicy?>? nodes = null)
    {
        var auto = automatic ?? Vector(20);
        var approvalMaximum = approval ?? Vector(30);
        var budgetCeiling = ceiling ?? Vector(40);
        var providerLimit = provider ?? Vector(50);
        BudgetPolicy.TryCreate(Cell(), CostCenter(), Approval(), posture, Q(100),
            maximumEvidence,
            nodes ?? [new NodeClassCapacityPolicy(NodeClass(), 1, 5, 2)],
            budgetCeiling, budgetCeiling, providerLimit, providerLimit,
            new BudgetBandPolicy(auto, auto, approvalMaximum, approvalMaximum), out var result, out _);
        return result!;
    }

    public static BudgetProposal Proposal(
        BudgetVector? delta = null,
        BudgetChangeDirection direction = BudgetChangeDirection.Increase,
        BudgetSafetyPurpose purpose = BudgetSafetyPurpose.OrdinaryCapacity,
        int nodeCount = 1,
        BudgetResourceId? resource = null,
        BudgetCellId? cell = null,
        BudgetCostCenterId? costCenter = null,
        BudgetNodeClassId? nodeClass = null,
        PriceEvidenceId? price = null) =>
        new(resource ?? Resource(), cell ?? Cell(), costCenter ?? CostCenter(), nodeClass ?? NodeClass(),
            price ?? Evidence(), direction, purpose, nodeCount, delta ?? Vector(1));

    public static BudgetUsageObservation CellUsage(
        BudgetVector? usage = null, BudgetEvidenceStatus status = BudgetEvidenceStatus.Current,
        BudgetCellId? cell = null, BudgetCostCenterId? costCenter = null, long age = 1) =>
        new(BudgetUsageScope.Cell, cell ?? Cell(), costCenter ?? CostCenter(), Evidence("cell-usage"), status, Q(age), usage ?? Vector(10));

    public static BudgetUsageObservation GlobalUsage(
        BudgetVector? usage = null, BudgetEvidenceStatus status = BudgetEvidenceStatus.Current,
        BudgetCellId cell = default, BudgetCostCenterId? costCenter = null, long age = 1) =>
        new(BudgetUsageScope.Global, cell, costCenter ?? CostCenter(), Evidence("global-usage"), status, Q(age), usage ?? Vector(10));

    public static NodeClassUsageObservation NodeUsage(
        int count = 3, BudgetEvidenceStatus status = BudgetEvidenceStatus.Current,
        BudgetNodeClassId? nodeClass = null, BudgetCellId? cell = null, BudgetCostCenterId? costCenter = null, long age = 1) =>
        new(cell ?? Cell(), costCenter ?? CostCenter(), nodeClass ?? NodeClass(), Evidence("node-usage"), status, Q(age), count);

    public static PriceEvidenceObservation Price(
        BudgetEvidenceStatus status = BudgetEvidenceStatus.Current,
        PriceEvidenceId? id = null, BudgetCostCenterId? costCenter = null, long age = 1) =>
        new(id ?? Evidence(), costCenter ?? CostCenter(), status, Q(age));

    public static BudgetDecision Evaluate(
        BudgetPolicy? policy = null,
        BudgetProposal? proposal = null,
        IEnumerable<BudgetUsageObservation?>? usage = null,
        IEnumerable<NodeClassUsageObservation?>? nodes = null,
        IEnumerable<PriceEvidenceObservation?>? prices = null) =>
        BudgetAuthorizationEngine.Evaluate(policy ?? Policy(), proposal ?? Proposal(),
            usage ?? [CellUsage(), GlobalUsage()], nodes ?? [NodeUsage()], prices ?? [Price()]);
}
