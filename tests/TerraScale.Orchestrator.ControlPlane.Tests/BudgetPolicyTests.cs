using TerraScale.Orchestrator.ControlPlane.Budgets;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class BudgetPolicyTests
{
    [Test]
    public async Task Policy_rejects_invalid_node_bounds_duplicates_and_band_ordering()
    {
        await AssertPolicyError([new NodeClassCapacityPolicy(BudgetTestData.NodeClass(), 2, 1, 1)], BudgetPolicyError.InvalidNodeClassPolicy);
        await AssertPolicyError([new NodeClassCapacityPolicy(BudgetTestData.NodeClass(), 1, 5, 0)], BudgetPolicyError.InvalidNodeClassPolicy);
        await AssertPolicyError([
            new NodeClassCapacityPolicy(BudgetTestData.NodeClass(), 1, 5, 2),
            new NodeClassCapacityPolicy(BudgetTestData.NodeClass(), 1, 5, 2)], BudgetPolicyError.DuplicateNodeClassPolicy);

        var ok = BudgetPolicy.TryCreate(BudgetTestData.Cell(), BudgetTestData.CostCenter(), BudgetTestData.Approval(),
            BudgetEmergencyPosture.Normal, BudgetTestData.Q(100), 10, [new NodeClassCapacityPolicy(BudgetTestData.NodeClass(), 1, 5, 2)],
            BudgetTestData.Vector(40), BudgetTestData.Vector(40), BudgetTestData.Vector(50), BudgetTestData.Vector(50),
            new BudgetBandPolicy(BudgetTestData.Vector(30), BudgetTestData.Vector(30), BudgetTestData.Vector(20), BudgetTestData.Vector(20)),
            out _, out var error);
        await Assert.That(ok).IsFalse();
        await Assert.That(error).IsEqualTo(BudgetPolicyError.InvalidBandOrdering);
    }

    [Test]
    public async Task Policy_defensively_copies_and_canonically_orders_node_classes()
    {
        var nodes = new List<NodeClassCapacityPolicy?>
        {
            new(BudgetTestData.NodeClass("zeta"), 0, 3, 1),
            new(BudgetTestData.NodeClass("Alpha"), 0, 2, 0),
        };
        var policy = BudgetTestData.Policy(nodes: nodes);
        nodes.Clear();

        await Assert.That(policy.NodeClasses.Count).IsEqualTo(2);
        await Assert.That(policy.NodeClasses[0].NodeClass).IsEqualTo(BudgetTestData.NodeClass("Alpha"));
        await Assert.That(policy.NodeClasses[1].NodeClass).IsEqualTo(BudgetTestData.NodeClass("zeta"));
    }

    [Test]
    public async Task Policy_scope_posture_evidence_and_hard_limit_failures_are_typed()
    {
        await AssertCreate(default, BudgetEmergencyPosture.Normal, 10, BudgetTestData.Vector(50), BudgetPolicyError.InvalidScope);
        await AssertCreate(BudgetTestData.Cell(), BudgetEmergencyPosture.Unspecified, 10, BudgetTestData.Vector(50), BudgetPolicyError.InvalidPosture);
        await AssertCreate(BudgetTestData.Cell(), BudgetEmergencyPosture.Normal, 0, BudgetTestData.Vector(50), BudgetPolicyError.InvalidEvidenceLimit);
        await AssertCreate(BudgetTestData.Cell(), BudgetEmergencyPosture.Normal, 10, BudgetTestData.Vector(39), BudgetPolicyError.BudgetExceedsProviderLimit);

        var ok = BudgetPolicy.TryCreate(BudgetTestData.Cell(), BudgetTestData.CostCenter(), BudgetTestData.Approval(),
            BudgetEmergencyPosture.Normal, BudgetTestData.Q(100), 10,
            [new NodeClassCapacityPolicy(BudgetTestData.NodeClass(), 1, 5, 2)],
            null, BudgetTestData.Vector(40), BudgetTestData.Vector(50), BudgetTestData.Vector(50),
            new BudgetBandPolicy(BudgetTestData.Vector(20), BudgetTestData.Vector(20), BudgetTestData.Vector(30), BudgetTestData.Vector(30)),
            out _, out var error);
        await Assert.That(ok).IsFalse();
        await Assert.That(error).IsEqualTo(BudgetPolicyError.InvalidCeiling);
    }

    private static async Task AssertPolicyError(IEnumerable<NodeClassCapacityPolicy?> nodes, BudgetPolicyError expected)
    {
        var ok = BudgetPolicy.TryCreate(BudgetTestData.Cell(), BudgetTestData.CostCenter(), BudgetTestData.Approval(),
            BudgetEmergencyPosture.Normal, BudgetTestData.Q(100), 10, nodes, BudgetTestData.Vector(40), BudgetTestData.Vector(40),
            BudgetTestData.Vector(50), BudgetTestData.Vector(50),
            new BudgetBandPolicy(BudgetTestData.Vector(20), BudgetTestData.Vector(20), BudgetTestData.Vector(30), BudgetTestData.Vector(30)),
            out _, out var error);
        await Assert.That(ok).IsFalse();
        await Assert.That(error).IsEqualTo(expected);
    }

    private static async Task AssertCreate(
        BudgetCellId cell, BudgetEmergencyPosture posture, int evidenceCount,
        BudgetVector provider, BudgetPolicyError expected)
    {
        var ok = BudgetPolicy.TryCreate(cell, BudgetTestData.CostCenter(), BudgetTestData.Approval(), posture,
            BudgetTestData.Q(100), evidenceCount, [new NodeClassCapacityPolicy(BudgetTestData.NodeClass(), 1, 5, 2)],
            BudgetTestData.Vector(40), BudgetTestData.Vector(40), provider, provider,
            new BudgetBandPolicy(BudgetTestData.Vector(20), BudgetTestData.Vector(20), BudgetTestData.Vector(30), BudgetTestData.Vector(30)),
            out _, out var error);
        await Assert.That(ok).IsFalse();
        await Assert.That(error).IsEqualTo(expected);
    }
}
