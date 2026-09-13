using TerraScale.Orchestrator.ControlPlane.Budgets;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class BudgetEmergencyTests
{
    [Test]
    public async Task Emergency_rejects_non_safety_growth_and_holds_all_decreases()
    {
        var policy = BudgetTestData.Policy(BudgetEmergencyPosture.Emergency);
        var growth = BudgetTestData.Evaluate(policy, BudgetTestData.Proposal());
        var decrease = BudgetTestData.Evaluate(policy,
            BudgetTestData.Proposal(BudgetTestData.Vector(1), BudgetChangeDirection.Decrease));

        await Assert.That(growth.Kind).IsEqualTo(BudgetDecisionKind.Forbidden);
        await Assert.That(growth.Reason).IsEqualTo(BudgetDecisionReason.EmergencyNonSafetyGrowth);
        await Assert.That(decrease.Kind).IsEqualTo(BudgetDecisionKind.Held);
        await Assert.That(decrease.Reason).IsEqualTo(BudgetDecisionReason.EmergencyDecreaseHeld);
    }

    [Test]
    public async Task Emergency_data_loss_prevention_storage_expansion_bypasses_budget_not_hard_limits()
    {
        var policy = BudgetTestData.Policy(
            BudgetEmergencyPosture.Emergency,
            automatic: BudgetTestData.Vector(10),
            approval: BudgetTestData.Vector(20),
            ceiling: BudgetTestData.Vector(25),
            provider: BudgetTestData.Vector(50));
        var storageOnly = BudgetTestData.VectorAt(2, 20);
        var allowed = BudgetTestData.Evaluate(policy,
            BudgetTestData.Proposal(storageOnly, purpose: BudgetSafetyPurpose.DataLossPreventionStorageExpansion, nodeCount: 0));
        var beyondHardLimit = BudgetTestData.Evaluate(policy,
            BudgetTestData.Proposal(BudgetTestData.VectorAt(2, 41), purpose: BudgetSafetyPurpose.DataLossPreventionStorageExpansion, nodeCount: 0));

        await Assert.That(allowed.Kind).IsEqualTo(BudgetDecisionKind.Automatic);
        await Assert.That(allowed.Reason).IsEqualTo(BudgetDecisionReason.EmergencyDataLossPrevention);
        await Assert.That(beyondHardLimit.Kind).IsEqualTo(BudgetDecisionKind.Forbidden);
        await Assert.That(beyondHardLimit.Reason).IsEqualTo(BudgetDecisionReason.ProviderAccountLimitExceeded);
    }

    [Test]
    public async Task Emergency_storage_safety_claim_must_be_storage_only_and_non_terminating()
    {
        var policy = BudgetTestData.Policy(BudgetEmergencyPosture.Emergency);
        var mixed = BudgetTestData.Evaluate(policy,
            BudgetTestData.Proposal(BudgetTestData.Vector(1), purpose: BudgetSafetyPurpose.DataLossPreventionStorageExpansion, nodeCount: 0));
        var withNode = BudgetTestData.Evaluate(policy,
            BudgetTestData.Proposal(BudgetTestData.VectorAt(2, 1), purpose: BudgetSafetyPurpose.DataLossPreventionStorageExpansion, nodeCount: 1));
        var decrease = BudgetTestData.Evaluate(policy,
            BudgetTestData.Proposal(BudgetTestData.VectorAt(2, 1), BudgetChangeDirection.Decrease,
                BudgetSafetyPurpose.DataLossPreventionStorageExpansion, nodeCount: 0));

        await Assert.That(mixed.Reason).IsEqualTo(BudgetDecisionReason.InvalidEmergencySafetyClaim);
        await Assert.That(withNode.Reason).IsEqualTo(BudgetDecisionReason.InvalidEmergencySafetyClaim);
        await Assert.That(decrease.Reason).IsEqualTo(BudgetDecisionReason.EmergencyDecreaseHeld);
    }

    [Test]
    public async Task Emergency_storage_safety_domain_allows_performance_and_cost_but_rejects_capacity_piggyback()
    {
        var policy = BudgetTestData.Policy(
            BudgetEmergencyPosture.Emergency,
            automatic: BudgetTestData.Vector(10),
            approval: BudgetTestData.Vector(20),
            ceiling: BudgetTestData.Vector(25),
            provider: BudgetTestData.Vector(100));
        var storagePerformanceAndCost = new BudgetVector(
            BudgetTestData.Q(0), BudgetTestData.Q(0), BudgetTestData.Q(20),
            BudgetTestData.Q(15), BudgetTestData.Q(15), BudgetTestData.Q(0), BudgetTestData.Q(0),
            BudgetTestData.Q(5), BudgetTestData.Q(10));
        var cpuPiggyback = new BudgetVector(
            BudgetTestData.Q(1), BudgetTestData.Q(0), BudgetTestData.Q(1),
            BudgetTestData.Q(0), BudgetTestData.Q(0), BudgetTestData.Q(0), BudgetTestData.Q(0),
            BudgetTestData.Q(1), BudgetTestData.Q(1));
        var publicIpPiggyback = new BudgetVector(
            BudgetTestData.Q(0), BudgetTestData.Q(0), BudgetTestData.Q(1),
            BudgetTestData.Q(0), BudgetTestData.Q(0), BudgetTestData.Q(1), BudgetTestData.Q(0),
            BudgetTestData.Q(1), BudgetTestData.Q(1));

        var allowed = BudgetTestData.Evaluate(policy,
            BudgetTestData.Proposal(storagePerformanceAndCost,
                purpose: BudgetSafetyPurpose.DataLossPreventionStorageExpansion, nodeCount: 0));
        var cpuRejected = BudgetTestData.Evaluate(policy,
            BudgetTestData.Proposal(cpuPiggyback,
                purpose: BudgetSafetyPurpose.DataLossPreventionStorageExpansion, nodeCount: 0));
        var publicIpRejected = BudgetTestData.Evaluate(policy,
            BudgetTestData.Proposal(publicIpPiggyback,
                purpose: BudgetSafetyPurpose.DataLossPreventionStorageExpansion, nodeCount: 0));
        var nodeRejected = BudgetTestData.Evaluate(policy,
            BudgetTestData.Proposal(storagePerformanceAndCost,
                purpose: BudgetSafetyPurpose.DataLossPreventionStorageExpansion, nodeCount: 1));

        await Assert.That(allowed.Kind).IsEqualTo(BudgetDecisionKind.Automatic);
        await Assert.That(allowed.Reason).IsEqualTo(BudgetDecisionReason.EmergencyDataLossPrevention);
        await Assert.That(cpuRejected.Reason).IsEqualTo(BudgetDecisionReason.InvalidEmergencySafetyClaim);
        await Assert.That(publicIpRejected.Reason).IsEqualTo(BudgetDecisionReason.InvalidEmergencySafetyClaim);
        await Assert.That(nodeRejected.Reason).IsEqualTo(BudgetDecisionReason.InvalidEmergencySafetyClaim);
    }
}

