using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Budgets;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class BudgetDecisionTests
{
    [Test]
    public async Task Exact_automatic_and_approval_boundaries_are_inclusive()
    {
        var automatic = BudgetTestData.Evaluate(
            policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(20)),
            proposal: BudgetTestData.Proposal(delta: BudgetTestData.Vector(10), nodeCount: 0));
        var approval = BudgetTestData.Evaluate(
            policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(19), approval: BudgetTestData.Vector(20)),
            proposal: BudgetTestData.Proposal(delta: BudgetTestData.Vector(10), nodeCount: 0));

        await Assert.That(automatic.Kind).IsEqualTo(BudgetDecisionKind.Automatic);
        await Assert.That(approval.Kind).IsEqualTo(BudgetDecisionKind.ApprovalRequired);
        await Assert.That(approval.IsAuthorized).IsFalse();
        await Assert.That(approval.ApprovalScope).IsNotNull();
    }

    [Test]
    public async Task Every_dimension_can_independently_cross_approval_and_forbidden_bands()
    {
        var dimensions = new[]
        {
            BudgetDimension.Cpu, BudgetDimension.Memory, BudgetDimension.Storage, BudgetDimension.Iops,
            BudgetDimension.Throughput, BudgetDimension.PublicIp, BudgetDimension.LoadBalancerBackend,
            BudgetDimension.HourlySpend, BudgetDimension.DailySpend,
        };
        for (var index = 0; index < dimensions.Length; index++)
        {
            var empty = BudgetTestData.Vector(0);
            var approval = BudgetTestData.Evaluate(
                policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(10), approval: BudgetTestData.Vector(20)),
                proposal: BudgetTestData.Proposal(delta: BudgetTestData.VectorAt(index, 11), nodeCount: 0),
                usage: [BudgetTestData.CellUsage(empty), BudgetTestData.GlobalUsage(empty)]);
            var forbidden = BudgetTestData.Evaluate(
                policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(10), approval: BudgetTestData.Vector(20)),
                proposal: BudgetTestData.Proposal(delta: BudgetTestData.VectorAt(index, 21), nodeCount: 0),
                usage: [BudgetTestData.CellUsage(empty), BudgetTestData.GlobalUsage(empty)]);

            await Assert.That(approval.Kind).IsEqualTo(BudgetDecisionKind.ApprovalRequired);
            await Assert.That(approval.Trace!.BindingDimensions).IsEqualTo(dimensions[index]);
            await Assert.That(forbidden.Kind).IsEqualTo(BudgetDecisionKind.Forbidden);
            await Assert.That(forbidden.Reason).IsEqualTo(BudgetDecisionReason.ForbiddenBand);
            await Assert.That(forbidden.Trace!.BindingDimensions).IsEqualTo(dimensions[index]);
        }
    }

    [Test]
    public async Task Cell_global_budget_and_provider_hard_ceilings_are_distinct()
    {
        var budget = BudgetTestData.Evaluate(
            policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(20), approval: BudgetTestData.Vector(30), ceiling: BudgetTestData.Vector(35)),
            proposal: BudgetTestData.Proposal(delta: BudgetTestData.Vector(26), nodeCount: 0));
        var provider = BudgetTestData.Evaluate(
            policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(20), approval: BudgetTestData.Vector(30), ceiling: BudgetTestData.Vector(40), provider: BudgetTestData.Vector(45)),
            proposal: BudgetTestData.Proposal(delta: BudgetTestData.Vector(36), nodeCount: 0));

        await Assert.That(budget.Reason).IsEqualTo(BudgetDecisionReason.BudgetCeilingExceeded);
        await Assert.That(provider.Reason).IsEqualTo(BudgetDecisionReason.ProviderAccountLimitExceeded);
    }

    [Test]
    public async Task Node_minimum_maximum_and_warm_capacity_are_enforced()
    {
        var belowMinimum = BudgetTestData.Evaluate(
            proposal: BudgetTestData.Proposal(BudgetTestData.Vector(1), BudgetChangeDirection.Decrease, nodeCount: 3));
        var belowWarm = BudgetTestData.Evaluate(
            proposal: BudgetTestData.Proposal(BudgetTestData.Vector(1), BudgetChangeDirection.Decrease, nodeCount: 2));
        var aboveMaximum = BudgetTestData.Evaluate(
            proposal: BudgetTestData.Proposal(BudgetTestData.Vector(1), nodeCount: 3));

        await Assert.That(belowMinimum.Reason).IsEqualTo(BudgetDecisionReason.NodeClassMinimumViolated);
        await Assert.That(belowWarm.Kind).IsEqualTo(BudgetDecisionKind.ApprovalRequired);
        await Assert.That(belowWarm.Reason).IsEqualTo(BudgetDecisionReason.WarmCapacityProtection);
        await Assert.That(aboveMaximum.Reason).IsEqualTo(BudgetDecisionReason.NodeClassMaximumExceeded);
    }

    [Test]
    public async Task Arithmetic_overflow_and_underflow_hold_without_wrapping()
    {
        var maximum = BudgetTestData.Vector(long.MaxValue);
        var overflow = BudgetTestData.Evaluate(
            proposal: BudgetTestData.Proposal(BudgetTestData.Vector(1), nodeCount: 0),
            usage: [BudgetTestData.CellUsage(maximum), BudgetTestData.GlobalUsage(maximum)]);
        var underflow = BudgetTestData.Evaluate(
            proposal: BudgetTestData.Proposal(BudgetTestData.Vector(11), BudgetChangeDirection.Decrease, nodeCount: 0));
        var nodeOverflow = BudgetTestData.Evaluate(
            proposal: BudgetTestData.Proposal(BudgetTestData.VectorAt(0, 1), nodeCount: 1),
            nodes: [BudgetTestData.NodeUsage(int.MaxValue)]);

        await Assert.That(overflow.Reason).IsEqualTo(BudgetDecisionReason.ArithmeticOverflow);
        await Assert.That(underflow.Reason).IsEqualTo(BudgetDecisionReason.ArithmeticUnderflow);
        await Assert.That(nodeOverflow.Reason).IsEqualTo(BudgetDecisionReason.ArithmeticOverflow);
    }

    [Test]
    public async Task Approval_output_is_typed_and_does_not_echo_credential_looking_identity()
    {
        const string secretLike = "resource.sk_live_SUPERSECRET";
        var decision = BudgetTestData.Evaluate(
            policy: BudgetTestData.Policy(automatic: BudgetTestData.Vector(10)),
            proposal: BudgetTestData.Proposal(resource: BudgetTestData.Resource(secretLike), nodeCount: 0));

        await Assert.That(decision.Kind).IsEqualTo(BudgetDecisionKind.ApprovalRequired);
        await Assert.That(decision.ApprovalScope!.Resource).IsEqualTo(BudgetTestData.Resource(secretLike));
        await Assert.That(decision.ApprovalScope.ToString()).DoesNotContain(secretLike);
        await Assert.That(decision.ToString()).DoesNotContain(secretLike);
        await Assert.That(decision.ToString()).DoesNotContain("SUPERSECRET");
    }

    [Test]
    public async Task Evidence_input_order_and_culture_do_not_change_decision_or_numeric_trace()
    {
        var prior = CultureInfo.CurrentCulture;
        try
        {
            var usage = new[] { BudgetTestData.GlobalUsage(), BudgetTestData.CellUsage() };
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            var first = BudgetTestData.Evaluate(usage: usage);
            Array.Reverse(usage);
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
            var second = BudgetTestData.Evaluate(usage: usage);

            await Assert.That(second.Kind).IsEqualTo(first.Kind);
            await Assert.That(second.Reason).IsEqualTo(first.Reason);
            await Assert.That(second.Trace!.ToString()).IsEqualTo(first.Trace!.ToString());
        }
        finally
        {
            CultureInfo.CurrentCulture = prior;
        }
    }
}
