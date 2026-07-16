using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Budgets;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class BudgetPrimitiveTests
{
    [Test]
    public async Task Identities_are_bounded_and_quantities_reject_negative_values()
    {
        foreach (var invalid in new string?[] { null, "", "two words", "nul\0x", "\uD800", "\uDC00" })
            await Assert.That(BudgetCellId.TryCreate(invalid, 64, out _)).IsFalse();
        await Assert.That(BudgetNodeClassId.TryCreate("ab", 1, out _)).IsFalse();
        await Assert.That(BudgetCostCenterId.TryCreate("a", 0, out _)).IsFalse();
        await Assert.That(BudgetResourceId.TryCreate("resource", 8, out _)).IsTrue();
        await Assert.That(PriceEvidenceId.TryCreate("price", 8, out _)).IsTrue();
        await Assert.That(BudgetApprovalId.TryCreate("approval", 8, out _)).IsTrue();
        await Assert.That(BudgetQuantity.TryCreate(-1, out _)).IsFalse();
        await Assert.That(BudgetQuantity.TryCreate(0, out var zero)).IsTrue();
        await Assert.That(BudgetQuantity.TryCreate(long.MaxValue, out var maximum)).IsTrue();
        await Assert.That(zero.Value).IsEqualTo(0);
        await Assert.That(maximum.Value).IsEqualTo(long.MaxValue);
    }

    [Test]
    public async Task Numeric_vector_format_is_complete_stable_and_culture_invariant()
    {
        var prior = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            var rendered = new BudgetVector(
                BudgetTestData.Q(1), BudgetTestData.Q(2), BudgetTestData.Q(3), BudgetTestData.Q(4),
                BudgetTestData.Q(5), BudgetTestData.Q(6), BudgetTestData.Q(7), BudgetTestData.Q(8), BudgetTestData.Q(9)).ToString();
            await Assert.That(rendered).IsEqualTo("cpu=1;memory=2;storage=3;iops=4;throughput=5;publicIp=6;lbBackend=7;hourly=8;daily=9");
        }
        finally
        {
            CultureInfo.CurrentCulture = prior;
        }
    }

    [Test]
    public async Task Default_decision_is_not_authorized()
    {
        var decision = default(BudgetDecision);
        await Assert.That(decision.IsAuthorized).IsFalse();
        await Assert.That(decision.Kind).IsEqualTo(BudgetDecisionKind.Uninitialized);
        await Assert.That(decision.Reason).IsEqualTo(BudgetDecisionReason.Uninitialized);
    }
}
