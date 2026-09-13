using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Issue #7 notification failure isolation, delivery-budget half: a retry disposition on the
/// consumer's final allowed delivery must be loud — after that nak the Forgejo commit status
/// for the revision never lands, and that operator-visible fact may never be silent.
/// </summary>
public sealed class ForgejoCiEventConsumerTests
{
    [Test]
    public async Task TheFinalAllowedDeliveryIsExactlyTheOneAtTheDeliveryCap()
    {
        await Assert.That(ForgejoCiEventConsumer.IsFinalDelivery(5, 5)).IsTrue();
        await Assert.That(ForgejoCiEventConsumer.IsFinalDelivery(4, 5)).IsFalse();
        await Assert.That(ForgejoCiEventConsumer.IsFinalDelivery(1, 5)).IsFalse();
        // Defensive shapes: no metadata, no deliveries, or an unset cap never claim finality.
        await Assert.That(ForgejoCiEventConsumer.IsFinalDelivery(null, 5)).IsFalse();
        await Assert.That(ForgejoCiEventConsumer.IsFinalDelivery(0, 5)).IsFalse();
        await Assert.That(ForgejoCiEventConsumer.IsFinalDelivery(5, 0)).IsFalse();
        await Assert.That(ForgejoCiEventConsumer.IsFinalDelivery(null, 0)).IsFalse();
    }

    [Test]
    public async Task AnExhaustedDeliveryBudgetWarnsLoudlyAndABudgetedOneStaysQuiet()
    {
        // Fake consumer metadata: NumDelivered == MaxDeliver (the repository topology's
        // global CI trigger consumer caps deliveries at 5).
        var warning = ForgejoCiEventConsumer.FinalDeliveryWarning(5, 5, "ts.orch.v1.global.ci.trigger");
        var quiet = ForgejoCiEventConsumer.FinalDeliveryWarning(4, 5, "ts.orch.v1.global.ci.trigger");

        await Assert.That(quiet).IsNull();
        await Assert.That(warning).IsNotNull();
        await Assert.That(warning).Contains("delivery budget exhausted");
        await Assert.That(warning).Contains("ts.orch.v1.global.ci.trigger");
        await Assert.That(warning).Contains("delivery 5 of 5");
        await Assert.That(warning).Contains("commit status");
        await Assert.That(warning).Contains("Operator action required");
        // Bounded operator line: single line, no payload material.
        await Assert.That(warning).DoesNotContain("\n");
    }

    [Test]
    public async Task TheExhaustionWarningBoundsAHostileSubject()
    {
        var hostile = new string('x', 400);
        var warning = ForgejoCiEventConsumer.FinalDeliveryWarning(5, 5, hostile);

        await Assert.That(warning).IsNotNull();
        await Assert.That(warning).DoesNotContain(hostile);
        await Assert.That(warning).Contains(new string('x', 256));
        // An absent or blank subject still produces a bounded, actionable line.
        await Assert.That(ForgejoCiEventConsumer.FinalDeliveryWarning(5, 5, null!)).IsNotNull();
        await Assert.That(ForgejoCiEventConsumer.FinalDeliveryWarning(5, 5, "  ")).IsNotNull();
    }
}

