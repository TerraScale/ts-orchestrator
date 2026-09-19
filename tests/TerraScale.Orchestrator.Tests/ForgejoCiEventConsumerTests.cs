using System.Net;
using Oci.Common.Model;
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
    public async Task OperationalOciProviderFailuresRetryAndDurableRejectionsTerminate()
    {
        // One 429 throttle, 409 OutOfHostCapacity (the norm for VM.Standard.A1.Flex), 5xx, or a
        // transport-level timeout is operational: the CI event must retry via redelivery, never
        // be ack-terminated with its commit status unreported and its runners orphaned.
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(Oci(429, "TooManyRequests")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Retry);
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(Oci(409, "OutOfHostCapacity")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Retry);
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(Oci(500, "InternalError")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Retry);
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(Oci(503, "Unavailable")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Retry);
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(Oci(408, "RequestTimeout")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Retry);
        // A stale ETag fence (the instance changed between observation and mutation) is a
        // concurrency outcome: the next observe re-reads the ETag and the retry succeeds.
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(Oci(412, "PreconditionFailed")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Retry);
        // The SDK wraps transport failures (connect timeouts, resets) without a status.
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(
                new OciException("The OCI request timed out.", new TimeoutException())))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Retry);

        // Durable provider rejections are deterministic on every redelivery: terminate.
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(Oci(401, "NotAuthenticated")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Terminal);
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(Oci(403, "NotAuthorizedOrNotFound")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Terminal);
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(Oci(404, "NotFound")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Terminal);
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(Oci(400, "InvalidParameter")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Terminal);
    }

    private static OciException Oci(int status, string serviceCode) =>
        new((HttpStatusCode)status, $"OCI responded {status}.", serviceCode, "ocid1.request.oc1..test");

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

