using TerraScale.Orchestrator.Contracts;

namespace TerraScale.Orchestrator.Protocol.Tests;

public class StrongValueObjectTests
{
    [Test]
    public async Task Identifiers_reject_empty_whitespace_and_nul()
    {
        var invalidValues = new string?[] { null, string.Empty, " ", "\t", "cell\0suffix" };

        foreach (var value in invalidValues)
        {
            await Assert.That(CellId.TryCreate(value, out var cell)).IsFalse();
            await Assert.That(cell.IsValid).IsFalse();
            await Assert.That(AggregateId.TryCreate(value, out var aggregate)).IsFalse();
            await Assert.That(aggregate.IsValid).IsFalse();
            await Assert.That(OperationId.TryCreate(value, out var operation)).IsFalse();
            await Assert.That(operation.IsValid).IsFalse();
            await Assert.That(IdempotencyKey.TryCreate(value, out var idempotency)).IsFalse();
            await Assert.That(idempotency.IsValid).IsFalse();
        }
    }

    [Test]
    public async Task Identifiers_preserve_caller_supplied_identity_exactly()
    {
        const string value = "Cell/Case-Sensitive:01";

        await Assert.That(CellId.TryCreate(value, out var cell)).IsTrue();
        await Assert.That(cell.Value).IsEqualTo(value);
        await Assert.That(cell.ToString()).IsEqualTo(value);
        await Assert.That(CellId.TryCreate(value.ToLowerInvariant(), out var lower)).IsTrue();
        await Assert.That(cell).IsNotEqualTo(lower);
    }

    [Test]
    public async Task Positive_protocol_numbers_reject_zero_and_negative_values()
    {
        foreach (var value in new long[] { long.MinValue, -1, 0 })
        {
            await Assert.That(ProtocolRevision.TryCreate(value, out var protocol)).IsFalse();
            await Assert.That(protocol.IsValid).IsFalse();
            await Assert.That(DesiredGeneration.TryCreate(value, out var generation)).IsFalse();
            await Assert.That(generation.IsValid).IsFalse();
            await Assert.That(WriterEpoch.TryCreate(value, out var epoch)).IsFalse();
            await Assert.That(epoch.IsValid).IsFalse();
            await Assert.That(DeliveryAttempt.TryCreate(value, out var attempt)).IsFalse();
            await Assert.That(attempt.IsValid).IsFalse();
        }
    }

    [Test]
    public async Task Positive_protocol_numbers_accept_full_positive_range()
    {
        foreach (var value in new long[] { 1, 2, long.MaxValue })
        {
            await Assert.That(ProtocolRevision.TryCreate(value, out var protocol)).IsTrue();
            await Assert.That(protocol.Value).IsEqualTo(value);
            await Assert.That(DesiredGeneration.TryCreate(value, out var generation)).IsTrue();
            await Assert.That(generation.Value).IsEqualTo(value);
            await Assert.That(WriterEpoch.TryCreate(value, out var epoch)).IsTrue();
            await Assert.That(epoch.Value).IsEqualTo(value);
            await Assert.That(DeliveryAttempt.TryCreate(value, out var attempt)).IsTrue();
            await Assert.That(attempt.Value).IsEqualTo(value);
        }
    }
}

