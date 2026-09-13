using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record NativeGitOpsGlobalCellMessageMetadata(
    string Subject,
    string Stream,
    string Consumer,
    ulong StreamSequence,
    ulong ConsumerSequence,
    ulong DeliveryCount,
    int MessageSize);

/// <summary>
/// Pulls one globally stored CellSpec from the exact cell consumer and delegates its validation,
/// regional storage, and double acknowledgement to <see cref="NativeGitOpsGlobalCellRelay"/>.
/// </summary>
internal sealed class NativeGitOpsGlobalCellNatsConsumer
{
    private readonly INatsJSConsumer consumer;
    private readonly NativeGitOpsGlobalCellRelay relay;
    private readonly ConsumerConfig configuration;
    private readonly string cell;

    internal NativeGitOpsGlobalCellNatsConsumer(
        INatsJSConsumer consumer,
        NativeGitOpsGlobalCellRelay relay,
        GlobalNatsTopology topology,
        string cell)
    {
        this.consumer = consumer ?? throw new ArgumentNullException(nameof(consumer));
        this.relay = relay ?? throw new ArgumentNullException(nameof(relay));
        ArgumentNullException.ThrowIfNull(topology);
        configuration = topology.CellSpecConsumer(cell);
        this.cell = cell;
    }

    internal async Task<NativeGitOpsGlobalCellRelayReceipt?> NextAsync(
        long expectedWriterEpoch,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        TimeSpan wait,
        ICommandSignatureVerifier signatureVerifier,
        Func<bool> regionalAuthorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(regionalAuthorityStillValid);
        if (expectedWriterEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(expectedWriterEpoch));
        if (allowedClockSkew < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(allowedClockSkew));
        if (wait <= TimeSpan.Zero || wait > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(wait));
        var message = await consumer.NextAsync<byte[]>(
            opts: new NatsJSNextOpts { Expires = wait },
            cancellationToken: cancellationToken);
        if (message is null) return null;
        message.EnsureSuccess();
        var metadata = message.Metadata;
        if (message.Data is null || message.Headers is null || metadata is not { } observed ||
            !ValidMetadata(new(
                message.Subject,
                observed.Stream,
                observed.Consumer,
                observed.Sequence.Stream,
                observed.Sequence.Consumer,
                observed.NumDelivered,
                message.Size), configuration))
            return Malformed();

        return await relay.RelayAsync(
            message.Data,
            Flatten(message.Headers),
            cell,
            expectedWriterEpoch,
            now,
            allowedClockSkew,
            signatureVerifier,
            regionalAuthorityStillValid,
            token => message.AckAsync(
                new AckOpts { DoubleAck = true },
                cancellationToken: token).AsTask(),
            cancellationToken);
    }

    internal static bool ValidMetadata(
        NativeGitOpsGlobalCellMessageMetadata metadata,
        ConsumerConfig configuration) =>
        metadata.Subject == configuration.FilterSubject &&
        metadata.Stream == GlobalNatsTopology.CellSpecStream &&
        metadata.Consumer == configuration.Name &&
        metadata.StreamSequence > 0 && metadata.ConsumerSequence > 0 &&
        configuration.MaxDeliver > 0 && metadata.DeliveryCount is > 0 &&
        metadata.DeliveryCount <= (ulong)configuration.MaxDeliver &&
        metadata.MessageSize is > 0 and <= NativeGitOpsCellWireCodec.MaximumWireBytes;

    internal static IReadOnlyList<KeyValuePair<string, string>> Flatten(NatsHeaders headers) =>
        NativeGitOpsCellNatsConsumer.Flatten(headers);

    private static NativeGitOpsGlobalCellRelayReceipt Malformed() => new(
        NativeGitOpsGlobalCellRelayDisposition.Malformed,
        NativeGitOpsCellEnvelopeError.InvalidInput,
        CommandValidationError.MalformedEnvelope,
        null);
}

