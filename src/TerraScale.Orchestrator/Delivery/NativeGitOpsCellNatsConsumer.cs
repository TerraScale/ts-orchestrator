using NATS.Client.Core;
using NATS.Client.JetStream;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>
/// Pulls one raw CellSpec message from an already-reconciled durable consumer and delegates the
/// complete validation/journal/acknowledgement transaction to <see cref="NativeGitOpsCellInbox"/>.
/// </summary>
internal sealed class NativeGitOpsCellNatsConsumer(
    INatsJSConsumer consumer,
    NativeGitOpsCellInbox inbox,
    NatsTopology topology)
{
    internal async Task<NativeGitOpsCellDeliveryReceipt?> NextAsync(
        long expectedWriterEpoch,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        TimeSpan wait,
        ICommandSignatureVerifier signatureVerifier,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        if (wait <= TimeSpan.Zero || wait > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(wait));
        var message = await consumer.NextAsync<byte[]>(
            opts: new NatsJSNextOpts { Expires = wait },
            cancellationToken: cancellationToken);
        if (message is null) return null;
        message.EnsureSuccess();
        var metadata = message.Metadata;
        if (message.Data is null || message.Headers is null ||
            message.Size > NativeGitOpsCellWireCodec.MaximumWireBytes ||
            message.Subject != topology.CellSpecSubject || metadata is not { } observed)
            return Malformed();
        if (observed.Stream != NativeGitOpsCellPublisher.Stream ||
            observed.Consumer != topology.CellSpecConsumer.Name ||
            observed.Sequence.Stream == 0 || observed.Sequence.Consumer == 0 ||
            observed.NumDelivered is 0 or > 5)
            return Malformed();

        return await inbox.ProcessAsync(
            message.Data,
            Flatten(message.Headers),
            observed.Sequence.Stream,
            topology.Cell,
            expectedWriterEpoch,
            now,
            allowedClockSkew,
            signatureVerifier,
            authorityStillValid,
            token => message.AckAsync(
                new AckOpts { DoubleAck = true },
                cancellationToken: token).AsTask(),
            cancellationToken);
    }

    internal async Task<NativeGitOpsCellDeliveryReceipt?> NextWithConvergenceAsync(
        long expectedWriterEpoch,
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        TimeSpan wait,
        ICommandSignatureVerifier signatureVerifier,
        Func<bool> authorityStillValid,
        Func<NativeGitOpsAcceptedCellSpec, CancellationToken, Task<bool>> convergenceRecorded,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(convergenceRecorded);
        if (wait <= TimeSpan.Zero || wait > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(wait));
        var message = await consumer.NextAsync<byte[]>(
            opts: new NatsJSNextOpts { Expires = wait }, cancellationToken: cancellationToken);
        if (message is null) return null;
        message.EnsureSuccess();
        var metadata = message.Metadata;
        if (message.Data is null || message.Headers is null ||
            message.Size > NativeGitOpsCellWireCodec.MaximumWireBytes ||
            message.Subject != topology.CellSpecSubject || metadata is not { } observed ||
            observed.Stream != NativeGitOpsCellPublisher.Stream ||
            observed.Consumer != topology.CellSpecConsumer.Name ||
            observed.Sequence.Stream == 0 || observed.Sequence.Consumer == 0 ||
            observed.NumDelivered is 0 or > 5)
            return Malformed();

        return await inbox.ProcessWithConvergenceAsync(
            message.Data, Flatten(message.Headers), observed.Sequence.Stream, topology.Cell,
            expectedWriterEpoch, now, allowedClockSkew, signatureVerifier, authorityStillValid,
            convergenceRecorded,
            token => message.AckAsync(new AckOpts { DoubleAck = true }, cancellationToken: token).AsTask(),
            cancellationToken);
    }

    internal static IReadOnlyList<KeyValuePair<string, string>> Flatten(NatsHeaders headers)
    {
        var values = new List<KeyValuePair<string, string>>(17);
        foreach (var header in headers)
        {
            foreach (var value in header.Value)
            {
                values.Add(new(header.Key, value ?? string.Empty));
                if (values.Count == 17) return values;
            }
        }
        return values;
    }

    private static NativeGitOpsCellDeliveryReceipt Malformed() => new(
        NativeGitOpsCellDeliveryDisposition.Malformed,
        NativeGitOpsCellAcceptanceDisposition.Unspecified,
        CommandValidationError.MalformedEnvelope,
        null);
}
