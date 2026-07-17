using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record RepositoryCiJobMessageMetadata(
    string Subject,
    string Stream,
    string Consumer,
    ulong StreamSequence,
    ulong ConsumerSequence,
    ulong DeliveryCount,
    int MessageSize);

/// <summary>
/// Pulls one raw command from an already-reconciled runner-specific consumer and delegates its
/// validation, durable acceptance, and double acknowledgement to the runner inbox.
/// </summary>
internal sealed class RepositoryCiJobNatsConsumer
{
    private readonly INatsJSConsumer consumer;
    private readonly RepositoryCiJobInbox inbox;
    private readonly ConsumerConfig configuration;
    private readonly string runner;

    internal RepositoryCiJobNatsConsumer(
        INatsJSConsumer consumer,
        RepositoryCiJobInbox inbox,
        GlobalNatsTopology topology,
        string zone,
        string runner)
    {
        this.consumer = consumer ?? throw new ArgumentNullException(nameof(consumer));
        this.inbox = inbox ?? throw new ArgumentNullException(nameof(inbox));
        ArgumentNullException.ThrowIfNull(topology);
        configuration = topology.CiJobConsumer(zone, runner);
        this.runner = runner;
    }

    internal async Task<RepositoryCiJobDeliveryReceipt?> NextAsync(
        DateTimeOffset now,
        TimeSpan allowedClockSkew,
        TimeSpan wait,
        ICommandSignatureVerifier signatureVerifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signatureVerifier);
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

        return await inbox.ProcessAsync(
            message.Data,
            Flatten(message.Headers),
            observed.Sequence.Stream,
            runner,
            now,
            allowedClockSkew,
            signatureVerifier,
            token => message.AckAsync(
                new AckOpts { DoubleAck = true },
                cancellationToken: token).AsTask(),
            cancellationToken);
    }

    internal static bool ValidMetadata(
        RepositoryCiJobMessageMetadata metadata,
        ConsumerConfig configuration) =>
        metadata.Subject == configuration.FilterSubject &&
        metadata.Stream == GlobalNatsTopology.CiStream &&
        metadata.Consumer == configuration.Name &&
        metadata.StreamSequence > 0 && metadata.ConsumerSequence > 0 &&
        metadata.DeliveryCount is > 0 and <= 5 &&
        metadata.MessageSize is > 0 and <= RepositoryCiJobWireCodec.MaximumWireBytes;

    internal static IReadOnlyList<KeyValuePair<string, string>> Flatten(NatsHeaders headers)
    {
        var values = new List<KeyValuePair<string, string>>(RepositoryCiJobWireCodec.ExpectedHeaderCount + 1);
        foreach (var header in headers)
        {
            foreach (var value in header.Value)
            {
                values.Add(new(header.Key, value ?? string.Empty));
                if (values.Count == RepositoryCiJobWireCodec.ExpectedHeaderCount + 1) return values;
            }
        }
        return values;
    }

    private static RepositoryCiJobDeliveryReceipt Malformed() => new(
        RepositoryCiJobDeliveryDisposition.Malformed,
        RepositoryCiJobAcceptanceDisposition.Unspecified,
        CommandValidationError.MalformedEnvelope,
        null);
}
