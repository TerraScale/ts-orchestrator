using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery.Artifacts;

internal sealed class NatsArtifactPublicationStore(INatsJSContext context, INatsJSStream stream, string bucket) : IArtifactPublicationStore
{
    public string Bucket { get; } = bucket;

    internal static async Task<NatsArtifactPublicationStore> OpenAsync(INatsJSContext context, string cell, CancellationToken cancellationToken)
    {
        var stream = await context.GetStreamAsync("OBJ_ORCH_ARTIFACTS", cancellationToken: cancellationToken).ConfigureAwait(false);
        // The CLI discovers the provisioned replication factor; every other setting must
        // match the closed regional profile, including finite bytes, no expiry and Discard.New.
        var topology = new NatsTopology(cell, stream.Info.Config.NumReplicas);
        NatsOperationJournalStore.ValidateExactObjectConfiguration(stream.Info.Config, topology.Artifacts);
        return new(context, stream, topology.Artifacts.Bucket);
    }

    public async Task<ArtifactPublicationMessage?> ReadNextAsync(string subject, ulong after, CancellationToken cancellationToken)
    {
        try
        {
            var response = await stream.GetAsync(new StreamMsgGetRequest { NextBySubj = subject, Seq = checked(after + 1) }, cancellationToken)
                .ConfigureAwait(false);
            if (response.Message.Subject != subject || response.Message.Seq <= after)
                throw new InvalidDataException("The artifact read returned a different subject or sequence.");
            return new(response.Message.Seq, response.Message.Data);
        }
        catch (NatsJSApiException exception) when (exception.Error.ErrCode == 10037) { return null; }
    }

    public async Task<ulong?> AppendAsync(string subject, ReadOnlyMemory<byte> bytes, ulong expected, CancellationToken cancellationToken)
    {
        var ack = await context.PublishAsync(subject, bytes, serializer: NatsRawSerializer<ReadOnlyMemory<byte>>.Default,
            opts: new NatsJSPubOpts { ExpectedLastSubjectSequence = expected, RetryAttempts = 1 }, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        // 10164 is the concurrent/in-flight sequence conflict returned by newer
        // servers; 10071 is a conflict against an already committed sequence.
        if (ack.Error is { Code: 400, ErrCode: 10071 or 10164 }) return null;
        ack.EnsureSuccess();
        if (ack.Stream != stream.Info.Config.Name || ack.Seq == 0)
            throw new InvalidDataException("The artifact append was acknowledged by a different stream.");
        return ack.Seq;
    }
}
