using NATS.Client.JetStream;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record RepositoryCiRuntimeObservationTransportAck(
    string Stream,
    ulong Sequence,
    bool Duplicate);

internal interface IRepositoryCiRuntimeObservationTransport
{
    Task<RepositoryCiRuntimeObservationTransportAck> PublishAsync(
        string messageId,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken);
}

internal sealed class NatsRepositoryCiRuntimeObservationTransport(NatsClient client)
    : IRepositoryCiRuntimeObservationTransport
{
    public async Task<RepositoryCiRuntimeObservationTransportAck> PublishAsync(
        string messageId,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        var acknowledgement = await client.CreateJetStreamContext().PublishAsync(
            GlobalNatsTopology.CiRuntimeProofSubject,
            payload.ToArray(),
            opts: new NatsJSPubOpts
            {
                MsgId = messageId,
                ExpectedStream = GlobalNatsTopology.CiStream,
                RetryAttempts = 3,
                RetryWaitBetweenAttempts = TimeSpan.FromMilliseconds(250),
            },
            cancellationToken: cancellationToken);
        acknowledgement.EnsureSuccess();
        return new(
            acknowledgement.Stream ?? string.Empty,
            acknowledgement.Seq,
            acknowledgement.Duplicate);
    }
}

internal sealed class RepositoryCiRuntimeObservationPublisher(
    IRepositoryCiRuntimeObservationTransport transport)
{
    private readonly IRepositoryCiRuntimeObservationTransport transport = transport ??
        throw new ArgumentNullException(nameof(transport));

    internal async Task<RepositoryCiRuntimeObservationTransportAck> PublishAsync(
        RepositoryCiSignedRuntimeObservation runtime,
        CancellationToken cancellationToken = default)
    {
        var acknowledgement = await transport.PublishAsync(
            RepositoryCiRuntimeObservationWireCodec.MessageId(runtime),
            RepositoryCiRuntimeObservationWireCodec.Encode(runtime),
            cancellationToken);
        if (acknowledgement.Stream != GlobalNatsTopology.CiStream || acknowledgement.Sequence == 0)
            throw new InvalidDataException("The runtime observation was not durably stored in GLOBAL_CI.");
        return acknowledgement;
    }
}

internal enum RepositoryCiRuntimeObservationInboxDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    InvalidProof,
    AuthorityLost,
    IdentityConflict,
}

internal sealed record RepositoryCiRuntimeObservationInboxReceipt(
    RepositoryCiRuntimeObservationInboxDisposition Disposition,
    RepositoryCiSignedRuntimeObservation? Runtime)
{
    internal bool CanAcknowledge => Disposition is
        RepositoryCiRuntimeObservationInboxDisposition.Recorded or
        RepositoryCiRuntimeObservationInboxDisposition.Duplicate;
}

/// <summary>Verifies one signed matching-architecture observation before fenced durable storage.</summary>
internal sealed class RepositoryCiRuntimeObservationInbox(
    RepositoryCiArtifactAttestationJournal journal,
    IRepositoryCiArtifactSignatureVerifier verifier)
{
    private readonly RepositoryCiArtifactAttestationJournal journal = journal ??
        throw new ArgumentNullException(nameof(journal));
    private readonly IRepositoryCiArtifactSignatureVerifier verifier = verifier ??
        throw new ArgumentNullException(nameof(verifier));

    internal async Task<RepositoryCiRuntimeObservationInboxReceipt> HandleAsync(
        ReadOnlyMemory<byte> payload,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        RepositoryCiSignedRuntimeObservation runtime;
        try
        {
            runtime = RepositoryCiRuntimeObservationWireCodec.Decode(payload.Span);
        }
        catch (InvalidDataException)
        {
            return new(RepositoryCiRuntimeObservationInboxDisposition.InvalidProof, null);
        }
        if (!RepositoryCiArtifactAttestation.ValidateRuntime(runtime, verifier))
            return new(RepositoryCiRuntimeObservationInboxDisposition.InvalidProof, runtime);
        if (!authorityStillValid())
            return new(RepositoryCiRuntimeObservationInboxDisposition.AuthorityLost, runtime);
        var disposition = await journal.RecordRuntimeAsync(
            runtime,
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
        return new(disposition switch
        {
            RepositoryCiArtifactAttestationJournalDisposition.Recorded =>
                RepositoryCiRuntimeObservationInboxDisposition.Recorded,
            RepositoryCiArtifactAttestationJournalDisposition.Duplicate =>
                RepositoryCiRuntimeObservationInboxDisposition.Duplicate,
            RepositoryCiArtifactAttestationJournalDisposition.StaleAuthority =>
                RepositoryCiRuntimeObservationInboxDisposition.AuthorityLost,
            RepositoryCiArtifactAttestationJournalDisposition.IdentityConflict =>
                RepositoryCiRuntimeObservationInboxDisposition.IdentityConflict,
            _ => throw new InvalidDataException("The runtime proof journal returned an unspecified disposition."),
        }, runtime);
    }
}
