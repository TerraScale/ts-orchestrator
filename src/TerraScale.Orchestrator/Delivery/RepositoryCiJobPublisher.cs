using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Net;
using TerraScale.Orchestrator.Contracts;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiJobPublishDisposition
{
    Unspecified,
    Published,
    Duplicate,
    Expired,
    AuthorityLostBeforePublish,
    AuthorityLostAfterPublish,
}

internal sealed record RepositoryCiJobPublishReceipt(
    RepositoryCiJobPublishDisposition Disposition,
    string Subject,
    string MessageId,
    string PayloadDigest,
    ulong StreamSequence)
{
    internal bool IsDurable =>
        (Disposition is RepositoryCiJobPublishDisposition.Published or
            RepositoryCiJobPublishDisposition.Duplicate or
            RepositoryCiJobPublishDisposition.AuthorityLostAfterPublish) &&
        StreamSequence > 0;
}

internal sealed record RepositoryCiJobTransportAck(string Stream, ulong Sequence, bool Duplicate);

internal sealed record RepositoryCiJobWireMessage(
    ReadOnlyMemory<byte> Payload,
    IReadOnlyDictionary<string, string> Headers,
    string PayloadDigest);

internal sealed record RepositoryCiDecodedJobCommand(
    RepositoryCiJobWireDocument Document,
    CommandEnvelope Envelope);

internal interface IRepositoryCiJobSigner
{
    OpaqueSignature Sign(CommandSignedMaterial material);
}

internal interface IRepositoryCiJobTransport
{
    Task<RepositoryCiJobTransportAck> PublishAsync(
        string subject,
        string messageId,
        RepositoryCiJobWireMessage message,
        CancellationToken cancellationToken);
}

internal sealed class NatsRepositoryCiJobTransport(NatsClient client) : IRepositoryCiJobTransport
{
    public async Task<RepositoryCiJobTransportAck> PublishAsync(
        string subject,
        string messageId,
        RepositoryCiJobWireMessage message,
        CancellationToken cancellationToken)
    {
        var headers = new NatsHeaders();
        foreach (var header in message.Headers) headers[header.Key] = header.Value;
        var acknowledgement = await client.CreateJetStreamContext().PublishAsync(
            subject,
            message.Payload.ToArray(),
            opts: new NatsJSPubOpts
            {
                MsgId = messageId,
                ExpectedStream = GlobalNatsTopology.CiStream,
                RetryAttempts = 3,
                RetryWaitBetweenAttempts = TimeSpan.FromMilliseconds(250),
            },
            headers: headers,
            cancellationToken: cancellationToken);
        acknowledgement.EnsureSuccess();
        return new(acknowledgement.Stream ?? string.Empty, acknowledgement.Seq, acknowledgement.Duplicate);
    }
}

/// <summary>Publishes one already-prepared fenced CI attempt and requires a GLOBAL_CI storage acknowledgement.</summary>
internal sealed class RepositoryCiJobPublisher(
    IRepositoryCiJobTransport transport,
    IRepositoryCiJobSigner signer,
    TimeProvider? timeProvider = null)
{
    private readonly IRepositoryCiJobTransport transport = transport ??
        throw new ArgumentNullException(nameof(transport));
    private readonly IRepositoryCiJobSigner signer = signer ?? throw new ArgumentNullException(nameof(signer));
    private readonly TimeProvider timeProvider = timeProvider ?? TimeProvider.System;

    internal async Task<RepositoryCiJobPublishReceipt> PublishAsync(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiJobSnapshot prepared,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        var subject = Subject(prepared);
        var messageId = MessageId(prepared);
        var now = timeProvider.GetUtcNow();
        if (prepared.PreparedAt is not { } issued || prepared.ExpiresAt is not { } expires ||
            now < issued.AddMinutes(-1))
            throw new InvalidDataException("The prepared CI job clock evidence is invalid.");
        if (now >= expires)
            return new(RepositoryCiJobPublishDisposition.Expired, subject, messageId, string.Empty, 0);
        if (!authorityStillValid())
            return new(
                RepositoryCiJobPublishDisposition.AuthorityLostBeforePublish,
                subject,
                messageId,
                string.Empty,
                0);
        var message = RepositoryCiJobWireCodec.Encode(pipeline, prepared, signer);
        if (!authorityStillValid())
            return new(
                RepositoryCiJobPublishDisposition.AuthorityLostBeforePublish,
                subject,
                messageId,
                message.PayloadDigest,
                0);

        var acknowledgement = await transport.PublishAsync(
            subject,
            messageId,
            message,
            cancellationToken);
        if (acknowledgement.Stream != GlobalNatsTopology.CiStream || acknowledgement.Sequence == 0)
            throw new InvalidDataException("The CI job publish acknowledgement is invalid.");
        if (!authorityStillValid())
            return new(
                RepositoryCiJobPublishDisposition.AuthorityLostAfterPublish,
                subject,
                messageId,
                message.PayloadDigest,
                acknowledgement.Sequence);
        return new(
            acknowledgement.Duplicate
                ? RepositoryCiJobPublishDisposition.Duplicate
                : RepositoryCiJobPublishDisposition.Published,
            subject,
            messageId,
            message.PayloadDigest,
            acknowledgement.Sequence);
    }

    private static string Subject(RepositoryCiJobSnapshot prepared)
    {
        var zone = prepared.Job.Request.AllowedZones.Single() switch
        {
            TrustZone.UntrustedProduct => "untrusted-product",
            TrustZone.TrustedBuild => "trusted-build",
            _ => throw new InvalidDataException("The repository CI job has no publishable trust zone."),
        };
        return GlobalNatsTopology.CiJobSubject(zone, prepared.RunnerId);
    }

    private static string MessageId(RepositoryCiJobSnapshot prepared) =>
        $"ci-job:{prepared.Document.PipelineDigest}:{Hash(prepared.Job.Request.Job.Value)[..24]}:" +
        $"{prepared.Attempt}:{prepared.FencingToken}";

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

/// <summary>Advances to dispatched only after the exact prepared attempt receives durable storage acknowledgement.</summary>
internal sealed class RepositoryCiJobDispatcher(
    RepositoryCiJobJournal journal,
    RepositoryCiJobPublisher publisher)
{
    internal async Task<RepositoryCiJobDispatchReceipt> DispatchAsync(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiJobSnapshot prepared,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        var publication = await publisher.PublishAsync(pipeline, prepared, authorityStillValid, cancellationToken);
        if (publication.Disposition is RepositoryCiJobPublishDisposition.Expired or
            RepositoryCiJobPublishDisposition.AuthorityLostBeforePublish or
            RepositoryCiJobPublishDisposition.AuthorityLostAfterPublish)
            return new(publication, null);
        var transition = await journal.AdvanceAsync(
            prepared,
            RepositoryCiJobPhase.Dispatched,
            publication.PayloadDigest,
            0,
            RepositoryCiJobFailureKind.Unspecified,
            publication.StreamSequence,
            authorityStillValid,
            cancellationToken);
        return new(publication, transition);
    }
}

internal sealed record RepositoryCiJobDispatchReceipt(
    RepositoryCiJobPublishReceipt Publication,
    RepositoryCiJobJournalReceipt? Transition)
{
    internal bool IsDispatched => Transition?.Disposition is
        RepositoryCiJobJournalDisposition.Advanced or RepositoryCiJobJournalDisposition.Duplicate;
}

internal static class RepositoryCiJobWireCodec
{
    internal const int MaximumPayloadBytes = 64 * 1024;
    internal const int MaximumSignatureBytes = 16 * 1024;
    internal const int MaximumWireBytes = 128 * 1024;
    internal const int ExpectedHeaderCount = 12;
    private const int MaximumHeaderBytes = 64 * 1024;
    private const string Schema = "TS-CI-Job-Schema";
    private const string Protocol = "TS-Protocol-Version";
    private const string Type = "TS-Message-Type";
    private const string Pipeline = "TS-Pipeline-Digest";
    private const string Job = "TS-Job-Id";
    private const string Attempt = "TS-Job-Attempt";
    private const string Fence = "TS-Fencing-Token";
    private const string Runner = "TS-Runner-Id";
    private const string Issued = "TS-Issued-At";
    private const string Expires = "TS-Expires-At";
    private const string PayloadSha256 = "TS-Payload-Sha256";
    private const string Signature = "TS-Signature";

    internal static RepositoryCiJobWireMessage Encode(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiJobSnapshot prepared,
        IRepositoryCiJobSigner signer)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(prepared);
        ArgumentNullException.ThrowIfNull(signer);
        if (prepared.Phase != RepositoryCiJobPhase.DispatchPrepared)
            throw new InvalidDataException("Only a prepared CI job can be encoded.");
        var document = RepositoryCiJobWireDocument.From(pipeline, prepared);
        document.Validate();
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            document,
            RepositoryCiJobWireJsonContext.Default.RepositoryCiJobWireDocument);
        if (payload.Length is < 1 or > MaximumPayloadBytes)
            throw new InvalidDataException("The CI job wire payload exceeds its bound.");
        var digest = Convert.ToHexStringLower(SHA256.HashData(payload));
        var material = SignedMaterial(document, payload, Convert.FromHexString(digest));
        var signature = signer.Sign(material);
        if (signature is not { IsValid: true } || signature.Length > MaximumSignatureBytes)
            throw new InvalidDataException("The CI job signer returned an invalid signature.");
        var headers = Headers(document, digest, Convert.ToBase64String(signature.Bytes));
        EnsureHeaderBound(headers);
        return new(payload, new ReadOnlyDictionary<string, string>(headers), digest);
    }

    internal static RepositoryCiDecodedJobCommand Decode(
        ReadOnlyMemory<byte> payload,
        IEnumerable<KeyValuePair<string, string>> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);
        if (payload.Length is < 1 or > MaximumPayloadBytes) throw Invalid();
        var captured = headers.Take(ExpectedHeaderCount + 1).ToArray();
        if (captured.Length != ExpectedHeaderCount || captured.Any(static item =>
                string.IsNullOrEmpty(item.Key) || item.Value is null))
            throw Invalid();
        var values = new Dictionary<string, string>(ExpectedHeaderCount, StringComparer.Ordinal);
        foreach (var header in captured)
            if (!values.TryAdd(header.Key, header.Value)) throw Invalid();
        if (!ExpectedHeaders.SetEquals(values.Keys)) throw Invalid();
        EnsureHeaderBound(values);

        RepositoryCiJobWireDocument document;
        try
        {
            document = JsonSerializer.Deserialize(
                payload.Span,
                RepositoryCiJobWireJsonContext.Default.RepositoryCiJobWireDocument) ?? throw new JsonException();
            document.Validate();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The CI job wire payload is invalid.", exception);
        }
        var canonical = JsonSerializer.SerializeToUtf8Bytes(
            document,
            RepositoryCiJobWireJsonContext.Default.RepositoryCiJobWireDocument);
        if (!payload.Span.SequenceEqual(canonical)) throw Invalid();
        var digest = Convert.ToHexStringLower(SHA256.HashData(canonical));
        var signature = Base64(values[Signature]);
        var expected = Headers(document, digest, values[Signature]);
        if (expected.Any(item => !values.TryGetValue(item.Key, out var value) || value != item.Value))
            throw Invalid();
        var envelope = Envelope(document, canonical, Convert.FromHexString(digest), signature);
        return new(document, envelope);
    }

    private static Dictionary<string, string> Headers(
        RepositoryCiJobWireDocument document,
        string digest,
        string signature) =>
        new(ExpectedHeaderCount, StringComparer.Ordinal)
        {
            [Schema] = "1",
            [Protocol] = "1",
            [Type] = "repository-ci-job",
            [Pipeline] = document.PipelineDigest,
            [Job] = document.Job,
            [Attempt] = Number(document.Attempt),
            [Fence] = Number(document.FencingToken),
            [Runner] = document.Runner,
            [Issued] = Number(document.IssuedAtUnixMilliseconds),
            [Expires] = Number(document.ExpiresAtUnixMilliseconds),
            [PayloadSha256] = digest,
            [Signature] = signature,
        };

    private static void EnsureHeaderBound(IReadOnlyDictionary<string, string> headers)
    {
        if (headers.Sum(static item =>
                Encoding.UTF8.GetByteCount(item.Key) + Encoding.UTF8.GetByteCount(item.Value) + 4) >
            MaximumHeaderBytes)
            throw Invalid();
    }

    private static string Number(long value) => value.ToString(CultureInfo.InvariantCulture);

    private static byte[] Base64(string value)
    {
        try
        {
            var bytes = Convert.FromBase64String(value);
            if (bytes.Length is < 1 or > MaximumSignatureBytes || Convert.ToBase64String(bytes) != value)
                throw Invalid();
            return bytes;
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("The CI job wire signature is invalid.", exception);
        }
    }

    private static CommandSignedMaterial SignedMaterial(
        RepositoryCiJobWireDocument document,
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> digest)
    {
        var identities = Identities(document);
        PayloadDigest.TryCopyFrom(digest, out var payloadDigest);
        return new(
            identities.Protocol,
            identities.Cell,
            identities.Aggregate,
            identities.Generation,
            identities.Epoch,
            identities.Operation,
            identities.Idempotency,
            DateTimeOffset.FromUnixTimeMilliseconds(document.IssuedAtUnixMilliseconds),
            DateTimeOffset.FromUnixTimeMilliseconds(document.ExpiresAtUnixMilliseconds),
            identities.Attempt,
            OpaquePayload.CopyFrom(payload),
            payloadDigest!);
    }

    private static CommandEnvelope Envelope(
        RepositoryCiJobWireDocument document,
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> digest,
        ReadOnlySpan<byte> signature)
    {
        var identities = Identities(document);
        PayloadDigest.TryCopyFrom(digest, out var payloadDigest);
        OpaqueSignature.TryCopyFrom(signature, out var opaqueSignature);
        return new(
            identities.Protocol,
            identities.Cell,
            identities.Aggregate,
            identities.Generation,
            identities.Epoch,
            identities.Operation,
            identities.Idempotency,
            DateTimeOffset.FromUnixTimeMilliseconds(document.IssuedAtUnixMilliseconds),
            DateTimeOffset.FromUnixTimeMilliseconds(document.ExpiresAtUnixMilliseconds),
            identities.Attempt,
            OpaquePayload.CopyFrom(payload),
            payloadDigest!,
            opaqueSignature!);
    }

    private static CommandIdentities Identities(RepositoryCiJobWireDocument document)
    {
        if (!ProtocolRevision.TryCreate(1, out var protocol) || !CellId.TryCreate("global", out var cell) ||
            !AggregateId.TryCreate(document.Job, out var aggregate) ||
            !DesiredGeneration.TryCreate(document.Generation, out var generation) ||
            !WriterEpoch.TryCreate(document.AuthorityEpoch, out var epoch) ||
            !OperationId.TryCreate(document.Operation, out var operation) ||
            !IdempotencyKey.TryCreate(document.Idempotency, out var idempotency) ||
            !DeliveryAttempt.TryCreate(document.Attempt, out var attempt))
            throw Invalid();
        return new(protocol!, cell!, aggregate!, generation!, epoch!, operation!, idempotency!, attempt!);
    }

    private static InvalidDataException Invalid() => new("The CI job wire message is invalid.");

    private static readonly HashSet<string> ExpectedHeaders =
    [
        Schema, Protocol, Type, Pipeline, Job, Attempt, Fence, Runner, Issued, Expires, PayloadSha256, Signature,
    ];

    private sealed record CommandIdentities(
        ProtocolRevision Protocol,
        CellId Cell,
        AggregateId Aggregate,
        DesiredGeneration Generation,
        WriterEpoch Epoch,
        OperationId Operation,
        IdempotencyKey Idempotency,
        DeliveryAttempt Attempt);
}

internal sealed record RepositoryCiJobWireDocument(
    int SchemaVersion,
    string Pipeline,
    string PipelineDigest,
    string ImpactDigest,
    RepositoryCiProfile Profile,
    string Job,
    string JobDigest,
    string PlanId,
    string Repository,
    string NodeId,
    RepositoryCiNodeKind NodeKind,
    RepositoryCiResourceWeight ResourceWeight,
    string SourceCommit,
    string SourceTree,
    bool SourceSignatureVerified,
    JobKind Kind,
    string Tree,
    long Generation,
    int Attempt,
    int MaximumAttempts,
    string BaseIdempotency,
    string Idempotency,
    bool RetryAuthorized,
    TrustZone[] AllowedZones,
    RunnerCapability[] RequiredCapabilities,
    long MinimumRunnerSequence,
    long MaximumRunnerSequence,
    string Runner,
    long RunnerSequence,
    string Controller,
    long AuthorityEpoch,
    long FencingToken,
    string Operation,
    string IsolationDigest,
    long IssuedAtUnixMilliseconds,
    long ExpiresAtUnixMilliseconds,
    string AttemptChainDigest,
    string RetryAuthorizationDigest,
    string[] Dependencies,
    bool MayPublishCandidateArtifact)
{
    private const long MaximumUnixMilliseconds = 253_402_300_799_999;

    internal static RepositoryCiJobWireDocument From(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiJobSnapshot prepared)
    {
        var planned = pipeline.Jobs.SingleOrDefault(job => job.Request.Job == prepared.Job.Request.Job)
            ?? throw new InvalidDataException("The prepared CI job is not part of the pipeline.");
        if (pipeline.Digest != prepared.Document.PipelineDigest ||
            RepositoryCiJobJournal.JobDigest(pipeline, planned) != prepared.Document.JobDigest)
            throw new InvalidDataException("The prepared CI job does not match the immutable pipeline.");
        var job = prepared.Job;
        var request = job.Request;
        return new(
            1,
            request.Pipeline.Value,
            prepared.Document.PipelineDigest,
            pipeline.ImpactDigest,
            pipeline.Profile,
            request.Job.Value,
            prepared.Document.JobDigest,
            job.Plan.Id,
            job.Plan.Repository,
            job.Plan.Node.Id,
            job.Plan.Node.Kind,
            job.Plan.Node.ResourceWeight,
            job.Source.Commit,
            job.Source.Tree,
            job.Source.SignatureVerified,
            request.Kind,
            request.Tree.Value,
            request.Generation,
            request.Attempt,
            request.MaximumAttempts,
            planned.Request.Idempotency.Value,
            request.Idempotency.Value,
            request.RetryAuthorized,
            request.AllowedZones.ToArray(),
            request.RequiredCapabilities.ToArray(),
            request.MinimumRunnerSequence,
            request.MaximumRunnerSequence,
            prepared.RunnerId,
            prepared.RunnerSequence,
            prepared.ControllerId,
            prepared.AuthorityEpoch,
            prepared.FencingToken,
            prepared.OperationId,
            prepared.Document.IsolationDigest,
            prepared.Document.PreparedAtUnixMilliseconds,
            prepared.Document.ExpiresAtUnixMilliseconds,
            prepared.Document.AttemptChainDigest,
            prepared.Document.RetryAuthorizationDigest,
            job.DependsOn.Select(static dependency => dependency.Value).ToArray(),
            job.MayPublishCandidateArtifact);
    }

    internal void Validate()
    {
        if (SchemaVersion != 1 || !Identity(Pipeline) || !Digest(PipelineDigest) || !Digest(ImpactDigest) ||
            Pipeline != $"ci-{PipelineDigest[..24]}" || !Identity(Job) || !Digest(JobDigest) ||
            !EnumValue(Profile) || !Identity(PlanId) || !ForgejoWebhookVerifier.IsRepository(Repository) ||
            !Node(NodeId) || PlanId != $"{Repository}:{NodeId}" ||
            !EnumValue(NodeKind) || !EnumValue(ResourceWeight) || !ObjectId(SourceCommit) ||
            !ObjectId(SourceTree) || !EnumValue(Kind) || !ObjectId(Tree) || Tree != SourceTree ||
            Generation <= 0 || Attempt is < 1 or > 3 || MaximumAttempts != 3 ||
            !Identity(BaseIdempotency) || !Identity(Idempotency) ||
            Idempotency != EffectiveIdempotency(BaseIdempotency, Attempt) ||
            RetryAuthorized != (Attempt > 1) || AllowedZones is not { Length: 1 } ||
            AllowedZones.Any(static value => !EnumValue(value)) ||
            RequiredCapabilities is not { Length: > 0 and <= 3 } ||
            RequiredCapabilities.Any(static value => !EnumValue(value)) ||
            RequiredCapabilities.Distinct().Count() != RequiredCapabilities.Length ||
            MinimumRunnerSequence <= 0 || MaximumRunnerSequence < MinimumRunnerSequence ||
            !Identity(Runner) || RunnerSequence < MinimumRunnerSequence || RunnerSequence > MaximumRunnerSequence ||
            !Identity(Controller) || AuthorityEpoch <= 0 || FencingToken <= 0 || !Identity(Operation) ||
            !Digest(IsolationDigest) || IssuedAtUnixMilliseconds <= 0 ||
            IssuedAtUnixMilliseconds > MaximumUnixMilliseconds - 7_200_000 ||
            ExpiresAtUnixMilliseconds != IssuedAtUnixMilliseconds + 7_200_000 ||
            Dependencies is null || Dependencies.Length > 256 || Dependencies.Any(static value => !Identity(value)) ||
            Dependencies.Distinct(StringComparer.Ordinal).Count() != Dependencies.Length ||
            AttemptChainDigest is null || RetryAuthorizationDigest is null ||
            Attempt == 1 && (AttemptChainDigest.Length != 0 || RetryAuthorizationDigest.Length != 0) ||
            Attempt > 1 && (!Digest(AttemptChainDigest) || !Digest(RetryAuthorizationDigest)) ||
            Kind == JobKind.ProductValidation &&
                (Profile != RepositoryCiProfile.Feature || AllowedZones[0] != TrustZone.UntrustedProduct ||
                    RequiredCapabilities.Any(static capability => capability is not (
                        RunnerCapability.Compile or RunnerCapability.Test)) || MayPublishCandidateArtifact) ||
            Kind == JobKind.TrustedBuild &&
                (Profile != RepositoryCiProfile.Release || AllowedZones[0] != TrustZone.TrustedBuild ||
                    !SourceSignatureVerified || RequiredCapabilities.Any(static capability => capability is not (
                        RunnerCapability.Compile or RunnerCapability.Test or RunnerCapability.Sign))) ||
            Kind is not (JobKind.ProductValidation or JobKind.TrustedBuild) ||
            MayPublishCandidateArtifact && NodeKind != RepositoryCiNodeKind.Artifact ||
            JobDigest != ExpectedJobDigest())
            throw new InvalidDataException("The CI job wire document is invalid.");
    }

    private string ExpectedJobDigest()
    {
        var value = new StringBuilder(PipelineDigest).Append('\n')
            .Append(ImpactDigest).Append('\n')
            .Append(PlanId).Append(':').Append(Repository).Append(':')
            .Append(NodeId).Append(':').Append(NodeKind).Append(':').Append(ResourceWeight).Append('\n')
            .Append(Repository).Append(':').Append(SourceCommit).Append(':')
            .Append(SourceTree).Append(':').Append(SourceSignatureVerified ? '1' : '0').Append('\n')
            .Append(Pipeline).Append(':').Append(Job).Append(':').Append(Kind).Append(':')
            .Append(Tree).Append(':').Append(Generation).Append(":1:")
            .Append(MaximumAttempts).Append(':').Append(BaseIdempotency).Append(':')
            .Append(MinimumRunnerSequence).Append(':').Append(MaximumRunnerSequence).Append(":0\n")
            .AppendJoin(',', AllowedZones).Append('\n')
            .AppendJoin(',', RequiredCapabilities).Append('\n')
            .AppendJoin(',', Dependencies).Append('\n')
            .Append(MayPublishCandidateArtifact ? '1' : '0');
        return Hash(value.ToString());
    }

    private static string EffectiveIdempotency(string value, int attempt) => attempt == 1
        ? value
        : $"ci-{Hash($"{value}\n{attempt}")}";

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static bool Identity(string? value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static bool ObjectId(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static bool Node(string? value) => value is { Length: >= 1 and <= 64 } &&
        value[0] is >= 'a' and <= 'z' && value.All(static character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    private static bool EnumValue<T>(T value) where T : struct, Enum =>
        Enum.IsDefined(value) && Convert.ToInt64(value, CultureInfo.InvariantCulture) != 0;
}

[JsonSerializable(typeof(RepositoryCiJobWireDocument))]
internal sealed partial class RepositoryCiJobWireJsonContext : JsonSerializerContext;
