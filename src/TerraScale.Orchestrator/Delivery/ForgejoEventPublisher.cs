using System.Text.Json;
using System.Text.Json.Serialization;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Net;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

internal interface IForgejoEventPublisher
{
    Task PublishAsync(ForgejoWebhookEnvelope envelope, CancellationToken cancellationToken);
}

internal sealed class NatsForgejoEventPublisher(NatsClient client) : IForgejoEventPublisher
{
    public async Task PublishAsync(
        ForgejoWebhookEnvelope envelope,
        CancellationToken cancellationToken)
    {
        var document = ForgejoWebhookEventDocument.From(envelope);
        document.Validate();
        var payload = JsonSerializer.Serialize(
            document,
            ForgejoWebhookEventJsonContext.Default.ForgejoWebhookEventDocument);
        var headers = new NatsHeaders
        {
            ["TS-Protocol-Version"] = "1",
            ["TS-Event-Id"] = envelope.DedupeKey,
            ["TS-Event-Kind"] = envelope.Kind.ToString(),
        };
        var acknowledgement = await client.CreateJetStreamContext().PublishAsync(
            GlobalNatsTopology.CiSubject,
            payload,
            opts: new NatsJSPubOpts
            {
                MsgId = envelope.DedupeKey,
                ExpectedStream = GlobalNatsTopology.CiStream,
                RetryAttempts = 3,
                RetryWaitBetweenAttempts = TimeSpan.FromMilliseconds(250),
            },
            headers: headers,
            cancellationToken: cancellationToken);
        acknowledgement.EnsureSuccess();
    }
}

internal sealed record ForgejoWebhookEventDocument(
    int SchemaVersion,
    Guid DeliveryId,
    ForgejoWebhookKind Kind,
    string Action,
    string Repository,
    string SourceRepository,
    string Revision,
    string SourceRef,
    string? TargetRef,
    long? PullRequestNumber,
    bool IsDeletion,
    string PayloadSha256,
    string DedupeKey)
{
    internal static ForgejoWebhookEventDocument From(ForgejoWebhookEnvelope envelope) => new(
        1,
        envelope.DeliveryId,
        envelope.Kind,
        envelope.Action,
        envelope.Repository,
        envelope.SourceRepository,
        envelope.Revision,
        envelope.SourceRef,
        envelope.TargetRef,
        envelope.PullRequestNumber,
        envelope.IsDeletion,
        envelope.PayloadSha256,
        envelope.DedupeKey);

    internal static ForgejoWebhookEventDocument Deserialize(string payload)
    {
        try
        {
            var document = JsonSerializer.Deserialize(
                payload,
                ForgejoWebhookEventJsonContext.Default.ForgejoWebhookEventDocument)
                ?? throw new JsonException();
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A normalized Forgejo inbox event is invalid.", exception);
        }
    }

    internal ForgejoWebhookEnvelope ToEnvelope()
    {
        Validate();
        return new(
            DeliveryId,
            Kind,
            Action,
            Repository,
            SourceRepository,
            Revision,
            SourceRef,
            TargetRef,
            PullRequestNumber,
            IsDeletion,
            PayloadSha256);
    }

    internal void Validate()
    {
        if (SchemaVersion != 1 || DeliveryId == Guid.Empty ||
            Kind is not (ForgejoWebhookKind.Push or ForgejoWebhookKind.PullRequest) ||
            string.IsNullOrWhiteSpace(Action) || !ForgejoWebhookVerifier.IsRepository(Repository) ||
            !ForgejoWebhookVerifier.IsRepository(SourceRepository) || !ObjectId(Revision) ||
            IsDeletion != Revision.All(static character => character == '0') ||
            string.IsNullOrWhiteSpace(SourceRef) || !Digest(PayloadSha256) ||
            DedupeKey != $"forgejo-payload:{Repository}:{PayloadSha256}" ||
            Kind == ForgejoWebhookKind.Push &&
            (TargetRef is not null || PullRequestNumber is not null || SourceRepository != Repository) ||
            Kind == ForgejoWebhookKind.PullRequest &&
            (string.IsNullOrWhiteSpace(TargetRef) || PullRequestNumber is null or <= 0 || IsDeletion))
            throw new InvalidDataException("A normalized Forgejo inbox event is invalid.");
    }

    private static bool ObjectId(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

[JsonSerializable(typeof(ForgejoWebhookEventDocument))]
internal sealed partial class ForgejoWebhookEventJsonContext : JsonSerializerContext;
