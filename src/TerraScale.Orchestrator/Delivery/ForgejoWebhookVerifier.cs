using System.Security.Cryptography;
using System.Text.Json;

namespace TerraScale.Orchestrator.Delivery;

public enum ForgejoWebhookKind
{
    Unspecified,
    Push,
    PullRequest,
}

public enum ForgejoWebhookError
{
    None,
    EmptyPayload,
    PayloadTooLarge,
    UnsupportedContentType,
    InvalidSecret,
    InvalidExpectedRepository,
    InvalidSignature,
    InvalidDeliveryId,
    UnsupportedEvent,
    MalformedPayload,
    RepositoryMismatch,
    InvalidBaseRevision,
    InvalidRevision,
    InvalidReference,
    UnsupportedAction,
}

public sealed class ForgejoWebhookEnvelope
{
    internal ForgejoWebhookEnvelope(
        Guid deliveryId,
        ForgejoWebhookKind kind,
        string action,
        string repository,
        string sourceRepository,
        string baseRevision,
        string revision,
        string sourceRef,
        string? targetRef,
        long? pullRequestNumber,
        bool isDeletion,
        string payloadSha256)
    {
        DeliveryId = deliveryId;
        Kind = kind;
        Action = action;
        Repository = repository;
        SourceRepository = sourceRepository;
        BaseRevision = baseRevision;
        Revision = revision;
        SourceRef = sourceRef;
        TargetRef = targetRef;
        PullRequestNumber = pullRequestNumber;
        IsDeletion = isDeletion;
        PayloadSha256 = payloadSha256;
    }

    public Guid DeliveryId { get; }
    public ForgejoWebhookKind Kind { get; }
    public string Action { get; }
    public string Repository { get; }
    public string SourceRepository { get; }
    public string BaseRevision { get; }
    public string Revision { get; }
    public string SourceRef { get; }
    public string? TargetRef { get; }
    public long? PullRequestNumber { get; }
    public bool IsDeletion { get; }
    public bool IsFork => !StringComparer.Ordinal.Equals(Repository, SourceRepository);
    public string PayloadSha256 { get; }
    public string DeliveryKey => $"forgejo-delivery:{Repository}:{DeliveryId:D}";
    public string DedupeKey => $"forgejo-payload:{Repository}:{PayloadSha256}";
}

public sealed class ForgejoWebhookVerification
{
    private ForgejoWebhookVerification(ForgejoWebhookEnvelope? envelope, ForgejoWebhookError error)
    {
        Envelope = envelope;
        Error = error;
    }

    public bool Accepted => Envelope is not null;
    public ForgejoWebhookEnvelope? Envelope { get; }
    public ForgejoWebhookError Error { get; }

    internal static ForgejoWebhookVerification Accept(ForgejoWebhookEnvelope envelope) => new(envelope, ForgejoWebhookError.None);
    internal static ForgejoWebhookVerification Reject(ForgejoWebhookError error) => new(null, error);
}

/// <summary>Verifies and bounds Forgejo webhook input before it can become replayable INV-005 delivery work.</summary>
public static class ForgejoWebhookVerifier
{
    public const int MaximumPayloadBytes = 1_048_576;
    public const int MinimumSecretBytes = 32;
    private const int MaximumJsonDepth = 16;

    public static ForgejoWebhookVerification Verify(
        byte[]? payload,
        byte[]? secret,
        string? expectedRepository,
        string? contentType,
        string? signature,
        string? deliveryId,
        string? eventName)
    {
        if (payload is not { Length: > 0 }) return Reject(ForgejoWebhookError.EmptyPayload);
        if (payload.Length > MaximumPayloadBytes) return Reject(ForgejoWebhookError.PayloadTooLarge);
        if (!IsJson(contentType)) return Reject(ForgejoWebhookError.UnsupportedContentType);
        if (secret is not { Length: >= MinimumSecretBytes }) return Reject(ForgejoWebhookError.InvalidSecret);
        if (expectedRepository is not { } validatedRepository || !IsRepository(validatedRepository))
            return Reject(ForgejoWebhookError.InvalidExpectedRepository);
        if (!VerifySignature(payload, secret, signature)) return Reject(ForgejoWebhookError.InvalidSignature);
        if (!Guid.TryParseExact(deliveryId, "D", out var parsedDeliveryId) || parsedDeliveryId == Guid.Empty)
            return Reject(ForgejoWebhookError.InvalidDeliveryId);

        var kind = eventName switch
        {
            "push" => ForgejoWebhookKind.Push,
            "pull_request" => ForgejoWebhookKind.PullRequest,
            _ => ForgejoWebhookKind.Unspecified,
        };
        if (kind == ForgejoWebhookKind.Unspecified) return Reject(ForgejoWebhookError.UnsupportedEvent);

        try
        {
            if (HasDuplicateProperties(payload)) return Reject(ForgejoWebhookError.MalformedPayload);
            using var document = JsonDocument.Parse(payload, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = MaximumJsonDepth,
            });
            var payloadDigest = Convert.ToHexStringLower(SHA256.HashData(payload));
            return kind == ForgejoWebhookKind.Push
                ? ParsePush(document.RootElement, parsedDeliveryId, validatedRepository, payloadDigest)
                : ParsePullRequest(document.RootElement, parsedDeliveryId, validatedRepository, payloadDigest);
        }
        catch (JsonException)
        {
            return Reject(ForgejoWebhookError.MalformedPayload);
        }
        catch (InvalidOperationException)
        {
            return Reject(ForgejoWebhookError.MalformedPayload);
        }
    }

    private static ForgejoWebhookVerification ParsePush(
        JsonElement root,
        Guid deliveryId,
        string expectedRepository,
        string payloadDigest)
    {
        if (!TryRepository(root, "repository", out var repository)) return Reject(ForgejoWebhookError.MalformedPayload);
        if (!StringComparer.Ordinal.Equals(repository, expectedRepository)) return Reject(ForgejoWebhookError.RepositoryMismatch);
        if (!TryString(root, "before", out var baseRevision) || !IsRevision(baseRevision))
            return Reject(ForgejoWebhookError.InvalidBaseRevision);
        if (!TryString(root, "after", out var revision) || !IsRevision(revision))
            return Reject(ForgejoWebhookError.InvalidRevision);
        if (!TryString(root, "ref", out var sourceRef) || !IsFullRef(sourceRef))
            return Reject(ForgejoWebhookError.InvalidReference);

        baseRevision = baseRevision.ToLowerInvariant();
        revision = revision.ToLowerInvariant();
        if (revision.All(static value => value == '0') && baseRevision.All(static value => value == '0'))
            return Reject(ForgejoWebhookError.InvalidBaseRevision);
        return ForgejoWebhookVerification.Accept(new(
            deliveryId,
            ForgejoWebhookKind.Push,
            "push",
            repository,
            repository,
            baseRevision,
            revision,
            sourceRef,
            null,
            null,
            revision.All(static value => value == '0'),
            payloadDigest));
    }

    private static ForgejoWebhookVerification ParsePullRequest(
        JsonElement root,
        Guid deliveryId,
        string expectedRepository,
        string payloadDigest)
    {
        if (!TryRepository(root, "repository", out var repository) ||
            !TryObject(root, "pull_request", out var pullRequest) ||
            !TryObject(pullRequest, "head", out var head) ||
            !TryObject(pullRequest, "base", out var @base) ||
            !TryRepository(head, "repo", out var sourceRepository) ||
            !TryRepository(@base, "repo", out var targetRepository) ||
            !TryString(root, "action", out var action) ||
            !TryPositiveInt64(root, "number", out var number))
            return Reject(ForgejoWebhookError.MalformedPayload);

        if (!StringComparer.Ordinal.Equals(repository, expectedRepository) ||
            !StringComparer.Ordinal.Equals(targetRepository, expectedRepository))
            return Reject(ForgejoWebhookError.RepositoryMismatch);
        if (!IsPullRequestAction(action)) return Reject(ForgejoWebhookError.UnsupportedAction);
        if (!TryString(@base, "sha", out var baseRevision) || !IsRevision(baseRevision) ||
            baseRevision.All(static value => value == '0'))
            return Reject(ForgejoWebhookError.InvalidBaseRevision);
        if (!TryString(head, "sha", out var revision) || !IsRevision(revision) || revision.All(static value => value == '0'))
            return Reject(ForgejoWebhookError.InvalidRevision);
        if (!TryString(head, "ref", out var sourceRef) || !IsBranchRef(sourceRef) ||
            !TryString(@base, "ref", out var targetRef) || !IsBranchRef(targetRef))
            return Reject(ForgejoWebhookError.InvalidReference);

        return ForgejoWebhookVerification.Accept(new(
            deliveryId,
            ForgejoWebhookKind.PullRequest,
            action,
            repository,
            sourceRepository,
            baseRevision.ToLowerInvariant(),
            revision.ToLowerInvariant(),
            sourceRef,
            targetRef,
            number,
            false,
            payloadDigest));
    }

    private static bool VerifySignature(byte[] payload, byte[] secret, string? signature)
    {
        if (signature is not { Length: 64 }) return false;
        byte[] supplied;
        try
        {
            supplied = Convert.FromHexString(signature);
        }
        catch (FormatException)
        {
            return false;
        }

        if (supplied.Length != 32) return false;
        Span<byte> expected = stackalloc byte[32];
        HMACSHA256.HashData(secret, payload, expected);
        return CryptographicOperations.FixedTimeEquals(supplied, expected);
    }

    private static bool HasDuplicateProperties(byte[] payload)
    {
        var reader = new Utf8JsonReader(payload, new JsonReaderOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = MaximumJsonDepth,
        });
        var objectFields = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject)
            {
                objectFields.Push(new(StringComparer.Ordinal));
            }
            else if (reader.TokenType == JsonTokenType.EndObject)
            {
                objectFields.Pop();
            }
            else if (reader.TokenType == JsonTokenType.PropertyName)
            {
                if (!objectFields.TryPeek(out var current) || reader.GetString() is not { } propertyName ||
                    !current.Add(propertyName))
                    return true;
            }
        }
        return objectFields.Count != 0;
    }

    private static bool IsJson(string? contentType)
    {
        if (contentType is null) return false;
        var separator = contentType.IndexOf(';', StringComparison.Ordinal);
        var mediaType = separator < 0 ? contentType : contentType[..separator];
        return mediaType.Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryObject(JsonElement owner, string name, out JsonElement value)
    {
        value = default;
        return owner.ValueKind == JsonValueKind.Object && owner.TryGetProperty(name, out value) &&
               value.ValueKind == JsonValueKind.Object;
    }

    private static bool TryString(JsonElement owner, string name, out string value)
    {
        value = string.Empty;
        if (owner.ValueKind != JsonValueKind.Object || !owner.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.String || property.GetString() is not { } text) return false;
        value = text;
        return true;
    }

    private static bool TryRepository(JsonElement owner, string name, out string repository)
    {
        repository = string.Empty;
        return TryObject(owner, name, out var value) && TryString(value, "full_name", out repository) &&
               IsRepository(repository);
    }

    private static bool TryPositiveInt64(JsonElement owner, string name, out long value)
    {
        value = 0;
        return owner.ValueKind == JsonValueKind.Object && owner.TryGetProperty(name, out var property) &&
               property.TryGetInt64(out value) && value > 0;
    }

    internal static bool IsRepository(string? value)
    {
        if (value is not { Length: >= 3 and <= 256 }) return false;
        var slash = value.IndexOf('/');
        return slash is > 0 && slash == value.LastIndexOf('/') && slash < value.Length - 1 &&
               value.All(static character => character == '/' || IsRepositoryCharacter(character));
    }

    private static bool IsFullRef(string value) =>
        (value.StartsWith("refs/heads/", StringComparison.Ordinal) ||
         value.StartsWith("refs/tags/", StringComparison.Ordinal)) && IsRef(value);

    private static bool IsBranchRef(string value) => !value.StartsWith("refs/", StringComparison.Ordinal) && IsRef(value);

    private static bool IsRef(string value)
    {
        if (value is not { Length: > 0 and <= 512 } || value is "@" || value[0] is '.' or '/' ||
            value[^1] is '.' or '/' || value.Contains("..", StringComparison.Ordinal) ||
            value.Contains("//", StringComparison.Ordinal) || value.Contains("@{", StringComparison.Ordinal))
            return false;
        foreach (var character in value)
        {
            if (character <= ' ' || character is '\u007f' or '~' or '^' or ':' or '?' or '*' or '[' or '\\') return false;
        }
        return value.Split('/').All(static part => part.Length > 0 && part[0] != '.' &&
            !part.EndsWith(".lock", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsRevision(string value) =>
        value.Length is 40 or 64 && value.All(static character => IsHex(character));

    private static bool IsPullRequestAction(string value) => value is
        "opened" or "closed" or "reopened" or "edited" or "assigned" or "unassigned" or
        "label_updated" or "label_cleared" or "synchronized" or "milestoned" or "demilestoned" or
        "reviewed" or "review_requested" or "review_request_removed";

    private static bool IsRepositoryCharacter(char value) => value is
        >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-';

    private static bool IsHex(char value) => value is
        >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';

    private static ForgejoWebhookVerification Reject(ForgejoWebhookError error) => ForgejoWebhookVerification.Reject(error);
}
