using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.Contracts.Resources;

internal static partial class CanonicalText
{
    public static string Token(string value, string parameterName, int maximumLength = 63)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (value.Length is < 1 || value.Length > maximumLength || !TokenPattern().IsMatch(value))
        {
            throw new ArgumentException(
                $"Value must be a 1-{maximumLength} character canonical lowercase token.", parameterName);
        }

        return value;
    }

    [GeneratedRegex(ResourceId.JsonSchemaPattern, RegexOptions.CultureInvariant)]
    private static partial Regex TokenPattern();
}

public sealed record ApiVersion
{
    private const string VersionOne = "terrascale.io/orchestrator/v1";

    private ApiVersion(string value) => Value = value;

    public string Value { get; }

    public static ApiVersion V1 { get; } = new(VersionOne);

    public static ApiVersion Parse(string value) =>
        string.Equals(value, VersionOne, StringComparison.Ordinal)
            ? V1
            : throw new ArgumentException("Unknown or noncanonical API version.", nameof(value));

    public override string ToString() => Value;
}

public sealed record ResourceId
{
    public const int MaximumLength = 63;
    public const string JsonSchemaPattern = "^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$";

    public ResourceId(string value) => Value = CanonicalText.Token(value, nameof(value), MaximumLength);

    public string Value { get; }

    public override string ToString() => Value;
}

public sealed record Generation
{
    public Generation(ulong value)
    {
        if (value == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Generation zero is invalid.");
        }

        Value = value;
    }

    public ulong Value { get; }

    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}

public sealed record ResourceVersion
{
    public ResourceVersion(ulong value)
    {
        if (value == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Resource version zero is invalid.");
        }

        Value = value;
    }

    public ulong Value { get; }

    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}

public enum AuthorityKind
{
    GlobalController = 1,
    RegionalController = 2,
    DomainController = 3,
}

public sealed record ResourceOwnership
{
    public ResourceOwnership(AuthorityKind kind, ResourceId authorityId)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Kind = kind;
        AuthorityId = authorityId ?? throw new ArgumentNullException(nameof(authorityId));
    }

    public AuthorityKind Kind { get; }

    public ResourceId AuthorityId { get; }
}

public enum CreationActorKind
{
    Bootstrap = 1,
    Controller = 2,
    GitOps = 3,
    Operator = 4,
}

public sealed record CreationActor
{
    public CreationActor(CreationActorKind kind, ResourceId actorId)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Kind = kind;
        ActorId = actorId ?? throw new ArgumentNullException(nameof(actorId));
    }

    public CreationActorKind Kind { get; }

    public ResourceId ActorId { get; }
}

public sealed record AuditCorrelationId
{
    public AuditCorrelationId(string value) => Value = CanonicalText.Token(value, nameof(value));

    public string Value { get; }

    public override string ToString() => Value;
}

public sealed record ResourceMetadata
{
    public ResourceMetadata(
        ApiVersion apiVersion,
        ResourceId id,
        Generation generation,
        ResourceVersion resourceVersion,
        ResourceOwnership ownership,
        CreationActor creationActor,
        AuditCorrelationId auditCorrelationId)
    {
        ApiVersion = apiVersion ?? throw new ArgumentNullException(nameof(apiVersion));
        Id = id ?? throw new ArgumentNullException(nameof(id));
        Generation = generation ?? throw new ArgumentNullException(nameof(generation));
        ResourceVersion = resourceVersion ?? throw new ArgumentNullException(nameof(resourceVersion));
        Ownership = ownership ?? throw new ArgumentNullException(nameof(ownership));
        CreationActor = creationActor ?? throw new ArgumentNullException(nameof(creationActor));
        AuditCorrelationId = auditCorrelationId ?? throw new ArgumentNullException(nameof(auditCorrelationId));
    }

    public ApiVersion ApiVersion { get; }

    public ResourceId Id { get; }

    public Generation Generation { get; }

    public ResourceVersion ResourceVersion { get; }

    public ResourceOwnership Ownership { get; }

    public CreationActor CreationActor { get; }

    public AuditCorrelationId AuditCorrelationId { get; }

    public string ToCanonicalString() => string.Join('|',
        $"apiVersion={ApiVersion}",
        $"id={Id}",
        $"generation={Generation}",
        $"resourceVersion={ResourceVersion}",
        $"owner={Ownership.Kind}:{Ownership.AuthorityId}",
        $"createdBy={CreationActor.Kind}:{CreationActor.ActorId}",
        $"audit={AuditCorrelationId}");

    public byte[] GetCanonicalDigestInput() => Encoding.UTF8.GetBytes(ToCanonicalString());
}

