using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal enum RegionalHostSessionOperation { Acquire = 1, Renew = 2 }

/// <summary>
/// Proof of possession for an exact enrollment and process session. This does not authorize
/// enrollment: a controller must separately verify issuer trust, policy and durable session state.
/// </summary>
internal sealed record RegionalHostSessionRequest
{
    internal const int CurrentSchemaVersion = 1;
    internal const int MaximumBytes = 16_384;
    internal static readonly TimeSpan MaximumAge = TimeSpan.FromSeconds(10);
    private const string SignatureDomain = "terrascale-regional-host-session-request-v1";

    public RegionalHostSessionRequest(int schemaVersion, RegionalNodeEnrollmentEnvelope enrollment,
        RegionalHostSessionOperation operation, string sessionId, ulong epoch, string requestId,
        DateTimeOffset issuedAt, string signature)
    {
        if (schemaVersion != CurrentSchemaVersion)
            throw new ArgumentException("Unsupported host session request schema.", nameof(schemaVersion));
        ArgumentNullException.ThrowIfNull(enrollment);
        if (operation is not (RegionalHostSessionOperation.Acquire or RegionalHostSessionOperation.Renew) ||
            (operation == RegionalHostSessionOperation.Acquire ? epoch != 0 : epoch == 0))
            throw new ArgumentException("A host session request requires a closed operation and its exact epoch.", nameof(operation));
        if (issuedAt == default || issuedAt.Offset != TimeSpan.Zero || issuedAt > DateTimeOffset.MaxValue - MaximumAge)
            throw new ArgumentException("Host session requests require a bounded explicit UTC instant.", nameof(issuedAt));
        if (signature is not { Length: 88 })
            throw new ArgumentException("A host session proof must encode an Ed25519 signature.", nameof(signature));
        SchemaVersion = schemaVersion;
        Enrollment = enrollment;
        Operation = operation;
        SessionId = BootstrapGrantCanonical.ValidateLowercaseHex(sessionId, 32, nameof(sessionId));
        Epoch = epoch;
        RequestId = BootstrapGrantCanonical.ValidateLowercaseHex(requestId, 32, nameof(requestId));
        IssuedAt = issuedAt;
        Signature = signature;
    }

    public int SchemaVersion { get; }
    public RegionalNodeEnrollmentEnvelope Enrollment { get; }
    public RegionalHostSessionOperation Operation { get; }
    public string SessionId { get; }
    public ulong Epoch { get; }
    public string RequestId { get; }
    public DateTimeOffset IssuedAt { get; }
    public string Signature { get; }

    internal string EnrollmentDigest => Enrollment.Digest;

    internal byte[] CanonicalBytes() => Encoding.UTF8.GetBytes(BootstrapGrantCanonical.EncodeFields([
        SignatureDomain, EnrollmentDigest, Enrollment.Region, Enrollment.NodeId,
        Operation.ToString(), SessionId, Epoch.ToString(CultureInfo.InvariantCulture),
        RequestId, IssuedAt.UtcTicks.ToString(CultureInfo.InvariantCulture)]));

    internal string RequestDigest => Convert.ToHexStringLower(SHA256.HashData(CanonicalBytes()));

    internal bool HasValidProof(string cell, DateTimeOffset now) =>
        cell is "gru" or "sfo" or "fra" && Enrollment.Region == cell.ToUpperInvariant() &&
        now != default && IssuedAt <= now && now - IssuedAt < MaximumAge &&
        NatsUserSignature.Verify(Enrollment.NatsUserPublicKey, CanonicalBytes(), Signature);

    internal static RegionalHostSessionRequest Sign(RegionalNodeEnrollmentEnvelope enrollment,
        NatsAuthenticationFiles authentication, RegionalHostSessionOperation operation, string sessionId,
        ulong epoch, DateTimeOffset issuedAt)
    {
        if (authentication.PublicKey != enrollment.NatsUserPublicKey)
            throw new InvalidOperationException("The host session signer differs from the enrolled user key.");
        var unsigned = new RegionalHostSessionRequest(CurrentSchemaVersion, enrollment, operation, sessionId,
            epoch, Guid.NewGuid().ToString("N"), issuedAt, Convert.ToBase64String(new byte[64]));
        return new(CurrentSchemaVersion, enrollment, operation, sessionId, epoch, unsigned.RequestId, issuedAt,
            Convert.ToBase64String(authentication.SignUserRequest(unsigned.CanonicalBytes())));
    }

    internal static string Subject(string cell, string nodeId) =>
        NatsSubjectTaxonomy.HostAgentObservationSubject(cell, nodeId, "enrollment");

    internal static string ReplySubject(string cell, string nodeId, string requestId) =>
        NatsSubjectTaxonomy.HostAgentCommandSubject(cell, nodeId, "enrollment-" + requestId);

    internal string Serialize()
    {
        var json = JsonSerializer.Serialize(this, JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > MaximumBytes)
            throw new InvalidOperationException("The host session request exceeds its wire bounds.");
        return json;
    }

    /// <summary>Checks exact routing, freshness and user proof before any durable authority decision.</summary>
    internal static bool TryRead(string? json, string subject, string? reply, string cell,
        DateTimeOffset now, out RegionalHostSessionRequest? request)
    {
        request = null;
        try
        {
            if (json is not { Length: > 0 and <= MaximumBytes } || Encoding.UTF8.GetByteCount(json) > MaximumBytes ||
                cell is not ("gru" or "sfo" or "fra") || now == default) return false;
            var value = JsonSerializer.Deserialize<RegionalHostSessionRequest>(json, JsonOptions);
            if (value is null ||
                subject != Subject(cell, value.Enrollment.NodeId) ||
                reply != ReplySubject(cell, value.Enrollment.NodeId, value.RequestId) ||
                !value.HasValidProof(cell, now)) return false;
            request = value;
            return true;
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or FormatException or OverflowException)
        {
            return false;
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 16
    };
}
