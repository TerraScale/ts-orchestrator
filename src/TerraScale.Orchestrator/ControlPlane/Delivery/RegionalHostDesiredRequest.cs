using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>Selects desired state for one signed role and environment; never grants resource operations.</summary>
internal sealed record RegionalHostDesiredRequest
{
    internal const int MaximumBytes = 16_384;
    private const string Domain = "terrascale-regional-host-desired-v1";

    public RegionalHostDesiredRequest(int schemaVersion, RegionalNodeEnrollmentEnvelope enrollment,
        string sessionId, ulong epoch, AdmittedRole role, string requestId, DateTimeOffset issuedAt, string signature)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        _ = AdmittedRoleCatalog.Get(role);
        if (schemaVersion != 1 || epoch == 0 || signature is not { Length: 88 } ||
            issuedAt == default || issuedAt.Offset != TimeSpan.Zero || issuedAt > DateTimeOffset.MaxValue - RegionalHostSessionRequest.MaximumAge)
            throw new ArgumentException("Desired requests require a schema, session epoch, signature and bounded UTC time.");
        SchemaVersion = schemaVersion;
        Enrollment = enrollment;
        SessionId = BootstrapGrantCanonical.ValidateLowercaseHex(sessionId, 32, nameof(sessionId));
        Epoch = epoch;
        Role = role;
        RequestId = BootstrapGrantCanonical.ValidateLowercaseHex(requestId, 32, nameof(requestId));
        IssuedAt = issuedAt;
        Signature = signature;
    }

    public int SchemaVersion { get; }
    public RegionalNodeEnrollmentEnvelope Enrollment { get; }
    public string SessionId { get; }
    public ulong Epoch { get; }
    public AdmittedRole Role { get; }
    public string RequestId { get; }
    public DateTimeOffset IssuedAt { get; }
    public string Signature { get; }

    internal byte[] CanonicalBytes() => Encoding.UTF8.GetBytes(BootstrapGrantCanonical.EncodeFields([
        Domain, Enrollment.Digest, Enrollment.Region, Enrollment.NodeId, SessionId,
        Epoch.ToString(CultureInfo.InvariantCulture), Role.ToString(), RequestId,
        IssuedAt.UtcTicks.ToString(CultureInfo.InvariantCulture)]));
    internal string RequestDigest => Convert.ToHexStringLower(SHA256.HashData(CanonicalBytes()));

    internal bool HasValidProof(string cell, DateTimeOffset now) =>
        cell is "gru" or "sfo" or "fra" && Enrollment.Region == cell.ToUpperInvariant() &&
        Enrollment.Scope.Roles.Contains(Role) && now != default && IssuedAt <= now &&
        now - IssuedAt < RegionalHostSessionRequest.MaximumAge &&
        NatsUserSignature.Verify(Enrollment.NatsUserPublicKey, CanonicalBytes(), Signature);

    internal static RegionalHostDesiredRequest Sign(RegionalNodeEnrollmentEnvelope enrollment,
        NatsAuthenticationFiles authentication, string sessionId, ulong epoch, AdmittedRole role, DateTimeOffset issuedAt)
    {
        if (authentication.PublicKey != enrollment.NatsUserPublicKey || !enrollment.Scope.Roles.Contains(role))
            throw new InvalidOperationException("The desired signer and role must match the signed enrollment.");
        var unsigned = new RegionalHostDesiredRequest(1, enrollment, sessionId, epoch, role,
            Guid.NewGuid().ToString("N"), issuedAt, Convert.ToBase64String(new byte[64]));
        return new(1, enrollment, sessionId, epoch, role, unsigned.RequestId, issuedAt,
            Convert.ToBase64String(authentication.SignUserRequest(unsigned.CanonicalBytes())));
    }

    internal static string Subject(string cell, string node) =>
        NatsSubjectTaxonomy.HostAgentObservationSubject(cell, node, "desired");
    internal static string ReplySubject(string cell, string node, string nonce) =>
        NatsSubjectTaxonomy.HostAgentCommandSubject(cell, node, "desired-" + nonce);

    internal string Serialize()
    {
        var json = JsonSerializer.Serialize(this, RegionalHostSessionAuthority.JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > MaximumBytes)
            throw new InvalidOperationException("The desired request exceeds its wire bounds.");
        return json;
    }

    internal static bool TryRead(string? json, string subject, string? reply, string cell,
        DateTimeOffset now, out RegionalHostDesiredRequest? request)
    {
        request = null;
        try
        {
            if (json is not { Length: > 0 and <= MaximumBytes } || Encoding.UTF8.GetByteCount(json) > MaximumBytes) return false;
            var value = JsonSerializer.Deserialize<RegionalHostDesiredRequest>(json, RegionalHostSessionAuthority.JsonOptions);
            if (value is null || !value.HasValidProof(cell, now) ||
                subject != Subject(cell, value.Enrollment.NodeId) || reply != ReplySubject(cell, value.Enrollment.NodeId, value.RequestId)) return false;
            request = value;
            return true;
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or FormatException or OverflowException)
        { return false; }
    }
}

internal sealed record RegionalHostDesiredResponse(int SchemaVersion, string RequestId, string RequestDigest,
    RegionalHostSessionDecision Decision, ulong Generation, ulong Epoch, DateTimeOffset? ExpiresAt,
    string? ArtifactDigest, ulong Revision)
{
    internal bool Accepted => Decision == RegionalHostSessionDecision.Accepted;

    internal void RequireBinding(RegionalHostDesiredRequest request, DateTimeOffset now)
    {
        if (SchemaVersion != 1 || RequestId != request.RequestId || RequestDigest != request.RequestDigest ||
            Generation != request.Enrollment.BootstrapGeneration || Epoch != request.Epoch || !Enum.IsDefined(Decision) ||
            (Accepted ? ExpiresAt is null || ExpiresAt.Value.Offset != TimeSpan.Zero || ExpiresAt <= now ||
                ExpiresAt > request.IssuedAt + RegionalHostSessionRequest.MaximumAge || now < request.IssuedAt ||
                (ArtifactDigest is null ? Revision != 0 : Revision == 0 || !HostDesiredArtifactReader.ValidDigest(ArtifactDigest) ||
                    ArtifactDigest != ArtifactDigest.ToLowerInvariant())
                : ArtifactDigest is not null || Revision != 0 || ExpiresAt is not null))
            throw new InvalidDataException("The desired response is not bound to this exact current request.");
    }

    internal static RegionalHostDesiredResponse Deny(RegionalHostDesiredRequest request, RegionalHostSessionDecision decision) =>
        new(1, request.RequestId, request.RequestDigest, decision, request.Enrollment.BootstrapGeneration, request.Epoch, null, null, 0);
}
