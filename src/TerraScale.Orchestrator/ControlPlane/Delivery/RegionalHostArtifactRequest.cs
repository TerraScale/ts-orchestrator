using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>Requests one bounded range of the exact artifact currently desired for this enrolled role.</summary>
internal sealed record RegionalHostArtifactRequest
{
    internal const int MaximumBytes = 16_384;
    private const string Domain = "terrascale-regional-host-artifact-v1";

    public RegionalHostArtifactRequest(int schemaVersion, RegionalNodeEnrollmentEnvelope enrollment,
        string sessionId, ulong epoch, AdmittedRole role, string artifactDigest, long offset, int length, string requestId, DateTimeOffset issuedAt, string signature)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        _ = AdmittedRoleCatalog.Get(role);
        if (schemaVersion != 1 || epoch == 0 || signature is not { Length: 88 } ||
            issuedAt == default || issuedAt.Offset != TimeSpan.Zero || issuedAt > DateTimeOffset.MaxValue - RegionalHostSessionRequest.MaximumAge)
            throw new ArgumentException("Artifact requests require a schema, session epoch, signature and bounded UTC time.");
        if (!HostDesiredArtifactReader.ValidDigest(artifactDigest) || artifactDigest != artifactDigest.ToLowerInvariant() ||
            offset < 0 || offset >= RegionalArtifactCache.MaximumArtifactBytes || length is < 1 or > RegionalArtifactCache.MaximumChunkBytes)
            throw new ArgumentException("Artifact requests require a canonical digest and bounded range.");
        ArtifactDigest = artifactDigest;
        Offset = offset;
        Length = length;
        SchemaVersion = schemaVersion;
        Enrollment = enrollment;
        SessionId = BootstrapGrantCanonical.ValidateLowercaseHex(sessionId, 32, nameof(sessionId));
        Epoch = epoch;
        Role = role;
        RequestId = BootstrapGrantCanonical.ValidateLowercaseHex(requestId, 32, nameof(requestId));
        IssuedAt = issuedAt;
        Signature = signature;
    }

    public string ArtifactDigest { get; }
    public long Offset { get; }
    public int Length { get; }
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
        Epoch.ToString(CultureInfo.InvariantCulture), Role.ToString(), ArtifactDigest, Offset.ToString(CultureInfo.InvariantCulture),
        Length.ToString(CultureInfo.InvariantCulture), RequestId,
        IssuedAt.UtcTicks.ToString(CultureInfo.InvariantCulture)]));
    internal string RequestDigest => Convert.ToHexStringLower(SHA256.HashData(CanonicalBytes()));

    internal bool HasValidProof(string cell, DateTimeOffset now) =>
        cell is "gru" or "sfo" or "fra" && Enrollment.Region == cell.ToUpperInvariant() &&
        Enrollment.Scope.Roles.Contains(Role) && now != default && IssuedAt <= now &&
        now - IssuedAt < RegionalHostSessionRequest.MaximumAge &&
        NatsUserSignature.Verify(Enrollment.NatsUserPublicKey, CanonicalBytes(), Signature);

    internal static RegionalHostArtifactRequest Sign(RegionalNodeEnrollmentEnvelope enrollment,
        NatsAuthenticationFiles authentication, string sessionId, ulong epoch, AdmittedRole role, string artifactDigest, long offset, int length, DateTimeOffset issuedAt)
    {
        if (authentication.PublicKey != enrollment.NatsUserPublicKey || !enrollment.Scope.Roles.Contains(role))
            throw new InvalidOperationException("The artifact signer and role must match the signed enrollment.");
        var unsigned = new RegionalHostArtifactRequest(1, enrollment, sessionId, epoch, role, artifactDigest, offset, length,
            Guid.NewGuid().ToString("N"), issuedAt, Convert.ToBase64String(new byte[64]));
        return new(1, enrollment, sessionId, epoch, role, artifactDigest, offset, length, unsigned.RequestId, issuedAt,
            Convert.ToBase64String(authentication.SignUserRequest(unsigned.CanonicalBytes())));
    }

    internal static string Subject(string cell, string node) =>
        NatsSubjectTaxonomy.HostAgentObservationSubject(cell, node, "artifact");
    internal static string ReplySubject(string cell, string node, string nonce) =>
        NatsSubjectTaxonomy.HostAgentCommandSubject(cell, node, "artifact-" + nonce);

    internal string Serialize()
    {
        var json = JsonSerializer.Serialize(this, RegionalHostSessionAuthority.JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > MaximumBytes)
            throw new InvalidOperationException("The artifact request exceeds its wire bounds.");
        return json;
    }

    internal static bool TryRead(string? json, string subject, string? reply, string cell,
        DateTimeOffset now, out RegionalHostArtifactRequest? request)
    {
        request = null;
        try
        {
            if (json is not { Length: > 0 and <= MaximumBytes } || Encoding.UTF8.GetByteCount(json) > MaximumBytes) return false;
            var value = JsonSerializer.Deserialize<RegionalHostArtifactRequest>(json, RegionalHostSessionAuthority.JsonOptions);
            if (value is null || !value.HasValidProof(cell, now) ||
                subject != Subject(cell, value.Enrollment.NodeId) || reply != ReplySubject(cell, value.Enrollment.NodeId, value.RequestId)) return false;
            request = value;
            return true;
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or FormatException or OverflowException)
        { return false; }
    }
}

internal sealed record RegionalHostArtifactResponse(int SchemaVersion, string RequestId, string RequestDigest,
    RegionalHostSessionDecision Decision, ulong Generation, ulong Epoch, DateTimeOffset? ExpiresAt,
    string ArtifactDigest, long Offset, long TotalBytes, byte[]? Bytes, bool End)
{
    internal const int MaximumWireBytes = 720_896;
    internal bool Accepted => Decision == RegionalHostSessionDecision.Accepted;

    internal void RequireBinding(RegionalHostArtifactRequest request, DateTimeOffset now)
    {
        if (SchemaVersion != 1 || RequestId != request.RequestId || RequestDigest != request.RequestDigest ||
            Generation != request.Enrollment.BootstrapGeneration || Epoch != request.Epoch || !Enum.IsDefined(Decision) ||
            ArtifactDigest != request.ArtifactDigest || Offset != request.Offset ||
            (Accepted ? ExpiresAt is null || ExpiresAt.Value.Offset != TimeSpan.Zero || ExpiresAt <= now ||
                ExpiresAt > request.IssuedAt + RegionalHostSessionRequest.MaximumAge || now < request.IssuedAt ||
                TotalBytes is < 1 or > RegionalArtifactCache.MaximumArtifactBytes || Offset >= TotalBytes ||
                Bytes is null || Bytes.Length != Math.Min(request.Length, TotalBytes - Offset) || End != (Offset + Bytes.Length == TotalBytes)
                : Bytes is not null || TotalBytes != 0 || End || ExpiresAt is not null))
            throw new InvalidDataException("The artifact response is not bound to this exact current request and range.");
    }

    internal static RegionalHostArtifactResponse Deny(RegionalHostArtifactRequest request, RegionalHostSessionDecision decision) =>
        new(1, request.RequestId, request.RequestDigest, decision, request.Enrollment.BootstrapGeneration, request.Epoch,
            null, request.ArtifactDigest, request.Offset, 0, null, false);
}
