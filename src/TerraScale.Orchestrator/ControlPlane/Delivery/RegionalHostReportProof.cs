using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal enum RegionalHostReportKind { Admission = 1, Runtime = 2 }

/// <summary>Key-possession proof for exact report bytes, signed role and an admitted process epoch.</summary>
internal sealed record RegionalHostReportProof
{
    internal const int MaximumPayloadBytes = 16_384;
    private const string Domain = "terrascale-regional-host-report-v1";

    public RegionalHostReportProof(int schemaVersion, RegionalNodeEnrollmentEnvelope enrollment,
        string sessionId, ulong epoch, AdmittedRole role, RegionalHostReportKind kind,
        string requestId, DateTimeOffset issuedAt, string payloadDigest, string signature)
    {
        if (schemaVersion != 1 || epoch == 0 || !Enum.IsDefined(kind))
            throw new ArgumentException("A host report requires its schema, process epoch and closed report kind.");
        ArgumentNullException.ThrowIfNull(enrollment);
        _ = AdmittedRoleCatalog.Get(role);
        if (issuedAt == default || issuedAt.Offset != TimeSpan.Zero || issuedAt > DateTimeOffset.MaxValue - RegionalHostSessionRequest.MaximumAge)
            throw new ArgumentException("A host report proof requires an explicit bounded UTC instant.");
        if (signature is not { Length: 88 }) throw new ArgumentException("A host report requires an Ed25519 signature.");
        SchemaVersion = schemaVersion;
        Enrollment = enrollment;
        SessionId = BootstrapGrantCanonical.ValidateLowercaseHex(sessionId, 32, nameof(sessionId));
        Epoch = epoch;
        Role = role;
        Kind = kind;
        RequestId = BootstrapGrantCanonical.ValidateLowercaseHex(requestId, 32, nameof(requestId));
        IssuedAt = issuedAt;
        PayloadDigest = BootstrapGrantCanonical.ValidateLowercaseHex(payloadDigest, 64, nameof(payloadDigest));
        Signature = signature;
    }

    public int SchemaVersion { get; }
    public RegionalNodeEnrollmentEnvelope Enrollment { get; }
    public string SessionId { get; }
    public ulong Epoch { get; }
    public AdmittedRole Role { get; }
    public RegionalHostReportKind Kind { get; }
    public string RequestId { get; }
    public DateTimeOffset IssuedAt { get; }
    public string PayloadDigest { get; }
    public string Signature { get; }

    internal byte[] CanonicalBytes() => Encoding.UTF8.GetBytes(BootstrapGrantCanonical.EncodeFields([
        Domain, Enrollment.Digest, Enrollment.Region, Enrollment.NodeId, SessionId,
        Epoch.ToString(CultureInfo.InvariantCulture), Role.ToString(), Kind.ToString(),
        RequestId, IssuedAt.UtcTicks.ToString(CultureInfo.InvariantCulture), PayloadDigest]));

    internal bool Verifies(string cell, AdmittedRole expectedRole, RegionalHostReportKind expectedKind,
        ReadOnlySpan<byte> payload, DateTimeOffset now) =>
        cell is "gru" or "sfo" or "fra" && Enrollment.Region == cell.ToUpperInvariant() &&
        Role == expectedRole && Kind == expectedKind && Enrollment.Scope.Roles.Contains(Role) &&
        now != default && IssuedAt <= now && now - IssuedAt < RegionalHostSessionRequest.MaximumAge &&
        payload.Length is > 0 and <= MaximumPayloadBytes &&
        PayloadDigest == Convert.ToHexStringLower(SHA256.HashData(payload)) &&
        NatsUserSignature.Verify(Enrollment.NatsUserPublicKey, CanonicalBytes(), Signature);

    internal static RegionalHostReportProof Sign(RegionalNodeEnrollmentEnvelope enrollment,
        NatsAuthenticationFiles authentication, string sessionId, ulong epoch, AdmittedRole role,
        RegionalHostReportKind kind, ReadOnlySpan<byte> payload, DateTimeOffset issuedAt)
    {
        if (authentication.PublicKey != enrollment.NatsUserPublicKey || !enrollment.Scope.Roles.Contains(role))
            throw new InvalidOperationException("The report signer or role differs from the signed enrollment.");
        if (payload.Length is < 1 or > MaximumPayloadBytes)
            throw new ArgumentException("The host report exceeds its payload bounds.");
        var unsigned = new RegionalHostReportProof(1, enrollment, sessionId, epoch, role, kind,
            Guid.NewGuid().ToString("N"), issuedAt, Convert.ToHexStringLower(SHA256.HashData(payload)),
            Convert.ToBase64String(new byte[64]));
        return new(1, enrollment, sessionId, epoch, role, kind, unsigned.RequestId, issuedAt,
            unsigned.PayloadDigest, Convert.ToBase64String(authentication.SignUserRequest(unsigned.CanonicalBytes())));
    }

    internal string Serialize()
    {
        var json = JsonSerializer.Serialize(this, RegionalHostSessionAuthority.JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > MaximumPayloadBytes)
            throw new InvalidOperationException("The host report proof exceeds its wire bounds.");
        return json;
    }
}
