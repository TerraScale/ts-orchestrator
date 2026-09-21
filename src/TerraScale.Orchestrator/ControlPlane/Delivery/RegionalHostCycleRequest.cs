using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal enum RegionalHostCycleOperation { Begin = 1, Fail, Complete }
internal enum RegionalHostCycleDisposition { None, Active, Backoff, Busy, Settled }

/// <summary>Signed bookkeeping for one converge cycle; it never grants execution authority.</summary>
internal sealed record RegionalHostCycleRequest
{
    internal const int MaximumBytes = 16_384;
    private const string Domain = "terrascale-regional-host-cycle-v1";

    public RegionalHostCycleRequest(int schemaVersion, RegionalNodeEnrollmentEnvelope enrollment,
        string sessionId, ulong epoch, AdmittedRole role, string artifactDigest, RegionalHostCycleOperation operation,
        string attemptId, string? cycleId, ulong fence, string requestId, DateTimeOffset issuedAt, string signature)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        _ = AdmittedRoleCatalog.Get(role);
        if (schemaVersion != 1 || epoch == 0 || !Enum.IsDefined(operation) || signature is not { Length: 88 } ||
            issuedAt == default || issuedAt.Offset != TimeSpan.Zero || issuedAt > DateTimeOffset.MaxValue - TimeSpan.FromMinutes(15) ||
            !HostDesiredArtifactReader.ValidDigest(artifactDigest) || artifactDigest != artifactDigest.ToLowerInvariant())
            throw new ArgumentException("Cycle requests require a bounded signed session, operation, UTC time and canonical digest.");
        if (operation == RegionalHostCycleOperation.Begin ? cycleId is not null || fence != 0 : cycleId is null || fence == 0)
            throw new ArgumentException("Only cycle outcomes carry a controller cycle identity and fence.");
        if (cycleId is not null) _ = BootstrapGrantCanonical.ValidateLowercaseHex(cycleId, 32, nameof(cycleId));
        SchemaVersion = schemaVersion;
        Enrollment = enrollment;
        SessionId = BootstrapGrantCanonical.ValidateLowercaseHex(sessionId, 32, nameof(sessionId));
        Epoch = epoch;
        Role = role;
        ArtifactDigest = artifactDigest;
        Operation = operation;
        AttemptId = BootstrapGrantCanonical.ValidateLowercaseHex(attemptId, 32, nameof(attemptId));
        CycleId = cycleId;
        Fence = fence;
        RequestId = BootstrapGrantCanonical.ValidateLowercaseHex(requestId, 32, nameof(requestId));
        IssuedAt = issuedAt;
        Signature = signature;
    }

    public int SchemaVersion { get; }
    public RegionalNodeEnrollmentEnvelope Enrollment { get; }
    public string SessionId { get; }
    public ulong Epoch { get; }
    public AdmittedRole Role { get; }
    public string ArtifactDigest { get; }
    public RegionalHostCycleOperation Operation { get; }
    public string AttemptId { get; }
    public string? CycleId { get; }
    public ulong Fence { get; }
    public string RequestId { get; }
    public DateTimeOffset IssuedAt { get; }
    public string Signature { get; }

    internal byte[] CanonicalBytes() => Encoding.UTF8.GetBytes(BootstrapGrantCanonical.EncodeFields([
        Domain, Enrollment.Digest, Enrollment.Region, Enrollment.NodeId, SessionId,
        Epoch.ToString(CultureInfo.InvariantCulture), Role.ToString(), ArtifactDigest, Operation.ToString(),
        AttemptId, CycleId ?? string.Empty, Fence.ToString(CultureInfo.InvariantCulture), RequestId,
        IssuedAt.UtcTicks.ToString(CultureInfo.InvariantCulture)]));
    internal string RequestDigest => Convert.ToHexStringLower(SHA256.HashData(CanonicalBytes()));

    internal bool HasValidProof(string cell, DateTimeOffset now) =>
        cell is "gru" or "sfo" or "fra" && Enrollment.Region == cell.ToUpperInvariant() &&
        Enrollment.Scope.Roles.Contains(Role) && now != default && IssuedAt <= now &&
        now - IssuedAt < RegionalHostSessionRequest.MaximumAge &&
        NatsUserSignature.Verify(Enrollment.NatsUserPublicKey, CanonicalBytes(), Signature);

    internal static RegionalHostCycleRequest Sign(RegionalNodeEnrollmentEnvelope enrollment, NatsAuthenticationFiles authentication,
        string sessionId, ulong epoch, AdmittedRole role, string digest, RegionalHostCycleOperation operation,
        string attemptId, string? cycleId, ulong fence, DateTimeOffset issuedAt)
    {
        if (authentication.PublicKey != enrollment.NatsUserPublicKey || !enrollment.Scope.Roles.Contains(role))
            throw new InvalidOperationException("The cycle signer and role must match the signed enrollment.");
        var unsigned = new RegionalHostCycleRequest(1, enrollment, sessionId, epoch, role, digest, operation, attemptId,
            cycleId, fence, Guid.NewGuid().ToString("N"), issuedAt, Convert.ToBase64String(new byte[64]));
        return new(1, enrollment, sessionId, epoch, role, digest, operation, attemptId, cycleId, fence, unsigned.RequestId,
            issuedAt, Convert.ToBase64String(authentication.SignUserRequest(unsigned.CanonicalBytes())));
    }

    internal static string Subject(string cell, string node) => NatsSubjectTaxonomy.HostAgentObservationSubject(cell, node, "cycle");
    internal static string ReplySubject(string cell, string node, string nonce) => NatsSubjectTaxonomy.HostAgentCommandSubject(cell, node, "cycle-" + nonce);
    internal string Serialize()
    {
        var json = JsonSerializer.Serialize(this, RegionalHostSessionAuthority.JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > MaximumBytes) throw new InvalidOperationException("The cycle request exceeds its wire bounds.");
        return json;
    }

    internal static bool TryRead(string? json, string subject, string? reply, string cell, DateTimeOffset now, out RegionalHostCycleRequest? request)
    {
        request = null;
        try
        {
            if (json is not { Length: > 0 and <= MaximumBytes } || Encoding.UTF8.GetByteCount(json) > MaximumBytes) return false;
            var value = JsonSerializer.Deserialize<RegionalHostCycleRequest>(json, RegionalHostSessionAuthority.JsonOptions);
            if (value is null || !value.HasValidProof(cell, now) || subject != Subject(cell, value.Enrollment.NodeId) ||
                reply != ReplySubject(cell, value.Enrollment.NodeId, value.RequestId)) return false;
            request = value;
            return true;
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or FormatException or OverflowException) { return false; }
    }
}

internal sealed record RegionalHostCycleResponse(int SchemaVersion, string RequestId, string RequestDigest,
    RegionalHostSessionDecision Decision, ulong Generation, ulong Epoch, DateTimeOffset? ExpiresAt,
    RegionalHostCycleDisposition Disposition, string? CycleId, ulong Fence, int Failures, DateTimeOffset? NotBefore, bool? Succeeded)
{
    internal bool Accepted => Decision == RegionalHostSessionDecision.Accepted;
    internal static RegionalHostCycleResponse Deny(RegionalHostCycleRequest request, RegionalHostSessionDecision decision) =>
        new(1, request.RequestId, request.RequestDigest, decision, request.Enrollment.BootstrapGeneration, request.Epoch,
            null, RegionalHostCycleDisposition.None, null, 0, 0, null, null);

    internal void RequireBinding(RegionalHostCycleRequest request, DateTimeOffset now)
    {
        if (SchemaVersion != 1 || RequestId != request.RequestId || RequestDigest != request.RequestDigest ||
            Generation != request.Enrollment.BootstrapGeneration || Epoch != request.Epoch || !Enum.IsDefined(Decision) ||
            !Enum.IsDefined(Disposition)) throw new InvalidDataException("The cycle response does not match its signed request.");
        if (!Accepted)
        {
            if (ExpiresAt is not null || Disposition != RegionalHostCycleDisposition.None || CycleId is not null || Fence != 0 ||
                Failures != 0 || NotBefore is not null || Succeeded is not null)
                throw new InvalidDataException("Denied cycle responses cannot contain a receipt.");
            return;
        }
        if (ExpiresAt is null || ExpiresAt.Value.Offset != TimeSpan.Zero || ExpiresAt <= now || ExpiresAt > request.IssuedAt + RegionalHostSessionRequest.MaximumAge ||
            Disposition == RegionalHostCycleDisposition.None || Fence == 0 || Failures is < 0 or > 6 ||
            CycleId is not { Length: 32 } || CycleId.Any(static value => !char.IsAsciiHexDigitLower(value)) ||
            NotBefore is { } delay && (delay.Offset != TimeSpan.Zero || delay > request.IssuedAt + TimeSpan.FromMinutes(15) + RegionalHostSessionRequest.MaximumAge) ||
            Disposition == RegionalHostCycleDisposition.Backoff && (NotBefore is null || Failures == 0 || Succeeded is not null) ||
            Disposition is RegionalHostCycleDisposition.Active or RegionalHostCycleDisposition.Busy && (NotBefore is not null || Succeeded is not null) ||
            Disposition == RegionalHostCycleDisposition.Settled && (Succeeded is null ||
                (Succeeded.Value ? Failures != 0 || NotBefore is not null : Failures == 0 || NotBefore is null)) ||
            request.Operation != RegionalHostCycleOperation.Begin && (Disposition != RegionalHostCycleDisposition.Settled ||
                CycleId != request.CycleId || Fence != request.Fence || Succeeded != (request.Operation == RegionalHostCycleOperation.Complete)))
            throw new InvalidDataException("The cycle receipt has an invalid disposition, fence or deadline.");
    }
}
