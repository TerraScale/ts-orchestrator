using System.Security.Cryptography;
using System.Text;
using BootstrapSignatureEvidence = TerraScale.Orchestrator.Security.SystemProjectBootstrap.BootstrapGrantSignatureEvidence;
using BootstrapSignatureStatus = TerraScale.Orchestrator.Security.SystemProjectBootstrap.BootstrapGrantSignatureStatus;
using BootstrapSystemProjectTrustKey = TerraScale.Orchestrator.Security.SystemProjectBootstrap.BootstrapTrustBundleKey;
using BootstrapSystemProjectTrustKeyId = TerraScale.Orchestrator.Security.SystemProjectBootstrap.BootstrapTrustBundleKeyId;
using BootstrapSystemProjectTrustVersion = TerraScale.Orchestrator.Security.SystemProjectBootstrap.BootstrapTrustBundleVersion;
using ReplayOutcome = TerraScale.Orchestrator.Security.SystemProjectBootstrap.BootstrapReplayConsumeResult;

namespace TerraScale.Orchestrator.Bootstrap;

/// <summary>
/// Typed decisions for local cold-bootstrap grant verification. Every denial
/// names its exact reason; none of them distinguishes which byte of a
/// signature failed.
/// </summary>
public enum SignedBootstrapGrantDecision
{
    Authorized = 1,
    UnknownAlgorithm = 2,
    NonCanonicalPayload = 3,
    UnknownSigningKey = 4,
    KeyPurposeMismatch = 5,
    InvalidSignature = 6,
    RotationWindowExceeded = 7,
    AudienceMismatch = 8,
    CertificateMismatch = 9,
    NotYetValid = 10,
    Expired = 11,
    InvalidValidityWindow = 12,
    LifetimeExceeded = 13,
    SystemProjectMismatch = 14,
    OperationNotAllowed = 15,
    OperationNotIdempotent = 16,
    ReplayDetected = 17,
    ReplayRejected = 18,
    ReplayJournalUnavailable = 19,
}

/// <summary>
/// What the bootstrap caller is asking for: the audience it serves, the
/// certificate it actually saw on the wire, the operation it was asked to
/// admit, the fixed system Project identity, and the local clock.
/// </summary>
public sealed record BootstrapGrantVerificationRequest
{
    public BootstrapGrantVerificationRequest(
        string expectedAudience,
        string presentedCertificateFingerprint,
        string requestedOperation,
        BootstrapSystemProjectUlds expectedSystemProject,
        DateTimeOffset now,
        TimeSpan maximumLifetime)
    {
        ExpectedAudience = BootstrapGrantCanonical.ValidateToken(expectedAudience, nameof(expectedAudience));
        PresentedCertificateFingerprint = new BootstrapCertificateFingerprint(presentedCertificateFingerprint);
        RequestedOperation = BootstrapGrantCanonical.ValidateToken(requestedOperation, nameof(requestedOperation));
        ExpectedSystemProject = expectedSystemProject ?? throw new ArgumentNullException(nameof(expectedSystemProject));
        if (now == default) throw new ArgumentException("A verification instant must be explicit.", nameof(now));
        if (maximumLifetime <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(maximumLifetime));
        Now = now;
        MaximumLifetime = maximumLifetime;
    }

    public string ExpectedAudience { get; }
    public BootstrapCertificateFingerprint PresentedCertificateFingerprint { get; }
    public string RequestedOperation { get; }
    public BootstrapSystemProjectUlds ExpectedSystemProject { get; }
    public DateTimeOffset Now { get; }
    public TimeSpan MaximumLifetime { get; }
}

/// <summary>
/// The local verification result. It deliberately carries no grant identity,
/// nonce, audience, or certificate value so an audit log cannot leak bound
/// material; it names only the decision and the trust-bundle key used.
/// </summary>
public sealed record SignedBootstrapGrantVerification
{
    internal SignedBootstrapGrantVerification(SignedBootstrapGrantDecision decision, string? verifiedKeyId, ulong? verifiedKeyVersion, bool signatureVerified)
    {
        Decision = decision;
        VerifiedKeyId = verifiedKeyId;
        VerifiedKeyVersion = verifiedKeyVersion;
        SignatureVerified = signatureVerified;
    }

    public bool Authorized => Decision == SignedBootstrapGrantDecision.Authorized;
    public SignedBootstrapGrantDecision Decision { get; }
    public string? VerifiedKeyId { get; }
    public ulong? VerifiedKeyVersion { get; }
    public bool SignatureVerified { get; }

    /// <summary>
    /// Bridges this result into the signature evidence consumed by the
    /// <c>Security.SystemProjectBootstrap.BootstrapGrantVerifier</c> policy
    /// engine, so the cryptographic layer and the landed policy layer compose.
    /// </summary>
    public BootstrapSignatureEvidence ToSignatureEvidence() =>
        SignatureVerified && VerifiedKeyId is not null && VerifiedKeyVersion is not null
            ? new BootstrapSignatureEvidence(
                BootstrapSignatureStatus.Valid,
                new BootstrapSystemProjectTrustKey(new BootstrapSystemProjectTrustKeyId(VerifiedKeyId), new BootstrapSystemProjectTrustVersion(VerifiedKeyVersion.Value)))
            : new BootstrapSignatureEvidence(BootstrapSignatureStatus.Invalid, null);

    public sealed override string ToString() => Decision.ToString();
}

/// <summary>
/// Verifies a signed cold-bootstrap grant entirely from a locally available
/// rotated trust bundle: canonical payload form, signature, key purpose,
/// rotation window, audience, certificate binding, validity window, fixed
/// system Project identity, idempotent operation allowlist, and one-time
/// replay consumption. No Orchestrator, NATS, or other network lookup is
/// involved or permitted on this path.
/// </summary>
public static class SignedBootstrapGrantVerifier
{
    public static SignedBootstrapGrantVerification Verify(
        SignedBootstrapGrant grant,
        RotatedBootstrapTrustBundle trustBundle,
        BootstrapGrantVerificationRequest request,
        IBootstrapGrantReplayJournal? replayJournal)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(trustBundle);
        ArgumentNullException.ThrowIfNull(request);

        if (grant.Algorithm != SignedBootstrapGrant.SigningAlgorithm)
            return Deny(SignedBootstrapGrantDecision.UnknownAlgorithm, null, null);

        BootstrapGrantPayload payload;
        try
        {
            payload = grant.ParsePayload();
        }
        catch (FormatException)
        {
            return Deny(SignedBootstrapGrantDecision.NonCanonicalPayload, null, null);
        }

        if (payload.Encode() != grant.PayloadText)
            return Deny(SignedBootstrapGrantDecision.NonCanonicalPayload, payload.KeyId, payload.KeyVersion);

        var key = trustBundle.Find(payload.KeyId, payload.KeyVersion);
        if (key is null)
            return Deny(SignedBootstrapGrantDecision.UnknownSigningKey, payload.KeyId, payload.KeyVersion);
        if (key.Purpose != BootstrapTrustKeyPurpose.GrantSigning)
            return Deny(SignedBootstrapGrantDecision.KeyPurposeMismatch, payload.KeyId, payload.KeyVersion);

        if (!VerifySignature(key, grant))
            return Deny(SignedBootstrapGrantDecision.InvalidSignature, payload.KeyId, payload.KeyVersion);

        // The signature and key are proven from here on; only binding and policy remain.
        if (payload.Audience != request.ExpectedAudience)
            return Deny(SignedBootstrapGrantDecision.AudienceMismatch, payload.KeyId, payload.KeyVersion);
        if (!FixedTimeEquals(payload.CertificateFingerprint.Value, request.PresentedCertificateFingerprint.Value))
            return Deny(SignedBootstrapGrantDecision.CertificateMismatch, payload.KeyId, payload.KeyVersion);

        if (payload.ExpiresAt <= payload.IssuedAt) return Deny(SignedBootstrapGrantDecision.InvalidValidityWindow, payload.KeyId, payload.KeyVersion);
        if (request.Now < payload.IssuedAt) return Deny(SignedBootstrapGrantDecision.NotYetValid, payload.KeyId, payload.KeyVersion);
        if (request.Now >= payload.ExpiresAt) return Deny(SignedBootstrapGrantDecision.Expired, payload.KeyId, payload.KeyVersion);
        if (payload.ExpiresAt - payload.IssuedAt > request.MaximumLifetime) return Deny(SignedBootstrapGrantDecision.LifetimeExceeded, payload.KeyId, payload.KeyVersion);

        if (key.AcceptedUntil is { } pinned && payload.ExpiresAt > pinned)
            return Deny(SignedBootstrapGrantDecision.RotationWindowExceeded, payload.KeyId, payload.KeyVersion);

        if (payload.SystemProject != request.ExpectedSystemProject)
            return Deny(SignedBootstrapGrantDecision.SystemProjectMismatch, payload.KeyId, payload.KeyVersion);
        if (!payload.AllowedOperations.Contains(request.RequestedOperation))
            return Deny(SignedBootstrapGrantDecision.OperationNotAllowed, payload.KeyId, payload.KeyVersion);
        if (payload.AllowedOperations.Any(operation => !BootstrapGrantOperation.IsIdempotentBootstrapOperation(operation)))
            return Deny(SignedBootstrapGrantDecision.OperationNotIdempotent, payload.KeyId, payload.KeyVersion);

        if (replayJournal is null)
            return Deny(SignedBootstrapGrantDecision.ReplayJournalUnavailable, payload.KeyId, payload.KeyVersion);
        var consumed = replayJournal.TryConsume(payload.GrantId.Value, payload.Nonce, payload.ExpiresAt);
        return consumed switch
        {
            ReplayOutcome.Consumed => new SignedBootstrapGrantVerification(SignedBootstrapGrantDecision.Authorized, payload.KeyId, payload.KeyVersion, true),
            ReplayOutcome.AlreadyConsumed => Deny(SignedBootstrapGrantDecision.ReplayDetected, payload.KeyId, payload.KeyVersion),
            ReplayOutcome.Rejected => Deny(SignedBootstrapGrantDecision.ReplayRejected, payload.KeyId, payload.KeyVersion),
            _ => Deny(SignedBootstrapGrantDecision.ReplayJournalUnavailable, payload.KeyId, payload.KeyVersion),
        };
    }

    /// <summary>
    /// Verifies only the cryptographic layer — canonical form, algorithm, key
    /// presence, purpose, signature, and rotation window — and returns the
    /// bridged signature evidence for the policy engine plus the parsed
    /// payload. Binding checks stay with the full <see cref="Verify"/> path.
    /// </summary>
    public static (SignedBootstrapGrantVerification Crypto, BootstrapGrantPayload? Payload) VerifyCryptographic(
        SignedBootstrapGrant grant,
        RotatedBootstrapTrustBundle trustBundle,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(trustBundle);
        if (grant.Algorithm != SignedBootstrapGrant.SigningAlgorithm)
            return (Deny(SignedBootstrapGrantDecision.UnknownAlgorithm, null, null), null);

        BootstrapGrantPayload payload;
        try
        {
            payload = grant.ParsePayload();
        }
        catch (FormatException)
        {
            return (Deny(SignedBootstrapGrantDecision.NonCanonicalPayload, null, null), null);
        }

        if (payload.Encode() != grant.PayloadText)
            return (Deny(SignedBootstrapGrantDecision.NonCanonicalPayload, payload.KeyId, payload.KeyVersion), payload);

        var key = trustBundle.Find(payload.KeyId, payload.KeyVersion);
        if (key is null)
            return (Deny(SignedBootstrapGrantDecision.UnknownSigningKey, payload.KeyId, payload.KeyVersion), payload);
        if (key.Purpose != BootstrapTrustKeyPurpose.GrantSigning)
            return (Deny(SignedBootstrapGrantDecision.KeyPurposeMismatch, payload.KeyId, payload.KeyVersion), payload);
        if (!VerifySignature(key, grant))
            return (Deny(SignedBootstrapGrantDecision.InvalidSignature, payload.KeyId, payload.KeyVersion), payload);
        if (key.AcceptedUntil is { } pinned && payload.ExpiresAt > pinned)
            return (Deny(SignedBootstrapGrantDecision.RotationWindowExceeded, payload.KeyId, payload.KeyVersion), payload);
        if (payload.ExpiresAt <= payload.IssuedAt || now < payload.IssuedAt || now >= payload.ExpiresAt)
            return (Deny(SignedBootstrapGrantDecision.Expired, payload.KeyId, payload.KeyVersion), payload);

        return (new SignedBootstrapGrantVerification(SignedBootstrapGrantDecision.Authorized, payload.KeyId, payload.KeyVersion, true), payload);
    }

    private static bool VerifySignature(BootstrapTrustBundleKey key, SignedBootstrapGrant grant)
    {
        try
        {
            using var publicKey = key.ExportPublicKey();
            return publicKey.VerifyData(grant.PayloadBytes(), Convert.FromBase64String(grant.Signature), HashAlgorithmName.SHA256);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool FixedTimeEquals(string left, string right) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));

    private static SignedBootstrapGrantVerification Deny(SignedBootstrapGrantDecision decision, string? keyId, ulong? keyVersion) =>
        new(decision, keyId, keyVersion, false);
}
