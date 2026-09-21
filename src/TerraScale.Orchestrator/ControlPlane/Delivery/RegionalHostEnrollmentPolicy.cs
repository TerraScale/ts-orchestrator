using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Bootstrap;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

/// <summary>
/// Admission policy owned by a regional controller. Continuing authorization applies only
/// to an exact previously committed enrollment; it never authorizes bootstrap operations.
/// </summary>
internal sealed class RegionalHostEnrollmentPolicy
{
    private readonly string accountPublicKey;
    private readonly string clusterName;
    private readonly RegionalNodeEnrollmentScope allowedScope;
    private readonly string signerKeyId;
    private readonly ulong signerKeyVersion;
    private readonly byte[] signerPublicKey;
    private readonly RotatedBootstrapTrustBundle bootstrapTrust;
    private readonly BootstrapSystemProjectUlds systemProject;
    private readonly string bootstrapOperation;
    private readonly TimeSpan maximumGrantLifetime;

    internal RegionalHostEnrollmentPolicy(string cell, string accountPublicKey, string clusterName,
        RegionalNodeEnrollmentScope allowedScope, string signerKeyId, ulong signerKeyVersion,
        ECDsa signerPublicKey, RotatedBootstrapTrustBundle bootstrapTrust,
        BootstrapSystemProjectUlds systemProject, string bootstrapOperation, TimeSpan maximumGrantLifetime)
    {
        if (cell is not ("gru" or "sfo" or "fra")) throw new ArgumentException("A host session policy requires a regional cell.", nameof(cell));
        ArgumentException.ThrowIfNullOrWhiteSpace(accountPublicKey);
        ArgumentNullException.ThrowIfNull(allowedScope);
        ArgumentNullException.ThrowIfNull(bootstrapTrust);
        ArgumentNullException.ThrowIfNull(systemProject);
        BootstrapTrustBundleKey.RequireP256(signerPublicKey);
        if (signerKeyVersion == 0 || maximumGrantLifetime <= TimeSpan.Zero || maximumGrantLifetime > TimeSpan.FromDays(1))
            throw new ArgumentException("Enrollment policy requires a positive signer version and bounded grant lifetime.");
        if (!BootstrapGrantOperation.IsIdempotentBootstrapOperation(bootstrapOperation))
            throw new ArgumentException("Enrollment requires a closed bootstrap operation.", nameof(bootstrapOperation));
        Cell = cell;
        this.accountPublicKey = accountPublicKey;
        this.clusterName = RegionalNodeEnrollmentEnvelope.ValidateToken(clusterName, nameof(clusterName));
        this.allowedScope = allowedScope;
        this.signerKeyId = BootstrapGrantCanonical.ValidateToken(signerKeyId, nameof(signerKeyId));
        this.signerKeyVersion = signerKeyVersion;
        this.signerPublicKey = signerPublicKey.ExportSubjectPublicKeyInfo();
        this.bootstrapTrust = bootstrapTrust;
        this.systemProject = systemProject;
        this.bootstrapOperation = bootstrapOperation;
        this.maximumGrantLifetime = maximumGrantLifetime;
    }

    internal string Cell { get; }

    internal bool AllowsFreshEnrollment(RegionalNodeEnrollmentEnvelope enrollment, DateTimeOffset now, DateTimeOffset leaseExpiresAt) =>
        Allows(enrollment, now, leaseExpiresAt, continuing: false);

    internal bool AllowsContinuingEnrollment(RegionalNodeEnrollmentEnvelope enrollment, DateTimeOffset now, DateTimeOffset leaseExpiresAt) =>
        Allows(enrollment, now, leaseExpiresAt, continuing: true);

    private bool Allows(RegionalNodeEnrollmentEnvelope enrollment, DateTimeOffset now, DateTimeOffset leaseExpiresAt, bool continuing)
    {
        try
        {
            if (now == default || leaseExpiresAt <= now || leaseExpiresAt - now > RegionalHostSessionAuthority.LeaseLifetime ||
                enrollment.Region != Cell.ToUpperInvariant() ||
                enrollment.NatsAccountPublicKey != accountPublicKey || enrollment.ClusterName != clusterName ||
                enrollment.Scope.Environment != allowedScope.Environment ||
                enrollment.Scope.Roles.Any(role => !allowedScope.Roles.Contains(role)) ||
                enrollment.SignerKeyId != signerKeyId || enrollment.SignerKeyVersion != signerKeyVersion) return false;
            using var enrollmentKey = ECDsa.Create();
            enrollmentKey.ImportSubjectPublicKeyInfo(signerPublicKey, out _);
            if (!enrollmentKey.VerifyData(Encoding.UTF8.GetBytes(enrollment.CanonicalUnsigned()),
                    Convert.FromBase64String(enrollment.Signature), HashAlgorithmName.SHA256)) return false;

            var grant = enrollment.Grant;
            var payload = grant.ParsePayload();
            if (grant.Algorithm != SignedBootstrapGrant.SigningAlgorithm || payload.Encode() != grant.PayloadText ||
                payload.KeyPurposeCode != BootstrapKeyPurposeCodes.GrantSigning ||
                payload.Audience != enrollment.NodeId || payload.SystemProject != systemProject ||
                payload.IssuedAt > now || payload.ExpiresAt <= payload.IssuedAt ||
                payload.ExpiresAt - payload.IssuedAt > maximumGrantLifetime ||
                (!continuing && now >= payload.ExpiresAt) ||
                !payload.AllowedOperations.Contains(bootstrapOperation, StringComparer.Ordinal) ||
                payload.AllowedOperations.Any(operation => !BootstrapGrantOperation.IsIdempotentBootstrapOperation(operation))) return false;
            var grantKey = bootstrapTrust.Find(payload.KeyId, payload.KeyVersion);
            if (grantKey is null || grantKey.Purpose != BootstrapTrustKeyPurpose.GrantSigning ||
                (grantKey.AcceptedUntil is { } until && (payload.ExpiresAt > until || leaseExpiresAt > until))) return false;
            using var publicKey = grantKey.ExportPublicKey();
            return publicKey.VerifyData(grant.PayloadBytes(), Convert.FromBase64String(grant.Signature), HashAlgorithmName.SHA256);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or OverflowException or CryptographicException)
        {
            return false;
        }
    }
}
