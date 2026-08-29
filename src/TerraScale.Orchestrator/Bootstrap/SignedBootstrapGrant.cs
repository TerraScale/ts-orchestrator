using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TerraScale.Orchestrator.Bootstrap;

/// <summary>
/// The signed cold-bootstrap grant wire form: one canonical payload text plus
/// one ECDSA P-256 signature over its UTF-8 bytes. The key identity and
/// purpose live inside the signed payload, so every bound field is covered by
/// the signature.
/// </summary>
public sealed record SignedBootstrapGrant
{
    public const string SigningAlgorithm = "ECDSA-P256-SHA256";

    public SignedBootstrapGrant(string payloadText, string algorithm, string signature)
    {
        ArgumentException.ThrowIfNullOrEmpty(payloadText);
        ArgumentException.ThrowIfNullOrEmpty(signature);
        if (algorithm != SigningAlgorithm || !IsBase64(signature))
            throw new ArgumentException("A signed grant requires the pinned algorithm and a base64 signature.");
        PayloadText = payloadText;
        Algorithm = algorithm;
        Signature = signature;
    }

    public string PayloadText { get; init; }
    public string Algorithm { get; init; }
    public string Signature { get; init; }

    public BootstrapGrantPayload ParsePayload() => BootstrapGrantPayload.Parse(PayloadText);

    internal byte[] PayloadBytes() => Encoding.UTF8.GetBytes(PayloadText);

    private static bool IsBase64(string value)
    {
        try
        {
            _ = Convert.FromBase64String(value);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

/// <summary>
/// The Orchestrator-side bootstrap grant issuer. It signs one canonical
/// payload with the bundle's grant-signing private key. Refusing to sign with
/// a non-grant-signing key is the issuance half of key purpose separation.
/// </summary>
public sealed class BootstrapGrantIssuer : IDisposable
{
    private readonly ECDsa signingKey;

    public BootstrapGrantIssuer(string keyId, ulong keyVersion, BootstrapTrustKeyPurpose purpose, ECDsa signingKey)
    {
        KeyId = BootstrapGrantCanonical.ValidateToken(keyId, nameof(keyId));
        if (keyVersion == 0) throw new ArgumentOutOfRangeException(nameof(keyVersion), "A trust-bundle key version must be positive.");
        if (!Enum.IsDefined(purpose)) throw new ArgumentOutOfRangeException(nameof(purpose));
        if (purpose != BootstrapTrustKeyPurpose.GrantSigning)
            throw new ArgumentException("A bootstrap grant issuer must use a grant-signing purpose key.", nameof(purpose));
        this.signingKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
        BootstrapTrustBundleKey.RequireP256(this.signingKey);
        KeyVersion = keyVersion;
        Purpose = purpose;
    }

    public string KeyId { get; }
    public ulong KeyVersion { get; }
    public BootstrapTrustKeyPurpose Purpose { get; }

    public SignedBootstrapGrant Sign(BootstrapGrantPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (payload.KeyId != KeyId || payload.KeyVersion != KeyVersion || payload.KeyPurposeCode != BootstrapTrustKeyPurposeCodes.ToCode(Purpose))
            throw new ArgumentException("The payload must name exactly this issuer's key identity and purpose.", nameof(payload));
        var payloadText = payload.Encode();
        var signature = Convert.ToBase64String(signingKey.SignData(Encoding.UTF8.GetBytes(payloadText), HashAlgorithmName.SHA256));
        return new SignedBootstrapGrant(payloadText, SignedBootstrapGrant.SigningAlgorithm, signature);
    }

    public BootstrapTrustBundleKey ExportPublicKey(DateTimeOffset? acceptedUntil = null) =>
        new(KeyId, KeyVersion, Purpose, signingKey.ExportSubjectPublicKeyInfo(), acceptedUntil);

    public void Dispose() => signingKey.Dispose();
}

/// <summary>
/// Helpers for the short-lived X.509 workload identity the grant binds. The
/// canonical binding value is the lowercase SHA-256 hex digest of the
/// certificate's SubjectPublicKeyInfo, so the Database API can recompute it
/// from the certificate presented during the TLS handshake without any
/// Orchestrator round trip.
/// </summary>
public static class BootstrapWorkloadIdentity
{
    public static BootstrapCertificateFingerprint CertificateFingerprint(byte[] subjectPublicKeyInfo)
    {
        ArgumentNullException.ThrowIfNull(subjectPublicKeyInfo);
        return new BootstrapCertificateFingerprint(Convert.ToHexStringLower(SHA256.HashData(subjectPublicKeyInfo)));
    }

    /// <summary>
    /// Mints a short-lived self-signed ECDSA P-256 development workload
    /// certificate. Production workload identity issuance stays with the
    /// Orchestrator provider adapter; this is the local, testable shape.
    /// </summary>
    public static BootstrapWorkloadCertificate IssueDevelopmentWorkloadCertificate(
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        string commonName = "terrascale-bootstrap-workload")
    {
        if (notAfter <= notBefore) throw new ArgumentOutOfRangeException(nameof(notAfter), "A workload certificate must have a positive lifetime.");
        ArgumentException.ThrowIfNullOrEmpty(commonName);
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
            var certificate = request.CreateSelfSigned(notBefore.UtcDateTime, notAfter.UtcDateTime);
            return new BootstrapWorkloadCertificate(certificate, key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }
}

public sealed class BootstrapWorkloadCertificate : IDisposable
{
    public BootstrapWorkloadCertificate(X509Certificate2 certificate, ECDsa privateKey)
    {
        Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        this.privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
    }

    public X509Certificate2 Certificate { get; }

    /// <summary>The exact SubjectPublicKeyInfo bytes the certificate wraps, taken from the key itself.</summary>
    public byte[] ExportSubjectPublicKeyInfo() => privateKey.ExportSubjectPublicKeyInfo();

    public BootstrapCertificateFingerprint Fingerprint() =>
        BootstrapWorkloadIdentity.CertificateFingerprint(ExportSubjectPublicKeyInfo());

    public void Dispose()
    {
        Certificate.Dispose();
        privateKey.Dispose();
    }

    private readonly ECDsa privateKey;
}
