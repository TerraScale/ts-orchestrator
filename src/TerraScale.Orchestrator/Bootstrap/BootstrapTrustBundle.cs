using System.Collections.Frozen;
using System.Security.Cryptography;

namespace TerraScale.Orchestrator.Bootstrap;

/// <summary>The purpose a trust-bundle key is provisioned for. Keys never cross purposes.</summary>
public enum BootstrapTrustKeyPurpose
{
    GrantSigning = 1,
    WorkloadAttestation = 2,
}

public static class BootstrapTrustKeyPurposeCodes
{
    public static string ToCode(BootstrapTrustKeyPurpose purpose) => purpose switch
    {
        BootstrapTrustKeyPurpose.GrantSigning => BootstrapKeyPurposeCodes.GrantSigning,
        BootstrapTrustKeyPurpose.WorkloadAttestation => BootstrapKeyPurposeCodes.WorkloadAttestation,
        _ => throw new ArgumentOutOfRangeException(nameof(purpose)),
    };
}

/// <summary>
/// One public key in a rotated Orchestrator trust bundle, identified by key id
/// and bundle-local key version. <see cref="AcceptedUntil"/> pins the rotation
/// window: a previous-version grant-signing key is accepted only for grants
/// whose entire validity ends at or before that instant, after which the bundle
/// itself refuses the key even though the signature still checks.
/// </summary>
public sealed class BootstrapTrustBundleKey
{
    public BootstrapTrustBundleKey(string keyId, ulong keyVersion, BootstrapTrustKeyPurpose purpose, byte[] subjectPublicKeyInfo, DateTimeOffset? acceptedUntil = null)
    {
        KeyId = BootstrapGrantCanonical.ValidateToken(keyId, nameof(keyId));
        if (keyVersion == 0) throw new ArgumentOutOfRangeException(nameof(keyVersion), "A trust-bundle key version must be positive.");
        if (!Enum.IsDefined(purpose)) throw new ArgumentOutOfRangeException(nameof(purpose));
        ArgumentNullException.ThrowIfNull(subjectPublicKeyInfo);
        if (subjectPublicKeyInfo.Length is < 26 or > 4096 || subjectPublicKeyInfo[0] != 0x30)
            throw new ArgumentException("A trust-bundle key must carry a bounded DER SubjectPublicKeyInfo.", nameof(subjectPublicKeyInfo));
        if (acceptedUntil is { } until && until == default) throw new ArgumentException("An acceptance deadline must be an explicit instant.", nameof(acceptedUntil));
        KeyId = keyId;
        KeyVersion = keyVersion;
        Purpose = purpose;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo.ToArray();
        AcceptedUntil = acceptedUntil;
    }

    public string KeyId { get; }
    public ulong KeyVersion { get; }
    public BootstrapTrustKeyPurpose Purpose { get; }
    public string PurposeCode => BootstrapTrustKeyPurposeCodes.ToCode(Purpose);
    public DateTimeOffset? AcceptedUntil { get; }

    /// <summary>Exports the key's ECDSA P-256 public key for signature verification.</summary>
    public ECDsa ExportPublicKey()
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
            RequireP256(key);
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    public byte[] SubjectPublicKeyInfoCopy() => subjectPublicKeyInfo.ToArray();

    internal static void RequireP256(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
            throw new ArgumentException("Only NIST P-256 is allowed.", nameof(key));
    }

    private readonly byte[] subjectPublicKeyInfo;
}

/// <summary>
/// A versioned, rotated trust bundle that the Database API holds locally so a
/// cold bootstrap verifies without a live Orchestrator or NATS lookup. The
/// bundle carries at most one current grant-signing key plus bounded retained
/// older versions, each pinned with an acceptance deadline. Keys are resolved
/// by exact (key id, key version) pair, and grant verification refuses any key
/// whose purpose is not grant signing.
/// </summary>
public sealed class RotatedBootstrapTrustBundle
{
    private const int MaximumKeys = 8;

    public RotatedBootstrapTrustBundle(ulong bundleVersion, IReadOnlyList<BootstrapTrustBundleKey> keys, string currentGrantSigningKeyId, ulong currentGrantSigningKeyVersion)
    {
        if (bundleVersion == 0) throw new ArgumentOutOfRangeException(nameof(bundleVersion), "A trust-bundle version must be positive.");
        ArgumentNullException.ThrowIfNull(keys);
        var values = keys.ToArray();
        if (values.Length is < 1 or > MaximumKeys || values.Any(static key => key is null))
            throw new ArgumentException("A trust bundle holds between one and eight keys.", nameof(keys));
        if (values.DistinctBy(static key => (key.KeyId, key.KeyVersion)).Count() != values.Length)
            throw new ArgumentException("A trust bundle cannot repeat a (key id, key version) pair.", nameof(keys));
        var currentKey = values.FirstOrDefault(key => key.KeyId == currentGrantSigningKeyId && key.KeyVersion == currentGrantSigningKeyVersion)
            ?? throw new ArgumentException("The current grant-signing key must be present in the bundle.", nameof(currentGrantSigningKeyId));
        if (currentKey.Purpose != BootstrapTrustKeyPurpose.GrantSigning)
            throw new ArgumentException("The current grant-signing key must have the grant-signing purpose.", nameof(currentGrantSigningKeyId));
        foreach (var retained in values.Where(key => key.Purpose == BootstrapTrustKeyPurpose.GrantSigning && !ReferenceEquals(key, currentKey)))
        {
            if (retained.KeyVersion >= currentKey.KeyVersion)
                throw new ArgumentException("A retained grant-signing key must be older than the current key.", nameof(keys));
            if (retained.AcceptedUntil is null)
                throw new ArgumentException("A retained grant-signing key must pin its rotation-window deadline.", nameof(keys));
        }

        BundleVersion = bundleVersion;
        this.keys = values.ToFrozenDictionary(key => (key.KeyId, key.KeyVersion), static key => key);
        CurrentGrantSigningKey = currentKey;
    }

    public ulong BundleVersion { get; }
    public BootstrapTrustBundleKey CurrentGrantSigningKey { get; }

    public BootstrapTrustBundleKey? Find(string keyId, ulong keyVersion) =>
        keys.TryGetValue((keyId, keyVersion), out var key) ? key : null;

    public bool IsCurrentGrantSigningKey(BootstrapTrustBundleKey key) => key == CurrentGrantSigningKey;

    private readonly FrozenDictionary<(string KeyId, ulong KeyVersion), BootstrapTrustBundleKey> keys;
}

