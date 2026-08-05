using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

public sealed record CreateNodeReceiptBinding(
    string OperationId, string TenantId, string NodeRequestId, string IdempotencyKey, string CreateKey,
    string CellId, string CompartmentId, ulong Generation, ulong Epoch, string TemplateId,
    string PlacementId, string BootstrapEnvelopeDigest, long AuthorizationSequence, string AuthorizationDigest,
    string ProviderContextFingerprint)
{
    internal string Digest => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CreateNodeHandoffReceipt.Canonical(
        "create-node-binding-v1", OperationId, TenantId, NodeRequestId, IdempotencyKey, CreateKey, CellId, CompartmentId,
        Generation, Epoch, TemplateId, PlacementId, BootstrapEnvelopeDigest, AuthorizationSequence, AuthorizationDigest, ProviderContextFingerprint))));
}

public sealed record CreateNodeHandoffReceipt(
    string Algorithm, string KeyId, CreateNodeReceiptBinding Binding,
    DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, string Signature)
{
    internal byte[] Payload() => Encoding.UTF8.GetBytes(Canonical("terrascale-create-node-handoff-v2", Algorithm, KeyId,
        Binding.OperationId, "CreateNode", Binding.TenantId, Binding.NodeRequestId, Binding.IdempotencyKey,
        Binding.CreateKey, Binding.CellId, Binding.CompartmentId, Binding.Generation, Binding.Epoch,
        Binding.TemplateId, Binding.PlacementId, Binding.BootstrapEnvelopeDigest, Binding.AuthorizationSequence,
        Binding.AuthorizationDigest, Binding.ProviderContextFingerprint, IssuedAt.ToUniversalTime().Ticks, ExpiresAt.ToUniversalTime().Ticks));

    internal static string Canonical(params object[] values) => string.Concat(values.Select(static value =>
    {
        var text = Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        return string.Concat(text.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), ":", text, ";");
    }));
}

public interface ICreateNodeReceiptKeyResolver
{
    bool TryResolve(string keyId, string algorithm, out byte[] subjectPublicKeyInfo);
}

public class CreateNodeReceiptKeyRing : ICreateNodeReceiptKeyResolver
{
    private readonly IReadOnlyDictionary<string, byte[]> keys;
    public CreateNodeReceiptKeyRing(IReadOnlyDictionary<string, byte[]> keys) => this.keys = keys.ToDictionary(
        static pair => pair.Key, static pair => pair.Value.ToArray(), StringComparer.Ordinal);
    public bool TryResolve(string keyId, string algorithm, out byte[] subjectPublicKeyInfo)
    {
        if (algorithm != CreateNodeHandoffReceiptSigner.Algorithm || !keys.TryGetValue(keyId, out var key))
        { subjectPublicKeyInfo = []; return false; }
        subjectPublicKeyInfo = key.ToArray(); return true;
    }
}
public interface ICreateNodeTenantAuthorityKeyResolver : ICreateNodeReceiptKeyResolver { }
public interface ICreateNodeProviderAttestationKeyResolver : ICreateNodeReceiptKeyResolver { }
public interface ICreateNodeRecoveryLookupKeyResolver : ICreateNodeReceiptKeyResolver { }
public sealed class CreateNodeTenantAuthorityKeyRing(IReadOnlyDictionary<string, byte[]> keys) : CreateNodeReceiptKeyRing(keys), ICreateNodeTenantAuthorityKeyResolver { }
public sealed class CreateNodeProviderAttestationKeyRing(IReadOnlyDictionary<string, byte[]> keys) : CreateNodeReceiptKeyRing(keys), ICreateNodeProviderAttestationKeyResolver { }
public sealed class CreateNodeRecoveryLookupKeyRing(IReadOnlyDictionary<string, byte[]> keys) : CreateNodeReceiptKeyRing(keys), ICreateNodeRecoveryLookupKeyResolver { }

public sealed class CreateNodeHandoffReceiptSigner
{
    public const string Algorithm = "ECDSA-P256-SHA256";
    private readonly ECDsa signingKey;
    public CreateNodeHandoffReceiptSigner(string keyId, ECDsa signingKey)
    { if (string.IsNullOrWhiteSpace(keyId)) throw new ArgumentException("A receipt key ID is required.", nameof(keyId)); this.signingKey = RequireP256(signingKey); KeyId = keyId; }
    public string KeyId { get; }
    public byte[] ExportPublicKey() => signingKey.ExportSubjectPublicKeyInfo();
    public CreateNodeHandoffReceipt Sign(CreateNodeReceiptBinding binding, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        Validate(binding, issuedAt, expiresAt);
        var unsigned = new CreateNodeHandoffReceipt(Algorithm, KeyId, binding, issuedAt, expiresAt, string.Empty);
        return unsigned with { Signature = Convert.ToBase64String(signingKey.SignData(unsigned.Payload(), HashAlgorithmName.SHA256)) };
    }
    public CreateNodeTenantAuthorizationProof SignTenantProof(string tenant, string operation, string authorizationDigest, DateTimeOffset expiresAt)
    { var unsigned = new CreateNodeTenantAuthorizationProof(Algorithm, KeyId, tenant, operation, "CreateNode", authorizationDigest, expiresAt, string.Empty); return unsigned with { Signature = Convert.ToBase64String(signingKey.SignData(unsigned.Payload(), HashAlgorithmName.SHA256)) }; }
    internal static void Validate(CreateNodeReceiptBinding binding, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (new[] { binding.OperationId, binding.TenantId, binding.NodeRequestId, binding.IdempotencyKey, binding.CreateKey,
            binding.CellId, binding.CompartmentId, binding.TemplateId, binding.PlacementId, binding.BootstrapEnvelopeDigest,
            binding.AuthorizationDigest, binding.ProviderContextFingerprint }.Any(string.IsNullOrWhiteSpace) || binding.Generation == 0 || binding.Epoch == 0 ||
            binding.AuthorizationSequence <= 0 || issuedAt == default || expiresAt <= issuedAt)
            throw new ArgumentException("Receipt binding must be complete and have a positive lifetime.");
    }
    internal static ECDsa RequireP256(ECDsa key)
    { ArgumentNullException.ThrowIfNull(key); if (key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value) throw new ArgumentException("Only NIST P-256 is allowed.", nameof(key)); return key; }
}

public sealed record CreateNodeRecoveryLookupAuthority(string Algorithm, string KeyId, string Audience, string BindingDigest,
    DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, string Signature)
{ internal byte[] Payload() => Encoding.UTF8.GetBytes(CreateNodeHandoffReceipt.Canonical("create-node-recovery-lookup-v1", Algorithm, KeyId, Audience, BindingDigest, IssuedAt.ToUniversalTime().Ticks, ExpiresAt.ToUniversalTime().Ticks)); }
public sealed class CreateNodeRecoveryLookupSigner(string keyId, ECDsa key)
{
    private readonly ECDsa key = CreateNodeHandoffReceiptSigner.RequireP256(key); public string KeyId { get; } = keyId;
    public CreateNodeRecoveryLookupAuthority Sign(CreateNodeReceiptBinding binding, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    { if (expiresAt <= issuedAt || expiresAt - issuedAt > TimeSpan.FromDays(7)) throw new ArgumentOutOfRangeException(nameof(expiresAt)); var unsigned = new CreateNodeRecoveryLookupAuthority(CreateNodeHandoffReceiptSigner.Algorithm, KeyId, "create-node-provider-lookup", binding.Digest, issuedAt, expiresAt, string.Empty); return unsigned with { Signature = Convert.ToBase64String(key.SignData(unsigned.Payload(), HashAlgorithmName.SHA256)) }; }
}
public static class CreateNodeRecoveryLookupVerifier
{
    public static bool Verify(CreateNodeRecoveryLookupAuthority authority, ICreateNodeRecoveryLookupKeyResolver keys, CreateNodeReceiptBinding binding, DateTimeOffset now)
    { try { if (authority.Algorithm != CreateNodeHandoffReceiptSigner.Algorithm || authority.Audience != "create-node-provider-lookup" || authority.BindingDigest != binding.Digest || now < authority.IssuedAt || now >= authority.ExpiresAt || authority.ExpiresAt - authority.IssuedAt > TimeSpan.FromDays(7) || !keys.TryResolve(authority.KeyId, authority.Algorithm, out var bytes)) return false; using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(bytes, out _); CreateNodeHandoffReceiptSigner.RequireP256(key); return key.VerifyData(authority.Payload(), Convert.FromBase64String(authority.Signature), HashAlgorithmName.SHA256); } catch (CryptographicException) { return false; } catch (FormatException) { return false; } catch (ArgumentException) { return false; } }
}

public static class CreateNodeHandoffReceiptVerifier
{
    public static bool Verify(CreateNodeHandoffReceipt receipt, ICreateNodeReceiptKeyResolver resolver,
        CreateNodeReceiptBinding expected, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(receipt); ArgumentNullException.ThrowIfNull(resolver);
        try
        {
            CreateNodeHandoffReceiptSigner.Validate(receipt.Binding, receipt.IssuedAt, receipt.ExpiresAt);
            if (receipt.Algorithm != CreateNodeHandoffReceiptSigner.Algorithm || now < receipt.IssuedAt || now >= receipt.ExpiresAt ||
                receipt.Binding != expected || !resolver.TryResolve(receipt.KeyId, receipt.Algorithm, out var publicKey)) return false;
            using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(publicKey, out _); CreateNodeHandoffReceiptSigner.RequireP256(key);
            return key.VerifyData(receipt.Payload(), Convert.FromBase64String(receipt.Signature), HashAlgorithmName.SHA256);
        }
        catch (CryptographicException) { return false; }
        catch (FormatException) { return false; }
        catch (ArgumentException) { return false; }
    }
}

public sealed record CreateNodeTenantAuthorizationProof(string Algorithm, string KeyId, string TenantId, string OperationId,
    string Action, string AuthorizationDigest, DateTimeOffset ExpiresAt, string Signature)
{
    internal byte[] Payload() => Encoding.UTF8.GetBytes(CreateNodeHandoffReceipt.Canonical("create-node-tenant-proof-v1", Algorithm, KeyId, TenantId, OperationId, Action, AuthorizationDigest, ExpiresAt.ToUniversalTime().Ticks));
}
public sealed class CreateNodeTenantAuthorizationSigner(string keyId, ECDsa key)
{
    private readonly ECDsa key = CreateNodeHandoffReceiptSigner.RequireP256(key); public string KeyId { get; } = string.IsNullOrWhiteSpace(keyId) ? throw new ArgumentException("Key ID required.", nameof(keyId)) : keyId;
    public CreateNodeTenantAuthorizationProof Sign(string tenant, string operation, string digest, DateTimeOffset expiry)
    { var unsigned = new CreateNodeTenantAuthorizationProof(CreateNodeHandoffReceiptSigner.Algorithm, KeyId, tenant, operation, "CreateNode", digest, expiry, string.Empty); return unsigned with { Signature = Convert.ToBase64String(key.SignData(unsigned.Payload(), HashAlgorithmName.SHA256)) }; }
}
public static class CreateNodeTenantAuthorizationVerifier
{
    public static bool Verify(CreateNodeTenantAuthorizationProof proof, ICreateNodeTenantAuthorityKeyResolver keys, string operation, string digest, DateTimeOffset now, out string tenant)
    { tenant = string.Empty; try { if (proof.Algorithm != CreateNodeHandoffReceiptSigner.Algorithm || proof.Action != "CreateNode" || proof.OperationId != operation || proof.AuthorizationDigest != digest || now >= proof.ExpiresAt || string.IsNullOrWhiteSpace(proof.TenantId) || !keys.TryResolve(proof.KeyId, proof.Algorithm, out var bytes)) return false; using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(bytes, out _); CreateNodeHandoffReceiptSigner.RequireP256(key); if (!key.VerifyData(proof.Payload(), Convert.FromBase64String(proof.Signature), HashAlgorithmName.SHA256)) return false; tenant = proof.TenantId; return true; } catch (CryptographicException) { return false; } catch (FormatException) { return false; } catch (ArgumentException) { return false; } }
}
