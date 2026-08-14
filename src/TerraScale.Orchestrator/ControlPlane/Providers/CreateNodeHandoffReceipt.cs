using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Operations;

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
public interface ICreateNodePublicKeySource
{
    IReadOnlyDictionary<string, byte[]> ExportPublicKeys();
}

public class CreateNodeReceiptKeyRing : ICreateNodeReceiptKeyResolver, ICreateNodePublicKeySource
{
    private readonly FrozenDictionary<string, byte[]> keys;
    public CreateNodeReceiptKeyRing(IReadOnlyDictionary<string, byte[]> keys) => this.keys = keys.ToFrozenDictionary(
        static pair => pair.Key, static pair => pair.Value.ToArray(), StringComparer.Ordinal);
    public bool TryResolve(string keyId, string algorithm, out byte[] subjectPublicKeyInfo)
    {
        if (algorithm != CreateNodeHandoffReceiptSigner.Algorithm || !keys.TryGetValue(keyId, out var key))
        { subjectPublicKeyInfo = []; return false; }
        subjectPublicKeyInfo = key.ToArray(); return true;
    }
    public IReadOnlyDictionary<string, byte[]> ExportPublicKeys() => keys.ToDictionary(static pair => pair.Key, static pair => pair.Value.ToArray(), StringComparer.Ordinal);
}
public interface ICreateNodeTenantAuthorityKeyResolver : ICreateNodeReceiptKeyResolver { }
public interface ICreateNodeProviderAttestationKeyResolver : ICreateNodeReceiptKeyResolver { }
public interface ICreateNodeRecoveryLookupKeyResolver : ICreateNodeReceiptKeyResolver { }
public sealed class CreateNodeTenantAuthorityKeyRing(IReadOnlyDictionary<string, byte[]> keys) : CreateNodeReceiptKeyRing(keys), ICreateNodeTenantAuthorityKeyResolver { }
public sealed class CreateNodeProviderAttestationKeyRing(IReadOnlyDictionary<string, byte[]> keys) : CreateNodeReceiptKeyRing(keys), ICreateNodeProviderAttestationKeyResolver { }
public sealed class CreateNodeRecoveryLookupKeyRing(IReadOnlyDictionary<string, byte[]> keys) : CreateNodeReceiptKeyRing(keys), ICreateNodeRecoveryLookupKeyResolver { }
public interface ICreateNodeAuthoritativeInvocationCapabilityKeyResolver : ICreateNodeReceiptKeyResolver { }
public sealed class CreateNodeAuthoritativeInvocationCapabilityKeyRing(IReadOnlyDictionary<string, byte[]> keys) : CreateNodeReceiptKeyRing(keys), ICreateNodeAuthoritativeInvocationCapabilityKeyResolver { }

public static class CreateNodeKeyDomainValidator
{
    public static void EnsureDistinct(params ICreateNodeReceiptKeyResolver[] domains)
    {
        ArgumentNullException.ThrowIfNull(domains);
        for (var left = 0; left < domains.Length; left++)
        {
            if (domains[left] is not ICreateNodePublicKeySource leftKeys) throw new ArgumentException("CreateNode key domains must expose their configured public keys.", nameof(domains));
            foreach (var right in domains.Skip(left + 1))
            {
                if (right is not ICreateNodePublicKeySource rightKeys) throw new ArgumentException("CreateNode key domains must expose their configured public keys.", nameof(domains));
                foreach (var first in leftKeys.ExportPublicKeys()) foreach (var second in rightKeys.ExportPublicKeys())
                    if (first.Key == second.Key || CryptographicOperations.FixedTimeEquals(first.Value, second.Value))
                        throw new ArgumentException("CreateNode trust domains cannot share a key ID or public key material.", nameof(domains));
            }
        }
    }
}

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
    public static bool Verify(CreateNodeRecoveryLookupAuthority? authority, ICreateNodeRecoveryLookupKeyResolver keys, CreateNodeReceiptBinding binding, DateTimeOffset now)
    { try { if (authority is null || binding is null || authority.Algorithm != CreateNodeHandoffReceiptSigner.Algorithm || authority.Audience != "create-node-provider-lookup" || authority.BindingDigest != binding.Digest || now < authority.IssuedAt || now >= authority.ExpiresAt || authority.ExpiresAt - authority.IssuedAt > TimeSpan.FromDays(7) || !keys.TryResolve(authority.KeyId, authority.Algorithm, out var bytes)) return false; using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(bytes, out _); CreateNodeHandoffReceiptSigner.RequireP256(key); return key.VerifyData(authority.Payload(), Convert.FromBase64String(authority.Signature), HashAlgorithmName.SHA256); } catch (CryptographicException) { return false; } catch (FormatException) { return false; } catch (ArgumentException) { return false; } }
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

public sealed record CreateNodeTenantAuthorizationProof(string Algorithm, string KeyId, string Audience, string TenantId, string OperationId,
    string Action, string AuthorizationDigest, DateTimeOffset ExpiresAt, string Signature)
{
    internal byte[] Payload() => Encoding.UTF8.GetBytes(CreateNodeHandoffReceipt.Canonical("create-node-tenant-proof-v2", Algorithm, KeyId, Audience, TenantId, OperationId, Action, AuthorizationDigest, ExpiresAt.ToUniversalTime().Ticks));
}
public sealed class CreateNodeTenantAuthorizationSigner(string keyId, ECDsa key)
{
    private readonly ECDsa key = CreateNodeHandoffReceiptSigner.RequireP256(key); public string KeyId { get; } = string.IsNullOrWhiteSpace(keyId) ? throw new ArgumentException("Key ID required.", nameof(keyId)) : keyId;
    public CreateNodeTenantAuthorizationProof Sign(string tenant, string operation, string digest, DateTimeOffset expiry)
    { var unsigned = new CreateNodeTenantAuthorizationProof(CreateNodeHandoffReceiptSigner.Algorithm, KeyId, "create-node-tenant-authorization", tenant, operation, "CreateNode", digest, expiry, string.Empty); return unsigned with { Signature = Convert.ToBase64String(key.SignData(unsigned.Payload(), HashAlgorithmName.SHA256)) }; }
}
public static class CreateNodeTenantAuthorizationVerifier
{
    public static bool Verify(CreateNodeTenantAuthorizationProof proof, ICreateNodeTenantAuthorityKeyResolver keys, string operation, string digest, DateTimeOffset now, out string tenant)
    { tenant = string.Empty; try { if (proof.Algorithm != CreateNodeHandoffReceiptSigner.Algorithm || proof.Audience != "create-node-tenant-authorization" || proof.Action != "CreateNode" || proof.OperationId != operation || proof.AuthorizationDigest != digest || now >= proof.ExpiresAt || string.IsNullOrWhiteSpace(proof.TenantId) || !keys.TryResolve(proof.KeyId, proof.Algorithm, out var bytes)) return false; using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(bytes, out _); CreateNodeHandoffReceiptSigner.RequireP256(key); if (!key.VerifyData(proof.Payload(), Convert.FromBase64String(proof.Signature), HashAlgorithmName.SHA256)) return false; tenant = proof.TenantId; return true; } catch (CryptographicException) { return false; } catch (FormatException) { return false; } catch (ArgumentException) { return false; } }
}

public sealed record CreateNodeAuthoritativeInvocationCapability(string Algorithm, string KeyId, string Audience, string OperationId, string BindingDigest, long JournalVersion, string LeaseOwner, string LeaseToken, string Nonce, DateTimeOffset LeaseExpiresAt, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, string Signature)
{ internal byte[] Payload() => Encoding.UTF8.GetBytes(CreateNodeHandoffReceipt.Canonical("create-node-authoritative-invocation-v3", Algorithm, KeyId, Audience, OperationId, BindingDigest, JournalVersion, LeaseOwner, LeaseToken, Nonce, LeaseExpiresAt.ToUniversalTime().Ticks, IssuedAt.ToUniversalTime().Ticks, ExpiresAt.ToUniversalTime().Ticks)); }
internal sealed class CreateNodeAuthoritativeInvocationCapabilitySigner(string keyId, ECDsa key)
{
    private readonly ECDsa key = CreateNodeHandoffReceiptSigner.RequireP256(key); public string KeyId { get; } = string.IsNullOrWhiteSpace(keyId) ? throw new ArgumentException("Key ID required.", nameof(keyId)) : keyId;
    internal CreateNodeAuthoritativeInvocationCapability Sign(CreateNodeOperationJournalEntry checkpoint, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    { if (checkpoint.Stage != CreateNodeJournalStage.ProviderCallStarted || checkpoint.Version <= 0 || string.IsNullOrWhiteSpace(checkpoint.InvocationLeaseOwner) || string.IsNullOrWhiteSpace(checkpoint.InvocationLeaseToken) || string.IsNullOrWhiteSpace(checkpoint.InvocationCapabilityNonce) || checkpoint.InvocationLeaseExpiresAt is null || checkpoint.InvocationLeaseExpiresAt <= issuedAt || expiresAt < checkpoint.InvocationLeaseExpiresAt || expiresAt - issuedAt > TimeSpan.FromMinutes(10)) throw new ArgumentOutOfRangeException(nameof(checkpoint)); var unsigned = new CreateNodeAuthoritativeInvocationCapability(CreateNodeHandoffReceiptSigner.Algorithm, KeyId, "create-node-authoritative-invocation", checkpoint.Binding.OperationId, checkpoint.Binding.Digest, checkpoint.Version, checkpoint.InvocationLeaseOwner, checkpoint.InvocationLeaseToken, checkpoint.InvocationCapabilityNonce, checkpoint.InvocationLeaseExpiresAt.Value, issuedAt, expiresAt, string.Empty); return unsigned with { Signature = Convert.ToBase64String(key.SignData(unsigned.Payload(), HashAlgorithmName.SHA256)) }; }
}
public static class CreateNodeAuthoritativeInvocationCapabilityVerifier
{
    public static bool Verify(CreateNodeAuthoritativeInvocationCapability? capability, ICreateNodeAuthoritativeInvocationCapabilityKeyResolver keys, CreateNodeReceiptBinding binding, DateTimeOffset now)
    { try { if (capability is null || binding is null || capability.Algorithm != CreateNodeHandoffReceiptSigner.Algorithm || capability.Audience != "create-node-authoritative-invocation" || capability.OperationId != binding.OperationId || capability.BindingDigest != binding.Digest || capability.JournalVersion <= 0 || string.IsNullOrWhiteSpace(capability.LeaseOwner) || string.IsNullOrWhiteSpace(capability.LeaseToken) || string.IsNullOrWhiteSpace(capability.Nonce) || capability.LeaseExpiresAt <= capability.IssuedAt || now < capability.IssuedAt || now >= capability.LeaseExpiresAt || now >= capability.ExpiresAt || capability.ExpiresAt - capability.IssuedAt > TimeSpan.FromMinutes(10) || !keys.TryResolve(capability.KeyId, capability.Algorithm, out var bytes)) return false; using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(bytes, out _); CreateNodeHandoffReceiptSigner.RequireP256(key); return key.VerifyData(capability.Payload(), Convert.FromBase64String(capability.Signature), HashAlgorithmName.SHA256); } catch (CryptographicException) { return false; } catch (FormatException) { return false; } catch (ArgumentException) { return false; } }
}
