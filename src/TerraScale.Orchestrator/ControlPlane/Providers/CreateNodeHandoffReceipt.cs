using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

public sealed record CreateNodeReceiptBinding(
    string OperationId, string TenantId, string NodeRequestId, string IdempotencyKey, string CreateKey,
    string CellId, string CompartmentId, ulong Generation, ulong Epoch, string TemplateId,
    string PlacementId, string BootstrapEnvelopeDigest, long AuthorizationSequence, string AuthorizationDigest);

public sealed record CreateNodeHandoffReceipt(
    string Algorithm, string KeyId, CreateNodeReceiptBinding Binding,
    DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, string Signature)
{
    internal byte[] Payload() => Encoding.UTF8.GetBytes(Canonical("terrascale-create-node-handoff-v2", Algorithm, KeyId,
        Binding.OperationId, "CreateNode", Binding.TenantId, Binding.NodeRequestId, Binding.IdempotencyKey,
        Binding.CreateKey, Binding.CellId, Binding.CompartmentId, Binding.Generation, Binding.Epoch,
        Binding.TemplateId, Binding.PlacementId, Binding.BootstrapEnvelopeDigest, Binding.AuthorizationSequence,
        Binding.AuthorizationDigest, IssuedAt.ToUniversalTime().Ticks, ExpiresAt.ToUniversalTime().Ticks));

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

public sealed class CreateNodeReceiptKeyRing : ICreateNodeReceiptKeyResolver
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

public sealed class CreateNodeHandoffReceiptSigner
{
    public const string Algorithm = "ECDSA-P256-SHA256";
    private readonly ECDsa signingKey;
    public CreateNodeHandoffReceiptSigner(string keyId, ECDsa signingKey)
    { if (string.IsNullOrWhiteSpace(keyId)) throw new ArgumentException("A receipt key ID is required.", nameof(keyId)); KeyId = keyId; this.signingKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey)); }
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
            binding.AuthorizationDigest }.Any(string.IsNullOrWhiteSpace) || binding.Generation == 0 || binding.Epoch == 0 ||
            binding.AuthorizationSequence <= 0 || issuedAt == default || expiresAt <= issuedAt)
            throw new ArgumentException("Receipt binding must be complete and have a positive lifetime.");
    }
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
            using var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return key.VerifyData(receipt.Payload(), Convert.FromBase64String(receipt.Signature), HashAlgorithmName.SHA256);
        }
        catch (CryptographicException) { return false; }
        catch (FormatException) { return false; }
        catch (ArgumentException) { return false; }
    }
}
