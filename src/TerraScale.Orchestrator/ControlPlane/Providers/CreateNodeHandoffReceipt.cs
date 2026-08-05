using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

/// <summary>Signed proof that a single, named CreateNode request crossed the Pulumi-to-cell handoff boundary.</summary>
public sealed record CreateNodeHandoffReceipt(
    string KeyId,
    string OperationId,
    string TenantId,
    string NodeRequestId,
    string CreateKey,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string Signature)
{
    internal byte[] SigningPayload() => Encoding.UTF8.GetBytes(Canonical(
        "terrascale-create-node-handoff-v1", KeyId, OperationId, "CreateNode", TenantId,
        NodeRequestId, CreateKey, IssuedAt.ToUniversalTime().Ticks, ExpiresAt.ToUniversalTime().Ticks));

    internal static string Canonical(params object[] values) => string.Concat(values.Select(static value =>
    {
        var text = Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        return string.Concat(text.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), ":", text, ";");
    }));
}

public sealed class CreateNodeHandoffReceiptSigner
{
    private readonly ECDsa signingKey;

    public CreateNodeHandoffReceiptSigner(string keyId, ECDsa signingKey)
    {
        if (string.IsNullOrWhiteSpace(keyId)) throw new ArgumentException("A receipt key ID is required.", nameof(keyId));
        KeyId = keyId;
        this.signingKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
    }

    public string KeyId { get; }
    public byte[] ExportPublicKey() => signingKey.ExportSubjectPublicKeyInfo();

    public CreateNodeHandoffReceipt Sign(
        string operationId, string tenantId, string nodeRequestId, string createKey,
        DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        ValidateClaims(operationId, tenantId, nodeRequestId, createKey, issuedAt, expiresAt);
        var unsigned = new CreateNodeHandoffReceipt(KeyId, operationId, tenantId, nodeRequestId, createKey,
            issuedAt, expiresAt, string.Empty);
        return unsigned with { Signature = Convert.ToBase64String(signingKey.SignData(unsigned.SigningPayload(), HashAlgorithmName.SHA256)) };
    }

    internal static void ValidateClaims(string operationId, string tenantId, string nodeRequestId, string createKey,
        DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        if (string.IsNullOrWhiteSpace(operationId) || string.IsNullOrWhiteSpace(tenantId) ||
            string.IsNullOrWhiteSpace(nodeRequestId) || string.IsNullOrWhiteSpace(createKey) ||
            issuedAt == default || expiresAt <= issuedAt)
            throw new ArgumentException("Receipt claims must be complete and have a positive lifetime.");
    }
}

public static class CreateNodeHandoffReceiptVerifier
{
    public static bool Verify(
        CreateNodeHandoffReceipt receipt, ReadOnlySpan<byte> publicKey,
        string operationId, string tenantId, string nodeRequestId, string createKey, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        try
        {
            CreateNodeHandoffReceiptSigner.ValidateClaims(receipt.OperationId, receipt.TenantId,
                receipt.NodeRequestId, receipt.CreateKey, receipt.IssuedAt, receipt.ExpiresAt);
            if (now < receipt.IssuedAt || now >= receipt.ExpiresAt ||
                !StringComparer.Ordinal.Equals(receipt.OperationId, operationId) ||
                !StringComparer.Ordinal.Equals(receipt.TenantId, tenantId) ||
                !StringComparer.Ordinal.Equals(receipt.NodeRequestId, nodeRequestId) ||
                !StringComparer.Ordinal.Equals(receipt.CreateKey, createKey))
                return false;

            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out _);
            return key.VerifyData(receipt.SigningPayload(), Convert.FromBase64String(receipt.Signature), HashAlgorithmName.SHA256);
        }
        catch (CryptographicException) { return false; }
        catch (FormatException) { return false; }
        catch (ArgumentException) { return false; }
    }
}
