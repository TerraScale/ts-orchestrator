using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane;

/// <summary>
/// The command-identity key files behind the placement reconciler's CreateNode coordination: one
/// independently revocable PEM per trust domain (receipt, tenant authority, provider attestation,
/// recovery lookup, invocation capability). The pattern is the CI role identity composition: the
/// paths are resolved once at startup, and a composition that shares material between two
/// domains fails closed instead of re-coupling their trust roots.
/// </summary>
public sealed class TerraBaseReconcilerKeyConfiguration
{
    internal const string ReceiptKeyFileVariable = "TS_ORCH_TERRABASE_CREATE_NODE_RECEIPT_KEY_FILE";
    internal const string TenantKeyFileVariable = "TS_ORCH_TERRABASE_CREATE_NODE_TENANT_KEY_FILE";
    internal const string ProviderKeyFileVariable = "TS_ORCH_TERRABASE_CREATE_NODE_PROVIDER_KEY_FILE";
    internal const string RecoveryKeyFileVariable = "TS_ORCH_TERRABASE_CREATE_NODE_RECOVERY_KEY_FILE";
    internal const string InvocationKeyFileVariable = "TS_ORCH_TERRABASE_CREATE_NODE_INVOCATION_KEY_FILE";

    private TerraBaseReconcilerKeyConfiguration(
        string receiptKeyFile, string tenantKeyFile, string providerKeyFile,
        string recoveryKeyFile, string invocationKeyFile)
    {
        ReceiptKeyFile = receiptKeyFile;
        TenantKeyFile = tenantKeyFile;
        ProviderKeyFile = providerKeyFile;
        RecoveryKeyFile = recoveryKeyFile;
        InvocationKeyFile = invocationKeyFile;
    }

    public string ReceiptKeyFile { get; }
    public string TenantKeyFile { get; }
    public string ProviderKeyFile { get; }
    public string RecoveryKeyFile { get; }
    public string InvocationKeyFile { get; }

    /// <summary>Resolves the five key files from the environment; null when none is configured.</summary>
    public static TerraBaseReconcilerKeyConfiguration? Resolve(Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        var receipt = KeyFile(environment(ReceiptKeyFileVariable), ReceiptKeyFileVariable);
        var tenant = KeyFile(environment(TenantKeyFileVariable), TenantKeyFileVariable);
        var provider = KeyFile(environment(ProviderKeyFileVariable), ProviderKeyFileVariable);
        var recovery = KeyFile(environment(RecoveryKeyFileVariable), RecoveryKeyFileVariable);
        var invocation = KeyFile(environment(InvocationKeyFileVariable), InvocationKeyFileVariable);
        var configured = new[] { receipt, tenant, provider, recovery, invocation };
        if (configured.All(static value => value is null))
            return null;
        // A partial configuration silently re-couples one domain to another domain's key or to an
        // absent trust root: the reconciler composes all five domains or none.
        if (configured.Any(static value => value is null) ||
            configured.Distinct(StringComparer.Ordinal).Count() != configured.Length)
            throw new ArgumentException(
                "The TerraBase reconciler requires one distinct private key file per CreateNode trust domain " +
                $"({ReceiptKeyFileVariable}, {TenantKeyFileVariable}, {ProviderKeyFileVariable}, " +
                $"{RecoveryKeyFileVariable}, {InvocationKeyFileVariable}).");
        return new(receipt!, tenant!, provider!, recovery!, invocation!);
    }

    private static string? KeyFile(string? value, string variable) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : System.IO.Path.GetFullPath(value.Trim());
}

/// <summary>
/// The opened CreateNode key material for one reconciler process lifetime: the signers the
/// coordinator mints with and the resolvers every verifier in the chain verifies against, each
/// domain backed by its own configured key file.
/// </summary>
internal sealed class TerraBaseReconcilerKeyService : IDisposable
{
    private readonly List<IDisposable> owned;

    private TerraBaseReconcilerKeyService(
        List<IDisposable> owned,
        CreateNodeHandoffReceiptSigner receiptSigner,
        CreateNodeReceiptKeyRing receiptKeys,
        CreateNodeTenantAuthorizationSigner tenantSigner,
        CreateNodeTenantAuthorityKeyRing tenantKeys,
        CreateNodeProviderProofSigner proofSigner,
        CreateNodeProviderAttestationKeyRing providerKeys,
        CreateNodeRecoveryLookupSigner recoverySigner,
        CreateNodeRecoveryLookupKeyRing recoveryKeys,
        CreateNodeAuthoritativeInvocationCapabilitySigner invocationCapabilitySigner,
        CreateNodeAuthoritativeInvocationCapabilityKeyRing invocationCapabilityKeys)
    {
        this.owned = owned;
        ReceiptSigner = receiptSigner;
        ReceiptKeys = receiptKeys;
        TenantSigner = tenantSigner;
        TenantKeys = tenantKeys;
        ProofSigner = proofSigner;
        ProviderKeys = providerKeys;
        RecoverySigner = recoverySigner;
        RecoveryKeys = recoveryKeys;
        InvocationCapabilitySigner = invocationCapabilitySigner;
        InvocationCapabilityKeys = invocationCapabilityKeys;
    }

    internal CreateNodeHandoffReceiptSigner ReceiptSigner { get; }
    internal ICreateNodeReceiptKeyResolver ReceiptKeys { get; }
    internal CreateNodeTenantAuthorizationSigner TenantSigner { get; }
    internal ICreateNodeTenantAuthorityKeyResolver TenantKeys { get; }
    internal CreateNodeProviderProofSigner ProofSigner { get; }
    internal ICreateNodeProviderAttestationKeyResolver ProviderKeys { get; }
    internal CreateNodeRecoveryLookupSigner RecoverySigner { get; }
    internal ICreateNodeRecoveryLookupKeyResolver RecoveryKeys { get; }
    internal CreateNodeAuthoritativeInvocationCapabilitySigner InvocationCapabilitySigner { get; }
    internal ICreateNodeAuthoritativeInvocationCapabilityKeyResolver InvocationCapabilityKeys { get; }

    internal static TerraBaseReconcilerKeyService Open(TerraBaseReconcilerKeyConfiguration? configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var owned = new List<IDisposable>();
        try
        {
            var receipt = Domain(owned, configuration.ReceiptKeyFile);
            var tenant = Domain(owned, configuration.TenantKeyFile);
            var provider = Domain(owned, configuration.ProviderKeyFile);
            var recovery = Domain(owned, configuration.RecoveryKeyFile);
            var invocation = Domain(owned, configuration.InvocationKeyFile);
            var receiptKeys = new CreateNodeReceiptKeyRing(Ring(receipt.PublicKey));
            var tenantKeys = new CreateNodeTenantAuthorityKeyRing(Ring(tenant.PublicKey));
            var providerKeys = new CreateNodeProviderAttestationKeyRing(Ring(provider.PublicKey));
            var recoveryKeys = new CreateNodeRecoveryLookupKeyRing(Ring(recovery.PublicKey));
            var invocationKeys = new CreateNodeAuthoritativeInvocationCapabilityKeyRing(Ring(invocation.PublicKey));
            CreateNodeKeyDomainValidator.EnsureDistinct(
                receiptKeys, tenantKeys, providerKeys, recoveryKeys, invocationKeys);
            return new(
                owned,
                new CreateNodeHandoffReceiptSigner(receipt.KeyId, receipt.Key),
                receiptKeys,
                new CreateNodeTenantAuthorizationSigner(tenant.KeyId, tenant.Key),
                tenantKeys,
                new CreateNodeProviderProofSigner(provider.KeyId, provider.Key),
                providerKeys,
                new CreateNodeRecoveryLookupSigner(recovery.KeyId, recovery.Key),
                recoveryKeys,
                new CreateNodeAuthoritativeInvocationCapabilitySigner(invocation.KeyId, invocation.Key),
                invocationKeys);
        }
        catch
        {
            foreach (var disposable in owned) disposable.Dispose();
            throw;
        }
    }

    private static Dictionary<string, byte[]> Ring(byte[] publicKey) =>
        new(StringComparer.Ordinal) { [Convert.ToHexStringLower(SHA256.HashData(publicKey))] = publicKey };

    /// <summary>
    /// Loads one owner-private P-256 PEM and derives its key id — the stable SPKI digest, so a
    /// receipt names the exact key that signed it. Names the credential's path, never its contents.
    /// </summary>
    private static (string KeyId, ECDsa Key, byte[] PublicKey) Domain(List<IDisposable> owned, string path)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("TerraBase reconciler credentials require Linux file permissions.");
        var file = new FileInfo(path);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > 32 * 1024)
            throw new ArgumentException($"The CreateNode key file must be a bounded regular file: {path}.");
        var mode = File.GetUnixFileMode(path);
        if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
            throw new ArgumentException($"The CreateNode key file must be private to the current user: {path}.");
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(File.ReadAllText(path));
            var parameters = key.ExportParameters(true);
            if (key.KeySize != 256 || parameters.D is not { Length: > 0 } ||
                key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
                throw new CryptographicException("The CreateNode key is not a P-256 private key.");
            CryptographicOperations.ZeroMemory(parameters.D!);
            var publicKey = key.ExportSubjectPublicKeyInfo();
            owned.Add(key);
            return (Convert.ToHexStringLower(SHA256.HashData(publicKey)), key, publicKey);
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException or FormatException)
        {
            key.Dispose();
            throw new ArgumentException($"The CreateNode key file is not a P-256 private key: {path}.", exception);
        }
    }

    public void Dispose()
    {
        foreach (var disposable in owned) disposable.Dispose();
        owned.Clear();
    }
}
