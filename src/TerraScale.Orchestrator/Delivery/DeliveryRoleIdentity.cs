using System.Security.Cryptography;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>
/// The independently revocable signing roles behind the repository-CI and direct-delivery trust
/// boundary. Each role is provisioned with its own key material, so one compromised or rotated
/// role never widens into another role's trust root.
/// </summary>
public enum DeliverySigningRole
{
    /// <summary>
    /// Signs repository CI job dispatch envelopes. Runners verify them through the rotating
    /// command trust set; the controller side of this role is signing-only.
    /// </summary>
    CiJob = 1,
    /// <summary>
    /// Signs artifact attestations and the durable delivery-evidence records that production
    /// direct-delivery provenance verifies. Production delivery trusts exactly this role.
    /// </summary>
    CiArtifact = 2,
    /// <summary>
    /// The native runtime-observation role: the CI runner signs architecture-specific execution
    /// receipts and the controller verifies them. The controller side of this role is
    /// verification-only; the signing key lives with the runner process.
    /// </summary>
    CiRuntime = 3,
    /// <summary>
    /// Verification-only slice of the CI artifact role: every composition that verifies durable
    /// artifact evidence (regional and global direct delivery) requires the role's PUBLIC trust
    /// keys. Only a composition that signs CI evidence (a CI signer controller) additionally
    /// carries the private key through <see cref="CiArtifact"/>; verifier-only processes —
    /// including member hosts — must never hold signing material.
    /// </summary>
    CiArtifactTrust = 4,
}

/// <summary>
/// Composition-level sources for per-role CI/delivery signing identities. Follows the command
/// identity pattern: bounded file references resolved once at startup, never per request. A
/// role this composition actually uses must have its own configured sources:
/// <see cref="DeliveryRoleIdentityRuntime.Open"/> fails closed when it does not (one shared
/// identity across roles is exactly the compromise-amplification this configuration exists to
/// remove).
/// </summary>
public sealed class DeliveryRoleIdentityConfiguration
{
    internal const string CiJobSigningKeyFileVariable = "TS_ORCH_CI_JOB_SIGNING_KEY_FILE";
    internal const string CiArtifactSigningKeyFileVariable = "TS_ORCH_CI_ARTIFACT_SIGNING_KEY_FILE";
    internal const string CiArtifactTrustKeyFilesVariable = "TS_ORCH_CI_ARTIFACT_TRUST_KEY_FILES";
    internal const string CiRuntimeTrustKeyFilesVariable = "TS_ORCH_CI_RUNTIME_TRUST_KEY_FILES";

    private DeliveryRoleIdentityConfiguration(
        string? ciJobSigningKeyFile,
        string? ciArtifactSigningKeyFile,
        string[] ciArtifactTrustKeyFiles,
        string[] ciRuntimeTrustKeyFiles)
    {
        CiJobSigningKeyFile = ciJobSigningKeyFile;
        CiArtifactSigningKeyFile = ciArtifactSigningKeyFile;
        CiArtifactTrustKeyFiles = Array.AsReadOnly(ciArtifactTrustKeyFiles);
        CiRuntimeTrustKeyFiles = Array.AsReadOnly(ciRuntimeTrustKeyFiles);
    }

    public string? CiJobSigningKeyFile { get; }
    public string? CiArtifactSigningKeyFile { get; }
    public IReadOnlyList<string> CiArtifactTrustKeyFiles { get; }
    public IReadOnlyList<string> CiRuntimeTrustKeyFiles { get; }

    internal bool IsEmpty =>
        CiJobSigningKeyFile is null && CiArtifactSigningKeyFile is null &&
        CiArtifactTrustKeyFiles.Count == 0 && CiRuntimeTrustKeyFiles.Count == 0;

    /// <summary>Resolves the per-role key references from the environment; null when none is configured.</summary>
    public static DeliveryRoleIdentityConfiguration? Resolve(Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        var ciJob = SigningPath(environment(CiJobSigningKeyFileVariable), CiJobSigningKeyFileVariable);
        var ciArtifact = SigningPath(environment(CiArtifactSigningKeyFileVariable), CiArtifactSigningKeyFileVariable);
        var artifactTrust = TrustPaths(
            environment(CiArtifactTrustKeyFilesVariable), CiArtifactTrustKeyFilesVariable);
        var runtimeTrust = TrustPaths(
            environment(CiRuntimeTrustKeyFilesVariable), CiRuntimeTrustKeyFilesVariable);
        if (ciJob is null && ciArtifact is null && artifactTrust.Length == 0 && runtimeTrust.Length == 0)
            return null;
        // Sharing one key file between two roles couples their compromise and rotation: reject
        // the composition instead of silently re-creating the single shared identity.
        var configured = new List<string>();
        if (ciJob is not null) configured.Add(ciJob);
        if (ciArtifact is not null) configured.Add(ciArtifact);
        configured.AddRange(artifactTrust);
        configured.AddRange(runtimeTrust);
        if (configured.Distinct(StringComparer.Ordinal).Count() != configured.Count)
            throw new ArgumentException(
                "CI signing roles must not share key files: configure distinct key material per role " +
                $"({CiJobSigningKeyFileVariable}, {CiArtifactSigningKeyFileVariable}, " +
                $"{CiArtifactTrustKeyFilesVariable}, {CiRuntimeTrustKeyFilesVariable}).");
        return new(ciJob, ciArtifact, artifactTrust, runtimeTrust);
    }

    private static string? SigningPath(string? value, string variable)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var path = Path.GetFullPath(value.Trim());
        if (path.Length == 0)
            throw new ArgumentException($"{variable} must be one complete private key path.", variable);
        return path;
    }

    private static string[] TrustPaths(string? value, string variable)
    {
        if (string.IsNullOrWhiteSpace(value)) return [];
        var values = value.Split(Path.PathSeparator, StringSplitOptions.TrimEntries);
        if (values.Length is < 1 or > 4 || values.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException($"{variable} must contain one to four complete public key paths.", variable);
        var paths = values.Select(Path.GetFullPath).ToArray();
        if (paths.Distinct(StringComparer.Ordinal).Count() != paths.Length)
            throw new ArgumentException($"{variable} must not contain duplicate paths.", variable);
        return paths;
    }
}

/// <summary>
/// The opened per-role signers and verifiers for one process lifetime. Every composed role must
/// be configured; an uncomposed slot falls back to the shared command identity only until
/// composition names it, and the fallback instances stay owned by the caller's command identity
/// runtime and are never disposed here.
/// </summary>
internal sealed class DeliveryRoleIdentityRuntime : IDisposable
{
    private readonly List<IDisposable> owned;

    private DeliveryRoleIdentityRuntime(
        List<IDisposable> owned,
        EcdsaCommandSigner? ciJob,
        EcdsaCommandSigner? ciArtifact,
        EcdsaCommandSignatureVerifier? ciArtifactSignatures,
        EcdsaCommandSignatureVerifier? ciRuntimeSignatures)
    {
        this.owned = owned;
        CiJob = ciJob;
        CiArtifact = ciArtifact;
        CiArtifactSignatures = ciArtifactSignatures;
        CiRuntimeSignatures = ciRuntimeSignatures;
    }

    internal EcdsaCommandSigner? CiJob { get; }
    internal EcdsaCommandSigner? CiArtifact { get; }
    internal EcdsaCommandSignatureVerifier? CiArtifactSignatures { get; }
    internal EcdsaCommandSignatureVerifier? CiRuntimeSignatures { get; }

    internal static DeliveryRoleIdentityRuntime Open(
        DeliveryRoleIdentityConfiguration? configuration,
        CommandIdentityRuntime? fallback,
        IReadOnlyCollection<DeliverySigningRole>? requiredRoles = null)
    {
        requiredRoles ??= [];
        var owned = new List<IDisposable>();
        EcdsaCommandSigner? ciJob = null;
        EcdsaCommandSigner? ciArtifact = null;
        EcdsaCommandSignatureVerifier? ciArtifactSignatures = null;
        EcdsaCommandSignatureVerifier? ciRuntimeSignatures = null;
        try
        {
            if (configuration?.CiJobSigningKeyFile is { } jobPath)
                Track(owned, ref ciJob, EcdsaCommandSigner.LoadPrivatePem(jobPath));
            if (configuration?.CiArtifactSigningKeyFile is { } artifactPath)
                Track(owned, ref ciArtifact, EcdsaCommandSigner.LoadPrivatePem(artifactPath));
            if (configuration is { CiArtifactTrustKeyFiles.Count: > 0 })
                Track(owned, ref ciArtifactSignatures,
                    EcdsaCommandSignatureVerifier.LoadPublicPem(configuration.CiArtifactTrustKeyFiles));
            if (configuration is { CiRuntimeTrustKeyFiles.Count: > 0 })
                Track(owned, ref ciRuntimeSignatures,
                    EcdsaCommandSignatureVerifier.LoadPublicPem(configuration.CiRuntimeTrustKeyFiles));
            // Per-role key independence is unconditional: every role this composition
            // composes must carry its own configured key material, never a shared fallback.
            foreach (var role in requiredRoles)
                RequireConfigured(role, configuration);
            EnsureDistinctMaterial(configuration, fallback);
            return new DeliveryRoleIdentityRuntime(
                owned,
                ciJob ?? fallback?.Signer,
                ciArtifact ?? fallback?.Signer,
                ciArtifactSignatures ?? fallback?.Verifier,
                ciRuntimeSignatures ?? fallback?.Verifier);
        }
        catch
        {
            foreach (var disposable in owned) disposable.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        foreach (var disposable in owned) disposable.Dispose();
        owned.Clear();
    }

    private static void Track<T>(List<IDisposable> owned, ref T? slot, T value) where T : class, IDisposable
    {
        slot = value;
        owned.Add(value);
    }

    /// <summary>
    /// Composition refuses the shared-identity fallback for a role it actually composes: the
    /// fallback re-couples every role's trust root, which is the exact shape this configuration
    /// removes.
    /// </summary>
    private static void RequireConfigured(
        DeliverySigningRole role,
        DeliveryRoleIdentityConfiguration? configuration)
    {
        switch (role)
        {
            case DeliverySigningRole.CiJob:
                if (configuration?.CiJobSigningKeyFile is null)
                    throw new InvalidOperationException(
                        $"This composition requires {DeliveryRoleIdentityConfiguration.CiJobSigningKeyFileVariable} " +
                        "for the CI job signing role; the shared command identity is not admitted for it.");
                break;
            case DeliverySigningRole.CiArtifact:
                if (configuration?.CiArtifactSigningKeyFile is null ||
                    configuration.CiArtifactTrustKeyFiles.Count == 0)
                    throw new InvalidOperationException(
                        $"This composition requires {DeliveryRoleIdentityConfiguration.CiArtifactSigningKeyFileVariable} " +
                        $"and {DeliveryRoleIdentityConfiguration.CiArtifactTrustKeyFilesVariable} for the CI " +
                        "artifact attestation and delivery-evidence role; the shared command identity is not " +
                        "admitted for it.");
                break;
            case DeliverySigningRole.CiRuntime:
                if (configuration?.CiRuntimeTrustKeyFiles.Count is not > 0)
                    throw new InvalidOperationException(
                        $"This composition requires {DeliveryRoleIdentityConfiguration.CiRuntimeTrustKeyFilesVariable} " +
                        "for the native runtime-observation verification role; the shared command identity is " +
                        "not admitted for it.");
                break;
            case DeliverySigningRole.CiArtifactTrust:
                if (configuration?.CiArtifactTrustKeyFiles.Count is not > 0)
                    throw new InvalidOperationException(
                        $"This composition requires {DeliveryRoleIdentityConfiguration.CiArtifactTrustKeyFilesVariable} " +
                        "for the CI artifact evidence verification role; the shared command identity is not " +
                        "admitted for it.");
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(role));
        }
    }

    /// <summary>
    /// Material-level separation: no configured role may reuse another role's key material, and
    /// no configured role may reuse the base command identity's material — otherwise rotating or
    /// compromising one role would still move every other trust root.
    /// </summary>
    private static void EnsureDistinctMaterial(
        DeliveryRoleIdentityConfiguration? configuration,
        CommandIdentityRuntime? fallback)
    {
        if (configuration is null || configuration.IsEmpty) return;
        var byMaterial = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        void Add(string owner, string materialId)
        {
            if (!byMaterial.TryGetValue(materialId, out var owners)) byMaterial[materialId] = owners = [];
            owners.Add(owner);
        }

        const string SharedCommandIdentity = "the shared command identity";
        if (configuration.CiJobSigningKeyFile is { } jobPath)
            Add(nameof(DeliverySigningRole.CiJob), EcdsaCommandSigner.PublicKeyIdOf(jobPath));
        if (configuration.CiArtifactSigningKeyFile is { } artifactPath)
            Add(nameof(DeliverySigningRole.CiArtifact), EcdsaCommandSigner.PublicKeyIdOf(artifactPath));
        foreach (var path in configuration.CiArtifactTrustKeyFiles)
            Add(nameof(DeliverySigningRole.CiArtifact), EcdsaCommandSigner.PublicKeyIdOf(path));
        foreach (var path in configuration.CiRuntimeTrustKeyFiles)
            Add(nameof(DeliverySigningRole.CiRuntime), EcdsaCommandSigner.PublicKeyIdOf(path));
        if (fallback?.Signer is not null)
            Add(SharedCommandIdentity, fallback.Signer.PublicKeyId);
        // Aligning a role's own signing key with its own trust set is the intended self-trust
        // shape (the controller attests and re-verifies with one artifact-role key); a violation
        // is the same material serving two DIFFERENT owners.
        foreach (var shared in byMaterial.Where(static pair =>
                     pair.Value.Distinct(StringComparer.Ordinal).Count() > 1))
            throw new InvalidOperationException(
                $"CI signing roles must use distinct key material: the key {shared.Key} is configured for " +
                $"{string.Join(" and ", shared.Value.Distinct(StringComparer.Ordinal))}. Mint a separate key per " +
                "role so each trust root stays independently revocable.");
    }
}

