using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using TsOrch.Oci;

namespace TsOrch.Agent;

public sealed record class ResolvedSecret(SecretRef Ref, long Version, string Value)
{
    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{nameof(ResolvedSecret)} {{ Vault = {Ref.Vault}, Name = {Ref.Name}, Version = {Version} }}");
}

public sealed record class ResolvedServiceSecrets(
    IReadOnlyDictionary<string, long> Versions,
    IReadOnlyDictionary<string, ResolvedSecret> Values);

public sealed record class SecretMount(BindMount Mount, IReadOnlyDictionary<string, string> Env);

public sealed class SecretStore(OciVaultClient vault, AgentOptions options)
{
    public const string ContainerSecretsDirectory = "/run/secrets/ts-orch";
    private const string FileSuffix = "_FILE";

    private readonly ConcurrentDictionary<SecretRef, ResolvedSecret> _cache = new();

    public void Invalidate(IEnumerable<SecretRef> secrets)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        foreach (var secret in secrets)
        {
            _cache.TryRemove(secret, out _);
        }
    }

    public void InvalidateAll() => _cache.Clear();

    public async Task<Result<ResolvedServiceSecrets, Validation, NotFound, Forbidden, Unavailable, InternalFailure>> ResolveAsync(
        ServiceSpec service,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(service);
        if (service.Secrets.Keys.FirstOrDefault(static name => !AgentNames.IsEnvironmentName(name)) is { } invalid)
        {
            return new Validation($"Secret key {invalid} of {service.Name} is not a valid environment variable name.");
        }

        return await ResolveRemainingAsync([.. service.Secrets], [with(StringComparer.Ordinal)], cancellationToken);
    }

    public async Task<Result<SecretMount, InternalFailure>> MaterializeAsync(
        string placementId,
        string configHash,
        ResolvedServiceSecrets secrets,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        var directory = GenerationDirectory(placementId, configHash);
        Dictionary<string, string> env = [with(StringComparer.Ordinal)];
        List<AtomicWrite> writes = [];
        foreach (var (name, secret) in secrets.Values.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
        {
            var envName = name.EndsWith(FileSuffix, StringComparison.Ordinal) ? name : name + FileSuffix;
            var fileName = envName[..^FileSuffix.Length];
            writes.Add(new AtomicWrite(Path.Combine(directory, fileName), Encoding.UTF8.GetBytes(secret.Value), UnixFiles.OwnerReadWrite));
            env[envName] = $"{ContainerSecretsDirectory}/{fileName}";
        }

        var written = await UnixFiles.WriteAtomicAsync([options.SecretsDirectory, PlacementDirectory(placementId), directory], writes, cancellationToken);
        return written switch
        {
            Done => new SecretMount(new BindMount(directory, ContainerSecretsDirectory, ReadOnly: true), env),
            InternalFailure failure => failure,
        };
    }

    public void DeleteStaleGenerations(string placementId, IReadOnlySet<string> keepConfigHashes)
    {
        ArgumentNullException.ThrowIfNull(keepConfigHashes);
        var placementDirectory = PlacementDirectory(placementId);
        if (!Directory.Exists(placementDirectory))
        {
            return;
        }

        var keep = keepConfigHashes.Select(GenerationName).ToHashSet(StringComparer.Ordinal);
        foreach (var generation in Directory.EnumerateDirectories(placementDirectory))
        {
            if (!keep.Contains(Path.GetFileName(generation)))
            {
                Directory.Delete(generation, recursive: true);
            }
        }
    }

    public void DeletePlacement(string placementId)
    {
        var placementDirectory = PlacementDirectory(placementId);
        if (Directory.Exists(placementDirectory))
        {
            Directory.Delete(placementDirectory, recursive: true);
        }
    }

    private string PlacementDirectory(string placementId)
    {
        if (!AgentNames.IsSafeToken(placementId))
        {
            throw new ArgumentException($"Placement id {placementId} is not a safe path token.", nameof(placementId));
        }

        return Path.Combine(options.SecretsDirectory, placementId);
    }

    private async Task<Result<ResolvedServiceSecrets, Validation, NotFound, Forbidden, Unavailable, InternalFailure>> ResolveRemainingAsync(
        KeyValuePair<string, SecretRef>[] remaining,
        Dictionary<string, ResolvedSecret> resolved,
        CancellationToken cancellationToken)
    {
        if (remaining is not [var (name, reference), .. var rest])
        {
            return new ResolvedServiceSecrets(
                resolved.ToDictionary(static pair => pair.Key, static pair => pair.Value.Version, StringComparer.Ordinal),
                resolved);
        }

        if (_cache.TryGetValue(reference, out var cached))
        {
            resolved[name] = cached;
            return await ResolveRemainingAsync(rest, resolved, cancellationToken);
        }

        return await vault.GetSecretAsync(reference.Vault, reference.Name, cancellationToken) switch
        {
            VaultSecretBundle bundle => await ResolveRemainingAsync(
                rest,
                Remember(resolved, name, _cache.GetOrAdd(reference, new ResolvedSecret(reference, bundle.VersionNumber, bundle.Value))),
                cancellationToken),
            Validation failure => failure,
            NotFound failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    private static Dictionary<string, ResolvedSecret> Remember(Dictionary<string, ResolvedSecret> resolved, string name, ResolvedSecret secret)
    {
        resolved[name] = secret;
        return resolved;
    }

    private string GenerationDirectory(string placementId, string configHash) =>
        Path.Combine(PlacementDirectory(placementId), GenerationName(configHash));

    private static string GenerationName(string configHash) => configHash[..Math.Min(16, configHash.Length)];
}

public static partial class AgentNames
{
    public static bool IsSafeToken(string value) => !string.IsNullOrEmpty(value) && value.Length <= 128 && SafeToken().IsMatch(value);

    public static bool IsEnvironmentName(string value) => !string.IsNullOrEmpty(value) && EnvironmentName().IsMatch(value);

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9_.-]*$")]
    private static partial Regex SafeToken();

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex EnvironmentName();
}
