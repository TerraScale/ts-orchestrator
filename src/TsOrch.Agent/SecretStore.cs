using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace TsOrch.Agent;

public sealed record class ResolvedServiceSecrets(
    IReadOnlyDictionary<string, long> Versions,
    IReadOnlyDictionary<string, ResolvedSecret> Values);

public sealed record class SecretMount(BindMount Mount, IReadOnlyDictionary<string, string> Env);

public sealed class SecretStore(ISecretProvider provider, IOptions<AgentOptions> options)
{
    public const string ContainerSecretsDirectory = "/run/secrets/ts-orch";
    private const string FileSuffix = "_FILE";

    private readonly ConcurrentDictionary<SecretRef, ResolvedSecret> _cache = new();
    private readonly AgentOptions _options = options.Value;

    public void Invalidate(IEnumerable<SecretRef> secrets)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        foreach (var secret in secrets)
        {
            _cache.TryRemove(secret, out _);
        }
    }

    public void InvalidateAll() => _cache.Clear();

    public async Task<OrchResult<ResolvedServiceSecrets>> ResolveAsync(ServiceSpec service, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(service);
        Dictionary<string, long> versions = new(StringComparer.Ordinal);
        Dictionary<string, ResolvedSecret> values = new(StringComparer.Ordinal);
        foreach (var (name, reference) in service.Secrets)
        {
            if (!AgentNames.IsEnvironmentName(name))
            {
                return new Validation($"Secret key {name} of {service.Name} is not a valid environment variable name.");
            }

            if (!_cache.TryGetValue(reference, out var secret))
            {
                var fetched = await provider.GetSecretAsync(reference, cancellationToken);
                if (!fetched.TryGetValue(out var resolved, out var error))
                {
                    return error;
                }

                secret = _cache.GetOrAdd(reference, resolved);
            }

            versions[name] = secret.Version;
            values[name] = secret;
        }

        return new ResolvedServiceSecrets(versions, values);
    }

    public async Task<OrchResult<SecretMount>> MaterializeAsync(
        string placementId,
        string configHash,
        ResolvedServiceSecrets secrets,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        var directory = GenerationDirectory(placementId, configHash);
        UnixFiles.CreatePrivateDirectory(_options.SecretsDirectory);
        UnixFiles.CreatePrivateDirectory(PlacementDirectory(placementId));
        UnixFiles.CreatePrivateDirectory(directory);
        Dictionary<string, string> env = new(StringComparer.Ordinal);
        foreach (var (name, secret) in secrets.Values.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
        {
            var envName = name.EndsWith(FileSuffix, StringComparison.Ordinal) ? name : name + FileSuffix;
            var fileName = envName[..^FileSuffix.Length];
            await UnixFiles.WriteAtomicAsync(Path.Combine(directory, fileName), Encoding.UTF8.GetBytes(secret.Value), UnixFiles.OwnerReadWrite, cancellationToken);
            env[envName] = $"{ContainerSecretsDirectory}/{fileName}";
        }

        return new SecretMount(new BindMount(directory, ContainerSecretsDirectory, ReadOnly: true), env);
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

        return Path.Combine(_options.SecretsDirectory, placementId);
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
