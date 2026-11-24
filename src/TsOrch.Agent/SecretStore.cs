using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using TsOrch.Oci;

namespace TsOrch.Agent;

internal readonly union SecretMaterialization(SecretMounts, InvalidConfigFileTarget, ConfigFileSecretMissing, AtomicWriteFailed);

public sealed record class ResolvedSecret(SecretRef Ref, long Version, string Value)
{
    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{nameof(ResolvedSecret)} {{ Vault = {Ref.Vault}, Name = {Ref.Name}, Version = {Version} }}");
}

public sealed record class ResolvedServiceSecrets(
    IReadOnlyDictionary<string, long> Versions,
    IReadOnlyDictionary<string, ResolvedSecret> Values);

internal sealed record class SecretMounts(IReadOnlyList<BindMount> Mounts, IReadOnlyDictionary<string, string> Env);

public sealed record class InvalidSecretName(string Service, string Name)
{
    public string Message => $"Secret key '{Name}' of {Service} must produce a valid environment variable and a non-empty filename.";
}

public sealed record class SecretNameCollision(string Service, string FileVariable)
{
    public string Message => $"Secret file variable {FileVariable} of {Service} is defined more than once.";
}

public sealed record class InvalidServiceSecretReference(string Service, string Name)
{
    public string Message => $"Secret key {Name} of {Service} requires a vault id and secret name.";
}

public sealed record class SecretReadSuperseded(string Service)
{
    public string Message => $"Secrets for {Service} were invalidated during resolution.";
}

public sealed record class ServiceSecretUnreadable(SecretRef Reference, string Message);

public readonly union ServiceSecretResolution(
    ResolvedServiceSecrets, InvalidSecretName, SecretNameCollision, InvalidServiceSecretReference, SecretReadSuperseded, ServiceSecretUnreadable);

public sealed class SecretStore(OciVaultClient vault, AgentOptions options)
{
    public const string ContainerSecretsDirectory = "/run/secrets/ts-orch";
    private const string FileSuffix = "_FILE";

    private readonly Lock _cacheGate = new();
    private readonly Dictionary<SecretRef, ResolvedSecret> _cache = [];
    private long _generation;

    public void Invalidate(IEnumerable<SecretRef> secrets)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        lock (_cacheGate)
        {
            _generation++;
            foreach (var secret in secrets)
            {
                _cache.Remove(secret);
            }
        }
    }

    public void InvalidateAll()
    {
        lock (_cacheGate)
        {
            _generation++;
            _cache.Clear();
        }
    }

    public async Task<ServiceSecretResolution> ResolveAsync(ServiceSpec service, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(service);
        HashSet<string> normalized = [with(StringComparer.Ordinal)];
        foreach (var (name, reference) in service.Secrets)
        {
            var fileVariable = FileVariable(name);
            if (!AgentNames.IsEnvironmentName(name) || fileVariable.Length <= FileSuffix.Length)
            {
                return new InvalidSecretName(service.Name, name);
            }

            if (service.Env.ContainsKey(fileVariable) || !normalized.Add(fileVariable))
            {
                return new SecretNameCollision(service.Name, fileVariable);
            }

            if (string.IsNullOrWhiteSpace(reference.Vault) || string.IsNullOrWhiteSpace(reference.Name))
            {
                return new InvalidServiceSecretReference(service.Name, name);
            }
        }

        long generation;
        lock (_cacheGate)
        {
            generation = _generation;
        }

        Dictionary<string, ResolvedSecret> resolved = [with(StringComparer.Ordinal)];
        foreach (var (name, reference) in service.Secrets)
        {
            ResolvedSecret? secret;
            lock (_cacheGate)
            {
                if (generation != _generation)
                {
                    return new SecretReadSuperseded(service.Name);
                }

                secret = _cache.GetValueOrDefault(reference);
            }

            if (secret is null)
            {
                var read = await vault.GetSecretAsync(reference.Vault, reference.Name, cancellationToken);
                var fetched = read switch
                {
                    VaultSecretBundle bundle => new SecretFetch(Remember(generation, reference, bundle), null),
                    VaultRegionMissing failure => new SecretFetch(null, failure.Message),
                    VaultSecretMissing failure => new SecretFetch(null, failure.Message),
                    VaultAccessDenied failure => new SecretFetch(null, failure.Message),
                    VaultUnavailable failure => new SecretFetch(null, failure.Message),
                    VaultBundleInvalid failure => new SecretFetch(null, failure.Message),
                    ImdsRequestRejected failure => new SecretFetch(null, failure.Message),
                    ImdsUnavailable failure => new SecretFetch(null, failure.Message),
                    ImdsDocumentInvalid failure => new SecretFetch(null, failure.Message),
                    InvalidFederationCredentials failure => new SecretFetch(null, failure.Message),
                    FederationRejected failure => new SecretFetch(null, failure.Message),
                    FederationUnavailable failure => new SecretFetch(null, failure.Message),
                    FederationTokenInvalid failure => new SecretFetch(null, failure.Message),
                };
                if (fetched.Error is { } error)
                {
                    return new ServiceSecretUnreadable(reference, error);
                }

                if (fetched.Secret is not { } loaded)
                {
                    return new SecretReadSuperseded(service.Name);
                }

                secret = loaded;
            }

            resolved.Add(name, secret);
        }

        lock (_cacheGate)
        {
            return generation == _generation
                ? new ResolvedServiceSecrets(resolved.ToDictionary(static pair => pair.Key, static pair => pair.Value.Version, StringComparer.Ordinal), resolved)
                : new SecretReadSuperseded(service.Name);
        }
    }

    private ResolvedSecret? Remember(long generation, SecretRef reference, VaultSecretBundle bundle)
    {
        lock (_cacheGate)
        {
            if (generation != _generation)
            {
                return null;
            }

            _cache.TryAdd(reference, new ResolvedSecret(reference, bundle.VersionNumber, bundle.Value));
            return _cache[reference];
        }
    }

    internal async Task<SecretMaterialization> MaterializeAsync(
        string placementId,
        string configHash,
        ServiceSpec service,
        ResolvedServiceSecrets secrets,
        CancellationToken cancellationToken)
    {
        var outcome = ServiceConfigFiles.Render(service, secrets);
        return outcome switch
        {
            IReadOnlyList<RenderedConfigFile> files => await WriteFilesAsync(placementId, configHash, service, secrets, files, cancellationToken),
            InvalidConfigFileTarget invalid => invalid,
            ConfigFileSecretMissing missing => missing,
        };
    }

    private async Task<SecretMaterialization> WriteFilesAsync(
        string placementId,
        string configHash,
        ServiceSpec service,
        ResolvedServiceSecrets secrets,
        IReadOnlyList<RenderedConfigFile> configs,
        CancellationToken cancellationToken)
    {
        var directory = GenerationDirectory(placementId, configHash);
        var secretDirectory = configs.Count == 0 ? directory : Path.Combine(directory, "env");
        var templateSecrets = ServiceConfigFiles.ReferencedSecrets(service);
        List<DirectoryMode> directories =
        [
            new(options.SecretsDirectory, UnixFiles.OwnerOnlyDirectory),
            new(PlacementDirectory(placementId), UnixFiles.OwnerOnlyDirectory),
            new(directory, configs.Count == 0 ? UnixFiles.WorldReadableDirectory : UnixFiles.OwnerOnlyDirectory),
        ];
        List<BindMount> mounts = [];
        Dictionary<string, string> env = [with(StringComparer.Ordinal)];
        List<AtomicWrite> writes = [];
        foreach (var (name, secret) in secrets.Values.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
        {
            if (!name.EndsWith(FileSuffix, StringComparison.Ordinal) && templateSecrets.Contains(name))
            {
                continue;
            }

            var envName = FileVariable(name);
            var fileName = envName[..^FileSuffix.Length];
            writes.Add(new AtomicWrite(Path.Combine(secretDirectory, fileName), Encoding.UTF8.GetBytes(secret.Value), UnixFiles.WorldReadable));
            env[envName] = $"{ContainerSecretsDirectory}/{fileName}";
        }

        if (env.Count > 0)
        {
            if (configs.Count > 0)
            {
                directories.Add(new DirectoryMode(secretDirectory, UnixFiles.WorldReadableDirectory));
            }

            mounts.Add(new BindMount(secretDirectory, ContainerSecretsDirectory, ReadOnly: true));
        }

        if (configs.Count > 0)
        {
            var filesDirectory = Path.Combine(directory, "files");
            directories.Add(new DirectoryMode(filesDirectory, UnixFiles.WorldReadableDirectory));
            for (var index = 0; index < configs.Count; index++)
            {
                var file = configs[index];
                var path = Path.Combine(filesDirectory, string.Create(CultureInfo.InvariantCulture, $"{index}.cfg"));
                writes.Add(new AtomicWrite(path, file.Content, UnixFiles.WorldReadable));
                mounts.Add(new BindMount(path, file.Target, ReadOnly: true));
            }
        }

        var written = await UnixFiles.WriteAtomicAsync(directories, writes, cancellationToken);
        return written switch
        {
            AtomicWriteCompleted => new SecretMounts(mounts, env),
            AtomicWriteFailed failure => failure,
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

    private static string FileVariable(string name) =>
        name.EndsWith(FileSuffix, StringComparison.Ordinal) ? name : name + FileSuffix;

    private string GenerationDirectory(string placementId, string configHash) =>
        Path.Combine(PlacementDirectory(placementId), GenerationName(configHash));

    private static string GenerationName(string configHash) => configHash[..Math.Min(16, configHash.Length)];

    private sealed record class SecretFetch(ResolvedSecret? Secret, string? Error);
}

public static partial class AgentNames
{
    public static bool IsSafeToken(string value) => !string.IsNullOrEmpty(value) && value.Length <= 128 && SafeToken().IsMatch(value);

    public static bool IsEnvironmentName(string value) => !string.IsNullOrEmpty(value) && EnvironmentName().IsMatch(value);

    [GeneratedRegex(@"\A[A-Za-z0-9][A-Za-z0-9_.-]*\z")]
    private static partial Regex SafeToken();

    [GeneratedRegex(@"\A[A-Za-z_][A-Za-z0-9_]*\z")]
    private static partial Regex EnvironmentName();
}
