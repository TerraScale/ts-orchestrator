using System.Collections.ObjectModel;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Security;

internal sealed class InfisicalConfiguration
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private const UnixFileMode ForbiddenCredentialMode =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    private InfisicalConfiguration(
        Uri server,
        string projectId,
        string environment,
        string secretPath,
        string clientIdFile,
        string clientSecretFile,
        string? organizationSlug)
    {
        Server = server;
        VaultProject = projectId;
        Environment = environment;
        SecretPath = secretPath;
        ClientIdFile = clientIdFile;
        ClientSecretFile = clientSecretFile;
        OrganizationSlug = organizationSlug;
    }

    public Uri Server { get; }
    public string VaultProject { get; }
    public string Environment { get; }
    public string SecretPath { get; }
    public string ClientIdFile { get; }
    public string ClientSecretFile { get; }
    public string? OrganizationSlug { get; }

    // Infrastructure-only journal provisioning must not fetch or materialize
    // the generic TS_ORCH_* secret environment, which can contain controller
    // and journal-writer private credential files.
    internal static bool RequiresRuntimeSecretEnvironment(string? command) =>
        command is null or "run" or "check" or "runner";

    public static InfisicalConfiguration? Resolve(Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        return Resolve(
            environment("TS_ORCH_INFISICAL_URL"),
            environment("TS_ORCH_INFISICAL_PROJECT_ID"),
            environment("TS_ORCH_INFISICAL_ENVIRONMENT"),
            environment("TS_ORCH_INFISICAL_SECRET_PATH"),
            environment("TS_ORCH_INFISICAL_CLIENT_ID_FILE"),
            environment("TS_ORCH_INFISICAL_CLIENT_SECRET_FILE"),
            environment("TS_ORCH_INFISICAL_ORGANIZATION_SLUG"));
    }

    public static InfisicalConfiguration? Resolve(
        string? server,
        string? projectId,
        string? environment,
        string? secretPath,
        string? clientIdFile,
        string? clientSecretFile,
        string? organizationSlug = null)
    {
        var supplied = new[]
        {
            server, projectId, environment, secretPath, clientIdFile, clientSecretFile, organizationSlug
        }.Any(static value => !string.IsNullOrWhiteSpace(value));
        if (!supplied) return null;
        if (string.IsNullOrWhiteSpace(projectId) || string.IsNullOrWhiteSpace(environment) ||
            string.IsNullOrWhiteSpace(clientIdFile) || string.IsNullOrWhiteSpace(clientSecretFile))
            throw new ArgumentException(
                "Infisical requires project, environment, client ID file, and client secret file together.");

        var serverValue = string.IsNullOrWhiteSpace(server) ? "https://app.infisical.com" : server;
        if (!Uri.TryCreate(serverValue, UriKind.Absolute, out var serverUri) ||
            serverUri.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(serverUri.UserInfo) ||
            !string.IsNullOrEmpty(serverUri.Query) || !string.IsNullOrEmpty(serverUri.Fragment) ||
            serverUri.AbsolutePath != "/" || serverUri.Port <= 0 ||
            serverUri.Scheme == "http" && !IsLoopback(serverUri.Host))
            throw new ArgumentException("The Infisical server URL is invalid or insecure.");

        var resolvedPath = string.IsNullOrWhiteSpace(secretPath) ? "/" : secretPath;
        RequireText(projectId!, 128, "Infisical project");
        RequireText(environment!, 64, "Infisical environment");
        RequireText(resolvedPath, 512, "Infisical secret path", allowSlash: true);
        if (!resolvedPath.StartsWith('/') || resolvedPath.Contains('?') || resolvedPath.Contains('#'))
            throw new ArgumentException("The Infisical secret path must be an absolute vault path.");
        var resolvedOrganization = string.IsNullOrWhiteSpace(organizationSlug) ? null : organizationSlug;
        if (resolvedOrganization is not null)
            RequireText(resolvedOrganization, 64, "Infisical organization slug");

        return new(
            new Uri(serverUri.GetLeftPart(UriPartial.Authority) + "/", UriKind.Absolute),
            projectId!,
            environment!,
            resolvedPath,
            ResolveCredentialFile(clientIdFile!, "Infisical client ID"),
            ResolveCredentialFile(clientSecretFile!, "Infisical client secret"),
            resolvedOrganization);
    }

    internal string ReadClientId() => ReadCredential(ClientIdFile, "Infisical client ID");
    internal string ReadClientSecret() => ReadCredential(ClientSecretFile, "Infisical client secret");

    private static string ResolveCredentialFile(string value, string name)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Infisical credential files require Linux file permissions.");
        var path = Path.GetFullPath(value);
        var file = new FileInfo(path);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > 4096 ||
            (File.GetUnixFileMode(path) & ForbiddenCredentialMode) != 0)
            throw new ArgumentException($"The {name} file must be bounded, regular, and owner-private.");
        return path;
    }

    private static string ReadCredential(string path, string name)
    {
        var bytes = File.ReadAllBytes(ResolveCredentialFile(path, name));
        try
        {
            var value = StrictUtf8.GetString(bytes);
            if (value.Length is < 1 or > 4096 || value.Any(static character =>
                    char.IsWhiteSpace(character) || char.IsControl(character)))
                throw new InvalidDataException($"The {name} file is invalid.");
            return value;
        }
        catch (DecoderFallbackException)
        {
            throw new InvalidDataException($"The {name} file is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static void RequireText(string value, int maximum, string name, bool allowSlash = false)
    {
        if (value.Length is < 1 || value.Length > maximum || value.Any(character =>
                char.IsControl(character) || char.IsWhiteSpace(character) || !allowSlash && character == '/'))
            throw new ArgumentException($"The {name} is invalid.");
    }

    private static bool IsLoopback(string host) =>
        host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
        IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);
}

internal sealed class InfisicalSecret
{
    internal InfisicalSecret(string name, string value, int version, string path)
    {
        Name = name;
        Value = value;
        Version = version;
        Path = path;
    }

    public string Name { get; }
    public string Value { get; }
    public int Version { get; }
    public string Path { get; }

    public override string ToString() => $"{Path}:{Name}@{Version}";
}

internal sealed record InfisicalSecretMetadata(string Name, int Version, string Path);

/// <summary>Direct Universal Auth and v4 Secrets API adapter. Secret values never appear in its errors.</summary>
internal sealed class InfisicalSecretStore : IAsyncDisposable
{
    private const int MaximumResponseBytes = 8 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
    private readonly InfisicalConfiguration configuration;
    private readonly HttpClient client;
    private readonly SemaphoreSlim authentication = new(1, 1);
    private string? accessToken;
    private bool disposed;

    private InfisicalSecretStore(InfisicalConfiguration configuration, HttpClient client)
    {
        this.configuration = configuration;
        this.client = client;
    }

    public static InfisicalSecretStore Create(InfisicalConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return new(configuration, new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
        })
        {
            Timeout = TimeSpan.FromSeconds(15)
        });
    }

    internal static InfisicalSecretStore Create(
        InfisicalConfiguration configuration,
        HttpMessageHandler handler) => new(configuration, new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(15)
        });

    public async Task<IReadOnlyList<InfisicalSecretMetadata>> ListAsync(
        CancellationToken cancellationToken = default)
    {
        var documents = await ListDocumentsAsync(viewValues: false, cancellationToken);
        return Array.AsReadOnly(documents.Select(document =>
            new InfisicalSecretMetadata(document.SecretKey, document.Version, PathOf(document))).ToArray());
    }

    public async Task<InfisicalSecret> GetAsync(
        string name,
        CancellationToken cancellationToken = default)
    {
        RequireSecretName(name);
        var response = await SendAsync<SecretResponse>(
            HttpMethod.Get,
            $"api/v4/secrets/{Uri.EscapeDataString(name)}?{ScopeQuery()}&viewSecretValue=true&expandSecretReferences=true",
            null,
            cancellationToken);
        return SecretOf(RequireDocument(response.Secret));
    }

    public async Task<InfisicalSecretMetadata> CreateAsync(
        string name,
        string value,
        CancellationToken cancellationToken = default)
    {
        RequireSecretName(name);
        RequireSecretValue(value);
        var response = await SendAsync<SecretResponse>(
            HttpMethod.Post,
            $"api/v4/secrets/{Uri.EscapeDataString(name)}",
            new SecretWriteRequest(
                configuration.VaultProject,
                configuration.Environment,
                value,
                configuration.SecretPath,
                "shared"),
            cancellationToken);
        return MetadataOf(RequireDocument(response.Secret));
    }

    public async Task<InfisicalSecretMetadata> UpdateAsync(
        string name,
        string value,
        CancellationToken cancellationToken = default)
    {
        RequireSecretName(name);
        RequireSecretValue(value);
        var response = await SendAsync<SecretResponse>(
            HttpMethod.Patch,
            $"api/v4/secrets/{Uri.EscapeDataString(name)}",
            new SecretWriteRequest(
                configuration.VaultProject,
                configuration.Environment,
                value,
                configuration.SecretPath,
                "shared"),
            cancellationToken);
        return MetadataOf(RequireDocument(response.Secret));
    }

    public async Task<InfisicalSecretMetadata> DeleteAsync(
        string name,
        CancellationToken cancellationToken = default)
    {
        RequireSecretName(name);
        var response = await SendAsync<SecretResponse>(
            HttpMethod.Delete,
            $"api/v4/secrets/{Uri.EscapeDataString(name)}",
            new SecretDeleteRequest(
                configuration.VaultProject,
                configuration.Environment,
                configuration.SecretPath,
                "shared"),
            cancellationToken);
        return MetadataOf(RequireDocument(response.Secret));
    }

    internal async Task<IReadOnlyDictionary<string, string>> LoadEnvironmentAsync(
        CancellationToken cancellationToken = default)
    {
        var documents = await ListDocumentsAsync(viewValues: true, cancellationToken);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var document in documents)
        {
            if (document.SecretValue is null || !values.TryAdd(document.SecretKey, document.SecretValue))
                throw new InvalidDataException("Infisical returned missing or duplicate secret values.");
        }
        return new ReadOnlyDictionary<string, string>(values);
    }

    private async Task<SecretDocument[]> ListDocumentsAsync(
        bool viewValues,
        CancellationToken cancellationToken)
    {
        var response = await SendAsync<SecretListResponse>(
            HttpMethod.Get,
            $"api/v4/secrets?{ScopeQuery()}&viewSecretValue={viewValues.ToString().ToLowerInvariant()}" +
            "&expandSecretReferences=true&recursive=false",
            null,
            cancellationToken);
        if (response.Secrets is null) throw new InvalidDataException("Infisical returned an invalid secret list.");
        var values = new Dictionary<string, SecretDocument>(StringComparer.Ordinal);
        foreach (var document in response.Secrets)
        {
            var valid = RequireDocument(document);
            values.TryAdd(valid.SecretKey, valid);
        }
        foreach (var import in response.Imports ?? [])
        foreach (var document in import.Secrets ?? [])
        {
            var valid = RequireDocument(document);
            values.TryAdd(valid.SecretKey, string.IsNullOrWhiteSpace(valid.SecretPath)
                ? valid with { SecretPath = import.SecretPath }
                : valid);
        }
        return values.Values.ToArray();
    }

    private async Task<T> SendAsync<T>(
        HttpMethod method,
        string relativeUri,
        object? body,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        await EnsureAuthenticatedAsync(cancellationToken);
        using var request = new HttpRequestMessage(method, new Uri(configuration.Server, relativeUri));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        if (body is not null) request.Content = JsonContent.Create(body, options: JsonOptions);
        return await SendAsync<T>(request, "secret", cancellationToken);
    }

    private async Task EnsureAuthenticatedAsync(CancellationToken cancellationToken)
    {
        if (accessToken is not null) return;
        await authentication.WaitAsync(cancellationToken);
        try
        {
            if (accessToken is not null) return;
            var clientId = configuration.ReadClientId();
            var clientSecret = configuration.ReadClientSecret();
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                new Uri(configuration.Server, "api/v1/auth/universal-auth/login"))
            {
                Content = JsonContent.Create(
                    new LoginRequest(clientId, clientSecret, configuration.OrganizationSlug),
                    options: JsonOptions)
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var response = await SendAsync<LoginResponse>(request, "authentication", cancellationToken);
            if (response.ExpiresIn <= 0 || string.IsNullOrWhiteSpace(response.AccessToken) ||
                response.AccessToken.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character)))
                throw new InvalidDataException("Infisical returned an invalid authentication response.");
            accessToken = response.AccessToken;
        }
        finally
        {
            authentication.Release();
        }
    }

    private async Task<T> SendAsync<T>(
        HttpRequestMessage request,
        string operation,
        CancellationToken cancellationToken)
    {
        using var response = await client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Infisical {operation} failed with HTTP {(int)response.StatusCode}.");
        try
        {
            await response.Content.LoadIntoBufferAsync(MaximumResponseBytes, cancellationToken);
            return await response.Content.ReadFromJsonAsync<T>(JsonOptions, cancellationToken)
                ?? throw new InvalidDataException($"Infisical returned an empty {operation} response.");
        }
        catch (Exception exception) when (exception is JsonException or HttpRequestException)
        {
            throw new InvalidDataException($"Infisical returned an invalid {operation} response.");
        }
    }

    private string ScopeQuery() => string.Join('&',
        Pair("projectId", configuration.VaultProject),
        Pair("environment", configuration.Environment),
        Pair("secretPath", configuration.SecretPath));

    private static string Pair(string key, string value) =>
        $"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value)}";

    private InfisicalSecret SecretOf(SecretDocument document)
    {
        if (document.SecretValue is null)
            throw new InvalidDataException("Infisical did not return the requested secret value.");
        return new(document.SecretKey, document.SecretValue, document.Version, PathOf(document));
    }

    private InfisicalSecretMetadata MetadataOf(SecretDocument document) =>
        new(document.SecretKey, document.Version, PathOf(document));

    private string PathOf(SecretDocument document)
    {
        var path = string.IsNullOrWhiteSpace(document.SecretPath)
            ? configuration.SecretPath
            : document.SecretPath;
        if (path.Length > 512 || !path.StartsWith('/') ||
            path.Any(static character => char.IsControl(character)))
            throw new InvalidDataException("Infisical returned invalid secret metadata.");
        return path;
    }

    private static SecretDocument RequireDocument(SecretDocument? document)
    {
        if (document is null || document.Version < 1) throw new InvalidDataException("Infisical returned invalid secret metadata.");
        RequireSecretName(document.SecretKey);
        return document;
    }

    private static void RequireSecretName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 256 ||
            name.Any(static character => char.IsControl(character)))
            throw new ArgumentException("The Infisical secret name is invalid.", nameof(name));
    }

    private static void RequireSecretValue(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (Encoding.UTF8.GetByteCount(value) > 1024 * 1024)
            throw new ArgumentException("The Infisical secret value exceeds the supported bound.", nameof(value));
    }

    public ValueTask DisposeAsync()
    {
        if (disposed) return ValueTask.CompletedTask;
        disposed = true;
        accessToken = null;
        authentication.Dispose();
        client.Dispose();
        return ValueTask.CompletedTask;
    }

    private sealed record LoginRequest(string ClientId, string ClientSecret, string? OrganizationSlug);
    private sealed record LoginResponse(string AccessToken, int ExpiresIn, int AccessTokenMaxTtl);
    private sealed record SecretWriteRequest(
        string ProjectId,
        string Environment,
        string SecretValue,
        string SecretPath,
        string Type);
    private sealed record SecretDeleteRequest(
        string ProjectId,
        string Environment,
        string SecretPath,
        string Type);
    private sealed record SecretResponse(SecretDocument? Secret);
    private sealed record SecretListResponse(SecretDocument[]? Secrets, SecretImport[]? Imports);
    private sealed record SecretImport(string SecretPath, SecretDocument[]? Secrets);
    private sealed record SecretDocument(
        string SecretKey,
        string? SecretValue,
        int Version,
        string? SecretPath);
}

internal sealed class InfisicalSecretEnvironment : IDisposable
{
    private static readonly UnixFileMode DirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private static readonly UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private readonly Dictionary<string, string> values;
    private readonly string? directory;

    private InfisicalSecretEnvironment(Dictionary<string, string> values, string? directory)
    {
        this.values = values;
        this.directory = directory;
    }

    internal static async Task<InfisicalSecretEnvironment> LoadAsync(
        InfisicalConfiguration configuration,
        CancellationToken cancellationToken)
    {
        await using var store = InfisicalSecretStore.Create(configuration);
        return await LoadAsync(store, cancellationToken);
    }

    internal static async Task<InfisicalSecretEnvironment> LoadAsync(
        InfisicalSecretStore store,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Infisical secret files require Linux file permissions.");
        var secrets = await store.LoadEnvironmentAsync(cancellationToken);
        var values = new Dictionary<string, string>(secrets, StringComparer.Ordinal);
        string? directory = null;
        try
        {
            foreach (var key in secrets.Keys.Where(IsFileSetting).ToArray())
            {
                directory ??= CreateDirectory();
                var path = Path.Combine(directory, key.ToLowerInvariant());
                var bytes = Encoding.UTF8.GetBytes(secrets[key]);
                try
                {
                    using var file = new FileStream(path, new FileStreamOptions
                    {
                        Mode = FileMode.CreateNew,
                        Access = FileAccess.Write,
                        Share = FileShare.None,
                        Options = FileOptions.WriteThrough,
                        UnixCreateMode = PrivateFileMode,
                    });
                    file.Write(bytes);
                    file.Flush(flushToDisk: true);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
                values[key] = path;
            }
            return new(values, directory);
        }
        catch
        {
            if (directory is not null) Directory.Delete(directory, recursive: true);
            throw;
        }
    }

    internal string? GetValue(string key) => values.GetValueOrDefault(key);

    public void Dispose()
    {
        values.Clear();
        if (directory is not null && Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }

    private static string CreateDirectory()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Infisical secret files require Linux file permissions.");
        var path = Path.Combine(
            Path.GetTempPath(),
            $"terrascale-infisical-{Environment.ProcessId}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path, DirectoryMode);
        File.SetUnixFileMode(path, DirectoryMode);
        return path;
    }

    private static bool IsFileSetting(string key) =>
        key.StartsWith("TS_ORCH_", StringComparison.Ordinal) &&
        key.EndsWith("_FILE", StringComparison.Ordinal) &&
        key.All(static character => character is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_');
}
