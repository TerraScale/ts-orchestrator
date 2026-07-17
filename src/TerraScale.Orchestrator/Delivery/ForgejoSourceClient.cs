using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TerraScale.Orchestrator.Delivery;

public sealed class ForgejoSourceConfiguration
{
    private ForgejoSourceConfiguration(Uri server, string repository, string tokenFile)
    {
        Server = server;
        Repository = repository;
        TokenFile = tokenFile;
    }

    public Uri Server { get; }
    public string Repository { get; }
    public string TokenFile { get; }

    public static ForgejoSourceConfiguration? Resolve(
        string? server,
        string? repository,
        string? tokenFile)
    {
        var hasServer = !string.IsNullOrWhiteSpace(server);
        var hasToken = !string.IsNullOrWhiteSpace(tokenFile);
        if (!hasServer && !hasToken) return null;
        if (!hasServer || !hasToken || string.IsNullOrWhiteSpace(repository))
            throw new ArgumentException("Forgejo source configuration requires server, repository, and token file together.");
        if (!Uri.TryCreate(server, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) || !uri.AbsolutePath.EndsWith('/') ||
            uri.Scheme == "http" && !IsLoopback(uri.Host))
            throw new ArgumentException("The Forgejo source server URL is invalid or insecure.");
        if (!ForgejoWebhookVerifier.IsRepository(repository))
            throw new ArgumentException("The Forgejo source repository must be an owner/name identity.");
        return new(uri, repository!, ResolveTokenFile(tokenFile!));
    }

    internal string ReadToken()
    {
        var path = ResolveTokenFile(TokenFile);
        var bytes = File.ReadAllBytes(path);
        try
        {
            var token = new UTF8Encoding(false, true).GetString(bytes);
            if (token.Length is < 20 or > 4096 || token.Any(static value => char.IsWhiteSpace(value) || char.IsControl(value)))
                throw new InvalidOperationException("The Forgejo API token file is invalid.");
            return token;
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidOperationException("The Forgejo API token file is invalid.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static string ResolveTokenFile(string value)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Forgejo API tokens require Linux file permissions.");
        var path = Path.GetFullPath(value);
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < 20 or > 4096)
            throw new ArgumentException("The Forgejo API token file must be bounded and existing.");
        var mode = File.GetUnixFileMode(path);
        if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                     UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
            throw new ArgumentException("The Forgejo API token file must be private to the current user.");
        return path;
    }

    private static bool IsLoopback(string host) =>
        host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
        IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);
}

public sealed class ForgejoResolvedRevision
{
    internal ForgejoResolvedRevision(
        string repository,
        string commit,
        string tree,
        bool signatureVerified)
    {
        Repository = repository;
        Commit = commit;
        Tree = tree;
        SignatureVerified = signatureVerified;
    }

    public string Repository { get; }
    public string Commit { get; }
    public string Tree { get; }
    public bool SignatureVerified { get; }
}

public sealed class ForgejoBranchObservation
{
    internal ForgejoBranchObservation(
        string branch,
        bool isProtected,
        ForgejoResolvedRevision revision)
    {
        Branch = branch;
        Protected = isProtected;
        Revision = revision;
    }

    public string Branch { get; }
    public bool Protected { get; }
    public ForgejoResolvedRevision Revision { get; }
}

public sealed class ForgejoSourceFile
{
    internal ForgejoSourceFile(
        string repository,
        string commit,
        string path,
        string blob,
        string contentSha256,
        byte[] content)
    {
        Repository = repository;
        Commit = commit;
        Path = path;
        Blob = blob;
        ContentSha256 = contentSha256;
        Content = content;
    }

    public string Repository { get; }
    public string Commit { get; }
    public string Path { get; }
    public string Blob { get; }
    public string ContentSha256 { get; }
    public ReadOnlyMemory<byte> Content { get; }
}

public sealed class ForgejoSourceArchive
{
    internal ForgejoSourceArchive(
        ForgejoResolvedRevision revision,
        string contentSha256,
        byte[] content)
    {
        Revision = revision;
        ContentSha256 = contentSha256;
        Content = content;
    }

    public ForgejoResolvedRevision Revision { get; }
    public string ContentSha256 { get; }
    public int ContentLength => Content.Length;
    public ReadOnlyMemory<byte> Content { get; }
}

public sealed class ForgejoSourceNotFoundException : Exception
{
    internal ForgejoSourceNotFoundException() : base("The requested Forgejo source revision was not found.") { }
}

/// <summary>Resolves immutable Forgejo commit and tree identities with bounded authenticated API reads.</summary>
public sealed class ForgejoSourceClient : IAsyncDisposable
{
    private const int MaximumMetadataResponseBytes = 64 * 1024;
    private const int MaximumChangedPathsResponseBytes = 8 * 1024 * 1024;
    public const int MaximumFileBytes = 1024 * 1024;
    public const int MaximumArchiveBytes = 256 * 1024 * 1024;
    public const int MaximumChangedPaths = 4_096;
    private const int MaximumJsonDepth = 12;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ArchiveRequestTimeout = TimeSpan.FromMinutes(2);
    private readonly ForgejoSourceConfiguration configuration;
    private readonly HttpClient client;

    internal ForgejoSourceClient(ForgejoSourceConfiguration configuration, HttpClient client)
    {
        this.configuration = configuration;
        this.client = client;
    }

    public static ForgejoSourceClient Create(ForgejoSourceConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return new(configuration, new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
        })
        {
            Timeout = Timeout.InfiniteTimeSpan
        });
    }

    public ValueTask DisposeAsync()
    {
        client.Dispose();
        return ValueTask.CompletedTask;
    }

    public async Task<ForgejoResolvedRevision> ResolveAsync(
        string commit,
        CancellationToken cancellationToken = default)
    {
        if (!IsObjectId(commit) || commit.All(static value => value == '0'))
            throw new ArgumentException("The Forgejo commit identity is invalid.", nameof(commit));
        var (owner, repository) = SplitRepository(configuration.Repository);
        var path = $"api/v1/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repository)}/git/commits/" +
                   $"{commit.ToLowerInvariant()}?stat=false&verification=true&files=false";
        using var document = await GetJsonAsync(path, MaximumMetadataResponseBytes, cancellationToken);
        var root = document.RootElement;
        if (!TryString(root, "sha", out var observedCommit) ||
            !StringComparer.OrdinalIgnoreCase.Equals(observedCommit, commit) ||
            !TryObject(root, "commit", out var commitObject) ||
            !TryObject(commitObject, "tree", out var treeObject) ||
            !TryString(treeObject, "sha", out var tree) || !IsObjectId(tree) || tree.All(static value => value == '0'))
            throw new InvalidDataException("The Forgejo commit response did not contain the exact requested Git objects.");
        var signatureVerified = TryObject(commitObject, "verification", out var verification) &&
                                TryBoolean(verification, "verified", out var verified) && verified;
        return new(
            configuration.Repository,
            observedCommit.ToLowerInvariant(),
            tree.ToLowerInvariant(),
            signatureVerified);
    }

    public async Task<ForgejoBranchObservation> PollBranchAsync(
        string branch,
        CancellationToken cancellationToken = default)
    {
        if (branch is not ("develop" or "main"))
            throw new ArgumentException("Forgejo polling is restricted to develop and main.", nameof(branch));
        var (owner, repository) = SplitRepository(configuration.Repository);
        var path = $"api/v1/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repository)}/branches/" +
                   Uri.EscapeDataString(branch);
        using var document = await GetJsonAsync(path, MaximumMetadataResponseBytes, cancellationToken);
        var root = document.RootElement;
        if (!TryString(root, "name", out var observedBranch) || observedBranch != branch ||
            !TryBoolean(root, "protected", out var isProtected) ||
            !TryObject(root, "commit", out var commitObject) ||
            !TryString(commitObject, "id", out var commit) || !IsObjectId(commit) || commit.All(static value => value == '0'))
            throw new InvalidDataException("The Forgejo branch response did not contain a bounded exact commit identity.");
        var revision = await ResolveAsync(commit, cancellationToken);
        return new(branch, isProtected, revision);
    }

    public async Task<IReadOnlyList<string>> ReadChangedPathsAsync(
        ForgejoWebhookEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (envelope.Repository != configuration.Repository)
            throw new ArgumentException("The Forgejo event belongs to another repository.", nameof(envelope));
        if (!IsObjectId(envelope.BaseRevision) || !IsObjectId(envelope.Revision) ||
            envelope.Revision.All(static value => value == '0') || envelope.IsDeletion)
            throw new ArgumentException("The Forgejo event does not identify an exact comparable revision range.", nameof(envelope));
        if (envelope.BaseRevision.All(static value => value == '0'))
            return Array.AsReadOnly([RepositoryCiImpactPlanner.DescriptorPath]);

        var (owner, repository) = SplitRepository(configuration.Repository);
        var range = Uri.EscapeDataString($"{envelope.BaseRevision.ToLowerInvariant()}...{envelope.Revision.ToLowerInvariant()}");
        var path = $"api/v1/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repository)}/compare/{range}";
        using var document = await GetJsonAsync(path, MaximumChangedPathsResponseBytes, cancellationToken);
        if (!TryArray(document.RootElement, "files", out var files) ||
            files.GetArrayLength() is < 1 or > MaximumChangedPaths)
            throw new InvalidDataException("The Forgejo comparison did not contain a bounded changed-path set.");

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in files.EnumerateArray())
        {
            if (!TryString(file, "filename", out var filename) || !IsSafePath(filename) ||
                !TryString(file, "status", out var status) || !IsChangeStatus(status) || !seen.Add(filename))
                throw new InvalidDataException("The Forgejo comparison contained an invalid or ambiguous changed path.");
            paths.Add(filename);
            if (status is "renamed" or "copied") paths.Add(RepositoryCiImpactPlanner.DescriptorPath);
        }
        return Array.AsReadOnly(paths.Order(StringComparer.Ordinal).ToArray());
    }

    public async Task<ForgejoSourceFile> ReadFileAsync(
        string commit,
        string path,
        int maximumBytes,
        CancellationToken cancellationToken = default)
    {
        if (!IsObjectId(commit) || commit.All(static value => value == '0'))
            throw new ArgumentException("The Forgejo commit identity is invalid.", nameof(commit));
        if (!IsSafePath(path))
            throw new ArgumentException("The Forgejo source path is invalid.", nameof(path));
        if (maximumBytes is < 1 or > MaximumFileBytes)
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));

        var normalizedCommit = commit.ToLowerInvariant();
        var encodedPath = string.Join('/', path.Split('/').Select(Uri.EscapeDataString));
        var (owner, repository) = SplitRepository(configuration.Repository);
        var requestPath = $"api/v1/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repository)}/contents/" +
                          $"{encodedPath}?ref={normalizedCommit}";
        var maximumResponseBytes = checked(((maximumBytes + 2) / 3 * 4) + MaximumMetadataResponseBytes);
        using var document = await GetJsonAsync(requestPath, maximumResponseBytes, cancellationToken);
        var root = document.RootElement;
        var name = path[(path.LastIndexOf('/') + 1)..];
        if (!TryString(root, "type", out var type) || type != "file" ||
            !TryString(root, "name", out var observedName) || observedName != name ||
            !TryString(root, "path", out var observedPath) || observedPath != path ||
            !TryString(root, "sha", out var blob) || !IsObjectId(blob) || blob.All(static value => value == '0') ||
            !TryInt64(root, "size", out var size) || size < 0 || size > maximumBytes ||
            !TryString(root, "encoding", out var encoding) || encoding != "base64" ||
            !TryString(root, "content", out var encodedContent))
            throw new InvalidDataException("The Forgejo file response did not contain the exact bounded file identity.");

        byte[] content;
        try
        {
            content = Convert.FromBase64String(encodedContent);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("The Forgejo file response contained invalid Base64 content.", exception);
        }
        if (content.LongLength != size || content.Length > maximumBytes)
            throw new InvalidDataException("The Forgejo file response did not match its declared size.");

        return new(
            configuration.Repository,
            normalizedCommit,
            path,
            blob.ToLowerInvariant(),
            Convert.ToHexStringLower(SHA256.HashData(content)),
            content);
    }

    public async Task<ForgejoSourceArchive> ReadArchiveAsync(
        ForgejoResolvedRevision revision,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(revision);
        if (revision.Repository != configuration.Repository ||
            !IsObjectId(revision.Commit) || revision.Commit.All(static value => value == '0') ||
            !IsObjectId(revision.Tree) || revision.Tree.All(static value => value == '0'))
            throw new ArgumentException("The Forgejo source revision is invalid for this repository.", nameof(revision));

        var normalizedCommit = revision.Commit.ToLowerInvariant();
        var (owner, repository) = SplitRepository(configuration.Repository);
        var archive = Uri.EscapeDataString($"{normalizedCommit}.tar.gz");
        var path = $"api/v1/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repository)}/archive/{archive}";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ArchiveRequestTimeout);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(configuration.Server, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("token", configuration.ReadToken());
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/gzip"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (response.StatusCode == HttpStatusCode.NotFound) throw new ForgejoSourceNotFoundException();
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new UnauthorizedAccessException("Forgejo source credentials were denied.");
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException("Forgejo source archive retrieval failed.", null, response.StatusCode);
        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (mediaType is null ||
            !mediaType.Equals("application/gzip", StringComparison.OrdinalIgnoreCase) &&
            !mediaType.Equals("application/octet-stream", StringComparison.OrdinalIgnoreCase) ||
            response.Content.Headers.ContentEncoding.Count != 0)
            throw new InvalidDataException("The Forgejo source archive response was not an unencoded gzip archive.");
        var declaredLength = response.Content.Headers.ContentLength;
        if (declaredLength is <= 0 or > MaximumArchiveBytes)
            throw new InvalidDataException("The Forgejo source archive exceeded its technical bound.");

        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
        var content = await ReadBoundedAsync(stream, MaximumArchiveBytes, timeout.Token);
        if (declaredLength is not null && content.Length != declaredLength)
            throw new InvalidDataException("The Forgejo source archive did not match its declared length.");
        if (content.Length < 3 || content[0] != 0x1f || content[1] != 0x8b || content[2] != 0x08)
            throw new InvalidDataException("The Forgejo source archive was not a gzip stream.");
        return new(
            revision,
            Convert.ToHexStringLower(SHA256.HashData(content)),
            content);
    }

    private async Task<JsonDocument> GetJsonAsync(
        string path,
        int maximumResponseBytes,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(configuration.Server, path));
        var token = configuration.ReadToken();
        request.Headers.Authorization = new AuthenticationHeaderValue("token", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (response.StatusCode == HttpStatusCode.NotFound) throw new ForgejoSourceNotFoundException();
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new UnauthorizedAccessException("Forgejo source credentials were denied.");
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException("Forgejo source resolution failed.", null, response.StatusCode);
        if (!string.Equals(
                response.Content.Headers.ContentType?.MediaType,
                "application/json",
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The Forgejo source response was not JSON.");
        if (response.Content.Headers.ContentLength > maximumResponseBytes)
            throw new InvalidDataException("The Forgejo source response exceeded its technical bound.");
        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
        var bytes = await ReadBoundedAsync(stream, maximumResponseBytes, timeout.Token);
        try
        {
            if (HasDuplicateProperties(bytes))
                throw new InvalidDataException("The Forgejo source response contained ambiguous fields.");
            return JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = MaximumJsonDepth,
            });
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The Forgejo source response was invalid JSON.", exception);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        await using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0) return output.ToArray();
            if (output.Length + read > maximumBytes)
                throw new InvalidDataException("The Forgejo source response exceeded its technical bound.");
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    private static bool HasDuplicateProperties(byte[] payload)
    {
        var reader = new Utf8JsonReader(payload, new JsonReaderOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = MaximumJsonDepth,
        });
        var objectFields = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.StartObject) objectFields.Push(new(StringComparer.Ordinal));
            else if (reader.TokenType == JsonTokenType.EndObject) objectFields.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName && !objectFields.Peek().Add(reader.GetString()!))
                return true;
        }
        return objectFields.Count != 0;
    }

    private static bool TryObject(JsonElement owner, string name, out JsonElement value)
    {
        value = default;
        return owner.ValueKind == JsonValueKind.Object && owner.TryGetProperty(name, out value) &&
               value.ValueKind == JsonValueKind.Object;
    }

    private static bool TryArray(JsonElement owner, string name, out JsonElement value)
    {
        value = default;
        return owner.ValueKind == JsonValueKind.Object && owner.TryGetProperty(name, out value) &&
               value.ValueKind == JsonValueKind.Array;
    }

    private static bool TryString(JsonElement owner, string name, out string value)
    {
        value = string.Empty;
        if (owner.ValueKind != JsonValueKind.Object || !owner.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.String || property.GetString() is not { } text) return false;
        value = text;
        return true;
    }

    private static bool TryBoolean(JsonElement owner, string name, out bool value)
    {
        value = false;
        if (owner.ValueKind != JsonValueKind.Object || !owner.TryGetProperty(name, out var property) ||
            property.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
        value = property.GetBoolean();
        return true;
    }

    private static bool TryInt64(JsonElement owner, string name, out long value)
    {
        value = 0;
        return owner.ValueKind == JsonValueKind.Object && owner.TryGetProperty(name, out var property) &&
               property.ValueKind == JsonValueKind.Number && property.TryGetInt64(out value);
    }

    private static (string Owner, string Repository) SplitRepository(string value)
    {
        var separator = value.IndexOf('/');
        return (value[..separator], value[(separator + 1)..]);
    }

    private static bool IsObjectId(string value) => value.Length is 40 or 64 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static bool IsSafePath(string value) => value is { Length: > 0 and <= 512 } &&
        value[0] != '/' && value[^1] != '/' &&
        value.Split('/').All(static segment => segment is not ("" or "." or "..")) &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
            >= '0' and <= '9' or '.' or '_' or '-' or '/');

    private static bool IsChangeStatus(string value) => value is { Length: >= 1 and <= 32 } &&
        value.All(static character => character is >= 'a' and <= 'z' or '-');
}
