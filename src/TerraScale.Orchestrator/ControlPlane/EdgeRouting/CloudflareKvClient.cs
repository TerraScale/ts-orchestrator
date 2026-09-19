using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace TerraScale.Orchestrator.ControlPlane.EdgeRouting;

/// <summary>One Cloudflare API error entry of a response envelope.</summary>
public sealed record CloudflareKvError(int Code, string Message);

/// <summary>A Cloudflare KV REST call failed; <see cref="Status"/> carries the HTTP status when one was observed.</summary>
public class CloudflareKvException : Exception
{
    internal CloudflareKvException(
        HttpStatusCode? status,
        string message,
        IReadOnlyList<CloudflareKvError> errors,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Status = status;
        Errors = errors;
    }

    public HttpStatusCode? Status { get; }
    public IReadOnlyList<CloudflareKvError> Errors { get; }

    internal static bool IsTransientStatus(HttpStatusCode status) =>
        (int)status is >= 500 or 408 or 429;
}

/// <summary>
/// A KV call answered a namespace-not-found class 404: the namespace id the caller used is
/// stale (the namespace was deleted and recreated) or misconfigured. Callers holding a
/// resolved namespace id must re-resolve it once before treating this as a permanent
/// misconfiguration; it is never transient and never a silently absent key.
/// </summary>
public sealed class CloudflareKvNamespaceNotFoundException : CloudflareKvException
{
    internal CloudflareKvNamespaceNotFoundException(HttpStatusCode status, IReadOnlyList<CloudflareKvError> errors)
        : base(status, $"The Cloudflare KV namespace was not found ({(int)status} {status}).", errors)
    {
    }
}

/// <summary>
/// Minimal Cloudflare Workers KV REST client (<c>https://api.cloudflare.com/client/v4</c>) built
/// on the BCL <see cref="HttpClient"/> only: namespace resolution by title, single-key read and
/// write, bulk write, bulk delete, and key listing. The API token is passed by the caller, which owns its
/// secret handling; nothing here invents an environment convention. Every call carries its own
/// timeout and failures surface as typed <see cref="CloudflareKvException"/>s.
/// </summary>
public sealed class CloudflareKvClient : IDisposable
{
    private const string ApiBaseUrl = "https://api.cloudflare.com/client/v4/";
    private const int MaximumResponseBytes = 1024 * 1024;
    private const int PageSize = 50;
    private const int MaximumPageCount = 100;
    private const int KeyPageLimit = 1000;
    private static readonly TimeSpan DefaultCallTimeout = TimeSpan.FromSeconds(15);

    /// <summary>Cloudflare KV accepts at most 10,000 keys per bulk write or delete.</summary>
    public const int MaximumBulkKeys = 10_000;

    private readonly HttpClient client;
    private readonly bool ownsClient;
    private readonly string apiToken;
    private readonly string accountId;
    private readonly TimeSpan callTimeout;

    internal CloudflareKvClient(
        string apiToken,
        string accountId,
        HttpClient client,
        bool ownsClient = false,
        TimeSpan? callTimeout = null)
    {
        if (string.IsNullOrWhiteSpace(apiToken))
            throw new ArgumentException("The Cloudflare API token is required.", nameof(apiToken));
        if (string.IsNullOrWhiteSpace(accountId))
            throw new ArgumentException("The Cloudflare account id is required.", nameof(accountId));
        this.client = client ?? throw new ArgumentNullException(nameof(client));
        this.ownsClient = ownsClient;
        this.apiToken = apiToken;
        this.accountId = accountId;
        this.callTimeout = callTimeout ?? DefaultCallTimeout;
    }

    public static CloudflareKvClient Create(string apiToken, string accountId, TimeSpan? callTimeout = null) =>
        new(
            apiToken,
            accountId,
            new HttpClient(new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
            })
            {
                Timeout = Timeout.InfiniteTimeSpan,
            },
            ownsClient: true,
            callTimeout: callTimeout);

    public void Dispose()
    {
        if (ownsClient) client.Dispose();
    }

    /// <summary>Resolves a KV namespace id by exact title, or returns null when no namespace carries it.</summary>
    public async Task<string?> ResolveNamespaceIdAsync(string title, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(title))
            throw new ArgumentException("The Cloudflare KV namespace title is required.", nameof(title));
        for (var page = 1; page <= MaximumPageCount; page++)
        {
            var path = $"accounts/{Uri.EscapeDataString(accountId)}/storage/kv/namespaces" +
                       $"?per_page={PageSize}&page={page}";
            var (match, count) = await CallAsync(
                HttpMethod.Get,
                path,
                null,
                (response, token) => ReadNamespacePageAsync(title, response, token),
                cancellationToken);
            if (match is not null) return match;
            if (count < PageSize) return null;
        }

        throw new InvalidOperationException("The Cloudflare KV namespace listing exceeded its page bound.");
    }

    /// <summary>
    /// Returns the raw value of one key, or null when the key does not exist. A 404 whose error
    /// envelope names a missing namespace throws <see cref="CloudflareKvNamespaceNotFoundException"/>
    /// instead — an absent key and a stale namespace id must never be conflated.
    /// </summary>
    public Task<string?> GetKeyValueAsync(
        string namespaceId,
        string key,
        CancellationToken cancellationToken = default) =>
        CallAsync(HttpMethod.Get, ValuesPath(namespaceId, key), null, ReadValueAsync, cancellationToken);

    public async Task PutKeyValueAsync(
        string namespaceId,
        string key,
        string value,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(value))
            throw new ArgumentException("The Cloudflare KV value is required.", nameof(value));
        await CallAsync(
            HttpMethod.Put,
            ValuesPath(namespaceId, key),
            Encoding.UTF8.GetBytes(value),
            ReadEnvelopeSuccessAsync,
            cancellationToken);
    }

    public async Task PutKeysInBulkAsync(
        string namespaceId,
        IReadOnlyList<KeyValuePair<string, string>> entries,
        CancellationToken cancellationToken = default)
    {
        ValidateEntries(namespaceId, entries);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartArray();
            foreach (var entry in entries)
            {
                writer.WriteStartObject();
                writer.WriteString("key", entry.Key);
                writer.WriteString("value", entry.Value);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        await CallAsync(HttpMethod.Put, BulkPath(namespaceId), buffer.ToArray(), ReadEnvelopeSuccessAsync, cancellationToken);
    }

    public async Task DeleteKeysInBulkAsync(
        string namespaceId,
        IReadOnlyList<string> keys,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(namespaceId))
            throw new ArgumentException("The Cloudflare KV namespace id is required.", nameof(namespaceId));
        if (keys is null || keys.Count is < 1 or > MaximumBulkKeys)
            throw new ArgumentException(
                $"A Cloudflare KV bulk delete accepts 1 to {MaximumBulkKeys} keys.", nameof(keys));

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartArray();
            foreach (var key in keys) writer.WriteStringValue(key);
            writer.WriteEndArray();
        }

        await CallAsync(HttpMethod.Delete, BulkPath(namespaceId), buffer.ToArray(), ReadEnvelopeSuccessAsync, cancellationToken);
    }

    /// <summary>
    /// Lists every key of one namespace by following the API's cursor pagination. A 404 whose
    /// error envelope names a missing namespace throws <see cref="CloudflareKvNamespaceNotFoundException"/>
    /// instead — a stale namespace id must never read as an empty namespace.
    /// </summary>
    public async Task<IReadOnlyList<string>> ListKeysAsync(
        string namespaceId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(namespaceId))
            throw new ArgumentException("The Cloudflare KV namespace id is required.", nameof(namespaceId));
        var keys = new List<string>();
        string? cursor = null;
        for (var page = 1; page <= MaximumPageCount; page++)
        {
            var path = $"{KeysPath(namespaceId)}?limit={KeyPageLimit}" +
                       (cursor is null ? string.Empty : $"&cursor={Uri.EscapeDataString(cursor)}");
            var (names, nextCursor) = await CallAsync(
                HttpMethod.Get,
                path,
                null,
                ReadKeysPageAsync,
                cancellationToken);
            keys.AddRange(names);
            if (nextCursor is null) return keys;
            cursor = nextCursor;
        }

        throw new InvalidOperationException("The Cloudflare KV key listing exceeded its page bound.");
    }

    private static void ValidateEntries(string namespaceId, IReadOnlyList<KeyValuePair<string, string>> entries)
    {
        if (string.IsNullOrWhiteSpace(namespaceId))
            throw new ArgumentException("The Cloudflare KV namespace id is required.", nameof(namespaceId));
        if (entries is null || entries.Count is < 1 or > MaximumBulkKeys)
            throw new ArgumentException(
                $"A Cloudflare KV bulk write accepts 1 to {MaximumBulkKeys} entries.", nameof(entries));
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.Key) || string.IsNullOrEmpty(entry.Value) || !seen.Add(entry.Key))
                throw new ArgumentException(
                    "A Cloudflare KV bulk write requires unique non-empty keys and non-empty values.", nameof(entries));
        }
    }

    private string ValuesPath(string namespaceId, string key)
    {
        if (string.IsNullOrWhiteSpace(namespaceId))
            throw new ArgumentException("The Cloudflare KV namespace id is required.", nameof(namespaceId));
        if (string.IsNullOrWhiteSpace(key))
            throw new ArgumentException("The Cloudflare KV key is required.", nameof(key));
        return $"accounts/{Uri.EscapeDataString(accountId)}/storage/kv/namespaces/" +
               $"{Uri.EscapeDataString(namespaceId)}/values/{Uri.EscapeDataString(key)}";
    }

    private string BulkPath(string namespaceId)
    {
        if (string.IsNullOrWhiteSpace(namespaceId))
            throw new ArgumentException("The Cloudflare KV namespace id is required.", nameof(namespaceId));
        return $"accounts/{Uri.EscapeDataString(accountId)}/storage/kv/namespaces/{Uri.EscapeDataString(namespaceId)}/bulk";
    }

    private string KeysPath(string namespaceId)
    {
        if (string.IsNullOrWhiteSpace(namespaceId))
            throw new ArgumentException("The Cloudflare KV namespace id is required.", nameof(namespaceId));
        return $"accounts/{Uri.EscapeDataString(accountId)}/storage/kv/namespaces/{Uri.EscapeDataString(namespaceId)}/keys";
    }

    private HttpRequestMessage CreateRequest(HttpMethod method, string path, byte[]? body = null)
    {
        var request = new HttpRequestMessage(method, new Uri(new Uri(ApiBaseUrl), path));
        Prepare(request, body);
        return request;
    }

    private void Prepare(HttpRequestMessage request, byte[]? body)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (body is null) return;
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
    }

    /// <summary>
    /// One call: send with <see cref="HttpCompletionOption.ResponseHeadersRead"/> and read the
    /// body under the SAME timeout scope. The timeout bounds the whole call, not just
    /// time-to-headers — the linked source stays alive (the <c>using</c> disposes it only after
    /// the read delegate returns) so every body read below is gated by its token; a stalled
    /// body cancels instead of wedging the caller forever.
    /// </summary>
    private async Task<T> CallAsync<T>(
        HttpMethod method,
        string path,
        byte[]? body,
        Func<HttpResponseMessage, CancellationToken, Task<T>> read,
        CancellationToken cancellationToken)
    {
        using var request = CreateRequest(method, path, body);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(callTimeout);
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            return await read(response, timeout.Token);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The Cloudflare KV call exceeded its timeout.", exception);
        }
    }

    private static async Task<(string? Match, int Count)> ReadNamespacePageAsync(
        string title,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        using var document = await ReadEnvelopeAsync(response, cancellationToken);
        if (!response.IsSuccessStatusCode || !TrySuccess(document, out var success) || !success)
            throw CloudflareFailure(response.StatusCode, document);
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("result", out var entries) ||
            entries.ValueKind != JsonValueKind.Array)
            throw new CloudflareKvException(
                response.StatusCode,
                "The Cloudflare KV namespace listing did not carry a result array.",
                []);
        string? match = null;
        var count = 0;
        foreach (var entry in entries.EnumerateArray())
        {
            count++;
            if (match is not null) continue;
            if (entry.ValueKind == JsonValueKind.Object &&
                entry.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String &&
                entry.TryGetProperty("title", out var entryTitle) && entryTitle.ValueKind == JsonValueKind.String &&
                string.Equals(entryTitle.GetString(), title, StringComparison.Ordinal))
                match = id.GetString();
        }

        return (match, count);
    }

    private static async Task<(IReadOnlyList<string> Names, string? Cursor)> ReadKeysPageAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            var failure = await ReadNamespaceNotFoundAsync(response, cancellationToken);
            if (failure is not null) throw failure;
        }

        using var document = await ReadEnvelopeAsync(response, cancellationToken);
        if (!response.IsSuccessStatusCode || !TrySuccess(document, out var success) || !success)
            throw CloudflareFailure(response.StatusCode, document);
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("result", out var entries) ||
            entries.ValueKind != JsonValueKind.Array)
            throw new CloudflareKvException(
                response.StatusCode,
                "The Cloudflare KV key listing did not carry a result array.",
                []);
        var names = new List<string>();
        foreach (var entry in entries.EnumerateArray())
        {
            if (entry.ValueKind == JsonValueKind.Object &&
                entry.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.String)
                names.Add(name.GetString()!);
        }

        string? cursor = null;
        if (document.RootElement.TryGetProperty("result_info", out var info) &&
            info.ValueKind == JsonValueKind.Object &&
            info.TryGetProperty("cursor", out var next) && next.ValueKind == JsonValueKind.String)
            cursor = next.GetString();
        return (names, string.IsNullOrEmpty(cursor) ? null : cursor);
    }

    private static async Task<object?> ReadEnvelopeSuccessAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            var failure = await ReadNamespaceNotFoundAsync(response, cancellationToken);
            if (failure is not null) throw failure;
        }

        using var document = await ReadEnvelopeAsync(response, cancellationToken);
        if (!response.IsSuccessStatusCode || !TrySuccess(document, out var success) || !success)
            throw CloudflareFailure(response.StatusCode, document);
        return null;
    }

    private static async Task<string?> ReadValueAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            var failure = await ReadNamespaceNotFoundAsync(response, cancellationToken);
            if (failure is not null) throw failure;
            return null;
        }

        if (!response.IsSuccessStatusCode)
        {
            using var document = await ReadEnvelopeAsync(response, cancellationToken);
            throw CloudflareFailure(response.StatusCode, document);
        }

        var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var bytes = await ReadBoundedAsync(stream, MaximumResponseBytes, cancellationToken);
        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>
    /// Classifies a 404 by its error envelope: a "namespace not found" class failure is a stale
    /// or misconfigured namespace id; anything else — including an unparseable body — is a
    /// plainly absent key.
    /// </summary>
    private static async Task<CloudflareKvNamespaceNotFoundException?> ReadNamespaceNotFoundAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        try
        {
            using var document = await ReadEnvelopeAsync(response, cancellationToken);
            var errors = ReadErrors(document, out _);
            return errors.Any(error =>
                    error.Message.Contains("namespace not found", StringComparison.OrdinalIgnoreCase))
                ? new CloudflareKvNamespaceNotFoundException(response.StatusCode, errors)
                : null;
        }
        catch (CloudflareKvException)
        {
            return null;
        }
    }

    private static CloudflareKvException CloudflareFailure(HttpStatusCode status, JsonDocument document)
    {
        var errors = ReadErrors(document, out var message);
        return new(status, $"The Cloudflare KV call failed ({(int)status} {status}): {message}", errors);
    }

    private static async Task<JsonDocument> ReadEnvelopeAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var bytes = await ReadBoundedAsync(stream, MaximumResponseBytes, cancellationToken);
        try
        {
            return JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
        }
        catch (JsonException exception)
        {
            throw new CloudflareKvException(
                response.StatusCode,
                $"The Cloudflare KV response was not a valid envelope ({(int)response.StatusCode} {response.StatusCode}).",
                [],
                exception);
        }
    }

    private static bool TrySuccess(JsonDocument document, out bool success)
    {
        success = false;
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("success", out var value) ||
            value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            return false;
        success = value.GetBoolean();
        return true;
    }

    private static IReadOnlyList<CloudflareKvError> ReadErrors(JsonDocument document, out string message)
    {
        message = string.Empty;
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("errors", out var errors) ||
            errors.ValueKind != JsonValueKind.Array)
            return [];
        var result = new List<CloudflareKvError>();
        foreach (var error in errors.EnumerateArray())
        {
            if (error.ValueKind != JsonValueKind.Object ||
                !error.TryGetProperty("code", out var code) || code.ValueKind != JsonValueKind.Number ||
                !code.TryGetInt32(out var errorCode) ||
                !error.TryGetProperty("message", out var text) || text.ValueKind != JsonValueKind.String)
                continue;
            result.Add(new(errorCode, text.GetString() ?? string.Empty));
        }

        message = string.Join("; ", result.Select(static error => $"{error.Code} - {error.Message}"));
        return result;
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
                throw new CloudflareKvException(null, "The Cloudflare KV response exceeded its bound.", []);
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }
}
