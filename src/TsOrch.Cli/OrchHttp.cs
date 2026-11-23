using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Cli;

internal sealed class OrchHttp(HttpClient httpClient, TimeProvider timeProvider)
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    private const int MaxErrorBodyChars = 512;
    private static readonly MediaTypeWithQualityHeaderValue JsonMediaType = new("application/json");

    public static HttpRequestMessage CreateRequest(HttpMethod method, Uri baseUrl, string pathAndQuery, string? token, HttpContent? content)
    {
        ArgumentNullException.ThrowIfNull(baseUrl);
        var request = new HttpRequestMessage(method, new Uri(baseUrl, pathAndQuery)) { Content = content };
        request.Headers.Accept.Add(JsonMediaType);
        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return request;
    }

    public static HttpContent JsonBody<T>(T value, JsonTypeInfo<T> typeInfo) => JsonContent.Create(value, typeInfo);

    public Task<Result<T, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> SendJsonAsync<T>(
        HttpRequestMessage request,
        JsonTypeInfo<T> typeInfo,
        TimeSpan timeout,
        CancellationToken cancellationToken)
        where T : notnull =>
        SendAsync(request, timeout, (content, token) => content.ReadFromJsonAsync(typeInfo, token), cancellationToken);

    public Task<Result<string, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> SendTextAsync(
        HttpRequestMessage request,
        TimeSpan timeout,
        CancellationToken cancellationToken) =>
        SendAsync<string>(request, timeout, async (content, token) => await content.ReadAsStringAsync(token), cancellationToken);

    public async Task<Result<Done, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> StreamJsonLinesAsync<T>(
        HttpRequestMessage request,
        JsonTypeInfo<T> typeInfo,
        Func<T, CancellationToken, Task> onItem,
        CancellationToken cancellationToken)
        where T : notnull
    {
        ArgumentNullException.ThrowIfNull(onItem);
        HttpResponseMessage response;
        try
        {
            response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                using (response)
                {
                    return await FailureAsync<Done>(request, response, cancellationToken);
                }
            }
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException)
        {
            return new Unavailable($"{Describe(request)} failed: {exception.Message}");
        }

        using (response)
        {
            return await ReadLinesAsync(request, response.Content, typeInfo, onItem, cancellationToken) switch
            {
                Done done => done,
                Unavailable failure => failure,
            };
        }
    }

    private static async Task<Result<Done, Unavailable>> ReadLinesAsync<T>(
        HttpRequestMessage request,
        HttpContent content,
        JsonTypeInfo<T> typeInfo,
        Func<T, CancellationToken, Task> onItem,
        CancellationToken cancellationToken)
        where T : notnull
    {
        Stream stream;
        try
        {
            stream = await content.ReadAsStreamAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException)
        {
            return new Unavailable($"{Describe(request)} broke off: {exception.Message}");
        }

        await using (stream)
        {
            using var reader = new StreamReader(stream);
            while (true)
            {
                string? line;
                try
                {
                    line = await reader.ReadLineAsync(cancellationToken);
                }
                catch (Exception exception) when (exception is HttpRequestException or IOException)
                {
                    return new Unavailable($"{Describe(request)} broke off: {exception.Message}");
                }

                if (line is null)
                {
                    return new Done();
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                T? item;
                try
                {
                    item = JsonSerializer.Deserialize(line, typeInfo);
                }
                catch (JsonException exception)
                {
                    return new Unavailable($"{Describe(request)} streamed malformed JSON: {exception.Message}");
                }

                if (item is null)
                {
                    return new Unavailable($"{Describe(request)} streamed an empty JSON line.");
                }

                await onItem(item, cancellationToken);
            }
        }
    }

    private async Task<Result<T, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> SendAsync<T>(
        HttpRequestMessage request,
        TimeSpan timeout,
        Func<HttpContent, CancellationToken, Task<T?>> read,
        CancellationToken cancellationToken)
        where T : notnull
    {
        using var deadline = new CancellationTokenSource(timeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token);
            if (!response.IsSuccessStatusCode)
            {
                return await FailureAsync<T>(request, response, linked.Token);
            }

            return await read(response.Content, linked.Token) is { } value
                ? value
                : new Unavailable($"{Describe(request)} returned an empty JSON document.");
        }
        catch (HttpRequestException exception)
        {
            return new Unavailable($"{Describe(request)} failed: {exception.Message}");
        }
        catch (IOException exception)
        {
            return new Unavailable($"{Describe(request)} broke off: {exception.Message}");
        }
        catch (JsonException exception)
        {
            return new Unavailable($"{Describe(request)} returned malformed JSON: {exception.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new Unavailable(string.Create(CultureInfo.InvariantCulture, $"{Describe(request)} timed out after {timeout.TotalSeconds:F0}s."));
        }
    }

    private static async Task<Result<T, Validation, NotFound, Conflict, Unauthorized, Forbidden, Unavailable>> FailureAsync<T>(
        HttpRequestMessage request,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var status = (int)response.StatusCode;
        var message = ParseError(body) switch
        {
            { Fix: { } fix } detail => $"{detail.Message} ({fix})",
            { } detail => detail.Message,
            null => string.Create(
                CultureInfo.InvariantCulture,
                $"{Describe(request)} returned {status}: {(body.Length > MaxErrorBodyChars ? body[..MaxErrorBodyChars] : body)}"),
        };
        return status switch
        {
            400 or 422 => new Validation(message),
            401 => new Unauthorized(message),
            403 => new Forbidden(message),
            404 => new NotFound(message),
            409 => new Conflict(message),
            429 or >= 500 => new Unavailable(message),
            _ => new Unavailable(string.Create(CultureInfo.InvariantCulture, $"{Describe(request)} returned unexpected {status}: {message}")),
        };
    }

    private static ErrorDetail? ParseError(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(body, ApiJsonContext.Default.ErrorResponse)?.Error;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string Describe(HttpRequestMessage request) =>
        $"{request.Method.Method} {request.RequestUri?.GetLeftPart(UriPartial.Path)}";
}
