using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
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

    public Task<OrchResult<T>> SendJsonAsync<T>(HttpRequestMessage request, JsonTypeInfo<T> typeInfo, TimeSpan timeout, CancellationToken cancellationToken)
        where T : notnull =>
        SendAsync<T>(
            request,
            timeout,
            async (content, token) => await content.ReadFromJsonAsync(typeInfo, token) is { } value
                ? value
                : new Internal($"{Describe(request)} returned an empty JSON document."),
            cancellationToken);

    public Task<OrchResult<string>> SendTextAsync(HttpRequestMessage request, TimeSpan timeout, CancellationToken cancellationToken) =>
        SendAsync<string>(request, timeout, async (content, token) => await content.ReadAsStringAsync(token), cancellationToken);

    public Task<OrchResult<Done>> StreamJsonLinesAsync<T>(
        HttpRequestMessage request,
        JsonTypeInfo<T> typeInfo,
        Func<T, CancellationToken, Task> onItem,
        CancellationToken cancellationToken)
        where T : notnull =>
        SendAsync<Done>(
            request,
            Timeout.InfiniteTimeSpan,
            async (content, token) =>
            {
                await using var stream = await content.ReadAsStreamAsync(token);
                using var reader = new StreamReader(stream);
                while (await reader.ReadLineAsync(token) is { } line)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    if (JsonSerializer.Deserialize(line, typeInfo) is not { } item)
                    {
                        return new Internal($"{Describe(request)} streamed an empty JSON line.");
                    }

                    await onItem(item, token);
                }

                return new Done();
            },
            cancellationToken);

    private async Task<OrchResult<T>> SendAsync<T>(
        HttpRequestMessage request,
        TimeSpan timeout,
        Func<HttpContent, CancellationToken, Task<OrchResult<T>>> read,
        CancellationToken cancellationToken)
        where T : notnull
    {
        using var deadline = new CancellationTokenSource(timeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token);
            return response.IsSuccessStatusCode
                ? await read(response.Content, linked.Token)
                : await FailureAsync(request, response, linked.Token);
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
            return new Internal($"{Describe(request)} returned malformed JSON: {exception.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new Unavailable(string.Create(CultureInfo.InvariantCulture, $"{Describe(request)} timed out after {timeout.TotalSeconds:F0}s."));
        }
    }

    private static async Task<OrchError> FailureAsync(HttpRequestMessage request, HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var status = (int)response.StatusCode;
        var detail = ParseError(body);
        var message = detail switch
        {
            { Fix: { } fix } => $"{detail.Message} ({fix})",
            { } => detail.Message,
            null => string.Create(
                CultureInfo.InvariantCulture,
                $"{Describe(request)} returned {status}: {(body.Length > MaxErrorBodyChars ? body[..MaxErrorBodyChars] : body)}"),
        };
        return detail?.Code switch
        {
            "not_found" => new NotFound(message),
            "validation" => new Validation(message),
            "conflict" => new Conflict(message),
            "forbidden" => new Forbidden(message),
            "unauthorized" => new Unauthorized(message),
            "unavailable" => new Unavailable(message),
            "internal" => new Internal(message),
            _ => response.StatusCode switch
            {
                HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => new Validation(message),
                HttpStatusCode.Unauthorized => new Unauthorized(message),
                HttpStatusCode.Forbidden => new Forbidden(message),
                HttpStatusCode.NotFound => new NotFound(message),
                HttpStatusCode.Conflict => new Conflict(message),
                HttpStatusCode.TooManyRequests or >= HttpStatusCode.InternalServerError => new Unavailable(message),
                _ => new Internal(message),
            },
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
