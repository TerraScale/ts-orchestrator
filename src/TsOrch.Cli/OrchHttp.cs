using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Cli;

internal closed record class BackplaneProblem;

internal sealed record class BackplaneRequestRejected(HttpStatusCode Status, string Message) : BackplaneProblem;

internal sealed record class BackplaneTransportFailed(string Message) : BackplaneProblem;

internal sealed record class BackplaneResponseInvalid(string Message) : BackplaneProblem;

internal sealed record class BackplaneAuthenticationFailed(CliDiagnostic Diagnostic) : BackplaneProblem;

internal readonly record struct BackplaneStreamCompleted;

internal readonly union BackplaneText(string, BackplaneProblem);

internal readonly union BackplaneStream(BackplaneStreamCompleted, BackplaneProblem);

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

    public async Task<TOutput> SendJsonAsync<T, TOutput>(
        HttpRequestMessage request,
        JsonTypeInfo<T> typeInfo,
        TimeSpan timeout,
        Func<T, Task<TOutput>> handle,
        Func<BackplaneProblem, TOutput> fail,
        CancellationToken cancellationToken)
        where T : class
    {
        var outcome = await SendTextAsync(request, timeout, cancellationToken);
        return outcome switch
        {
            string body => await HandleJsonAsync(body, Describe(request), typeInfo, handle, fail, cancellationToken),
            BackplaneProblem problem => fail(problem),
        };
    }

    private static async Task<TOutput> HandleJsonAsync<T, TOutput>(
        string body,
        string target,
        JsonTypeInfo<T> typeInfo,
        Func<T, Task<TOutput>> handle,
        Func<BackplaneProblem, TOutput> fail,
        CancellationToken cancellationToken)
        where T : class
    {
        cancellationToken.ThrowIfCancellationRequested();
        var value = Decode(body, typeInfo, out var error);
        return value is not null
            ? await handle(value)
            : fail(new BackplaneResponseInvalid($"{target} returned invalid JSON: {error}"));
    }

    internal static T? Decode<T>(string body, JsonTypeInfo<T> typeInfo, out string? error) where T : class
    {
        try
        {
            var value = JsonSerializer.Deserialize(body, typeInfo);
            error = value is null ? "The document is null." : null;
            return value;
        }
        catch (JsonException exception)
        {
            error = exception.Message;
            return null;
        }
    }

    public async Task<BackplaneText> SendTextAsync(HttpRequestMessage request, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var deadline = new CancellationTokenSource(timeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token);
            return response.IsSuccessStatusCode
                ? await response.Content.ReadAsStringAsync(linked.Token)
                : await ReadRejectionAsync(request, response, linked.Token);
        }
        catch (HttpRequestException exception)
        {
            return new BackplaneTransportFailed($"{Describe(request)} failed: {exception.Message}");
        }
        catch (IOException exception)
        {
            return new BackplaneTransportFailed($"{Describe(request)} broke off: {exception.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new BackplaneTransportFailed(string.Create(CultureInfo.InvariantCulture, $"{Describe(request)} timed out after {timeout.TotalSeconds:F0}s."));
        }
    }

    public async Task<BackplaneStream> StreamJsonLinesAsync<T>(
        HttpRequestMessage request,
        JsonTypeInfo<T> typeInfo,
        Func<T, CancellationToken, Task> onItem,
        CancellationToken cancellationToken)
        where T : class
    {
        var opened = await OpenStreamAsync(request, cancellationToken);
        return opened switch
        {
            OpenBackplaneStream stream => await ReadLinesAsync(request, stream, typeInfo, onItem, cancellationToken),
            BackplaneProblem problem => problem,
        };
    }

    private async Task<BackplaneStreamOpening> OpenStreamAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        HttpResponseMessage? response = null;
        try
        {
            response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return await ReadRejectionAsync(request, response, cancellationToken);
            }

            var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            var opened = new OpenBackplaneStream(response, new StreamReader(stream));
            response = null;
            return opened;
        }
        catch (HttpRequestException exception)
        {
            return new BackplaneTransportFailed($"{Describe(request)} failed: {exception.Message}");
        }
        catch (IOException exception)
        {
            return new BackplaneTransportFailed($"{Describe(request)} broke off: {exception.Message}");
        }
        finally
        {
            response?.Dispose();
        }
    }

    private static async Task<BackplaneStream> ReadLinesAsync<T>(
        HttpRequestMessage request,
        OpenBackplaneStream opened,
        JsonTypeInfo<T> typeInfo,
        Func<T, CancellationToken, Task> onItem,
        CancellationToken cancellationToken)
        where T : class
    {
        using var response = opened.Response;
        using var reader = opened.Reader;
        while (true)
        {
            var read = await ReadLineAsync(reader, cancellationToken);
            var readLine = read switch
            {
                BackplaneStreamLine item => new StreamLineRead(item.Text, null),
                BackplaneTransportFailed failed => new StreamLineRead(null, failed),
            };
            if (readLine.Failure is { } failure)
            {
                return new BackplaneTransportFailed($"{Describe(request)} broke off: {failure.Message}");
            }

            if (readLine.Text is not { } line)
            {
                return new BackplaneStreamCompleted();
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (Decode(line, typeInfo, out var error) is not { } itemValue)
            {
                return new BackplaneResponseInvalid($"{Describe(request)} streamed invalid JSON: {error}");
            }

            await onItem(itemValue, cancellationToken);
        }
    }

    private static async Task<BackplaneLineRead> ReadLineAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        try
        {
            return new BackplaneStreamLine(await reader.ReadLineAsync(cancellationToken));
        }
        catch (IOException exception)
        {
            return new BackplaneTransportFailed(exception.Message);
        }
    }

    private static async Task<BackplaneRequestRejected> ReadRejectionAsync(
        HttpRequestMessage request,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var message = Decode(body, ApiJsonContext.Default.ErrorResponse, out _)?.Error switch
        {
            { Fix: { } fix } detail => $"{detail.Message} ({fix})",
            { } detail => detail.Message,
            null => string.Create(CultureInfo.InvariantCulture,
                $"{Describe(request)} returned {(int)response.StatusCode}: {(body.Length > MaxErrorBodyChars ? body[..MaxErrorBodyChars] : body)}"),
        };
        return new BackplaneRequestRejected(response.StatusCode, message);
    }

    private static string Describe(HttpRequestMessage request) =>
        $"{request.Method.Method} {request.RequestUri?.GetLeftPart(UriPartial.Path)}";

    private sealed record class OpenBackplaneStream(HttpResponseMessage Response, StreamReader Reader);

    private sealed record class BackplaneStreamLine(string? Text);

    private sealed record class StreamLineRead(string? Text, BackplaneTransportFailed? Failure);

    private readonly union BackplaneStreamOpening(OpenBackplaneStream, BackplaneProblem);

    private readonly union BackplaneLineRead(BackplaneStreamLine, BackplaneTransportFailed);
}
