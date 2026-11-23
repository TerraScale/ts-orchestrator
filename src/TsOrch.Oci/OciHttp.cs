using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Oci;

internal static class OciHttp
{
    private const int MaxErrorBodyChars = 512;

    public static async Task<Result<T, NotFound, Forbidden, Unavailable, InternalFailure>> SendJsonAsync<T>(
        HttpClient httpClient,
        HttpRequestMessage request,
        JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken)
        where T : notnull
    {
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return await FailureAsync<T>(request, response, cancellationToken);
            }

            await using var body = await response.Content.ReadAsStreamAsync(cancellationToken);
            return await JsonSerializer.DeserializeAsync(body, typeInfo, cancellationToken) is { } document
                ? document
                : new InternalFailure($"{Describe(request)} returned an empty JSON document.");
        }
        catch (HttpRequestException exception)
        {
            return new Unavailable($"{Describe(request)} failed: {exception.Message}");
        }
        catch (JsonException exception)
        {
            return new InternalFailure($"{Describe(request)} returned malformed JSON: {exception.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new Unavailable($"{Describe(request)} timed out.");
        }
    }

    public static async Task<Result<string, NotFound, Forbidden, Unavailable, InternalFailure>> SendTextAsync(
        HttpClient httpClient,
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            return response.IsSuccessStatusCode
                ? await response.Content.ReadAsStringAsync(cancellationToken)
                : await FailureAsync<string>(request, response, cancellationToken);
        }
        catch (HttpRequestException exception)
        {
            return new Unavailable($"{Describe(request)} failed: {exception.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new Unavailable($"{Describe(request)} timed out.");
        }
    }

    private static async Task<Result<T, NotFound, Forbidden, Unavailable, InternalFailure>> FailureAsync<T>(
        HttpRequestMessage request,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var detail = body.Length > MaxErrorBodyChars ? body[..MaxErrorBodyChars] : body;
        var message = $"{Describe(request)} returned {(int)response.StatusCode}: {detail}";
        return (int)response.StatusCode switch
        {
            404 => new NotFound(message),
            401 or 403 => new Forbidden(message),
            429 or >= 500 => new Unavailable(message),
            _ => new InternalFailure(message),
        };
    }

    private static string Describe(HttpRequestMessage request) =>
        $"OCI {request.Method.Method} {request.RequestUri?.GetLeftPart(UriPartial.Path)}";
}
