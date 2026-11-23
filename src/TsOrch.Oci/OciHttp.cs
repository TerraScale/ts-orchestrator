using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using TsOrch.Protocol;

namespace TsOrch.Oci;

internal static class OciHttp
{
    private const int MaxErrorBodyChars = 512;

    public static async Task<OrchResult<T>> SendJsonAsync<T>(
        HttpClient httpClient,
        HttpRequestMessage request,
        JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken)
    {
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return await ErrorAsync(request, response, cancellationToken);
            }

            await using var body = await response.Content.ReadAsStreamAsync(cancellationToken);
            var document = await JsonSerializer.DeserializeAsync(body, typeInfo, cancellationToken);
            return document is null
                ? new Internal($"{Describe(request)} returned an empty JSON document.")
                : document;
        }
        catch (HttpRequestException exception)
        {
            return new Unavailable($"{Describe(request)} failed: {exception.Message}");
        }
        catch (JsonException exception)
        {
            return new Internal($"{Describe(request)} returned malformed JSON: {exception.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new Unavailable($"{Describe(request)} timed out.");
        }
    }

    public static async Task<OrchResult<string>> SendTextAsync(
        HttpClient httpClient,
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return await ErrorAsync(request, response, cancellationToken);
            }

            return await response.Content.ReadAsStringAsync(cancellationToken);
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

    private static async Task<OrchError> ErrorAsync(
        HttpRequestMessage request,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var detail = body.Length > MaxErrorBodyChars ? body[..MaxErrorBodyChars] : body;
        var message = $"{Describe(request)} returned {(int)response.StatusCode}: {detail}";
        return (int)response.StatusCode switch
        {
            400 => new Validation(message),
            401 => new Unauthorized(message),
            403 => new Forbidden(message),
            404 => new NotFound(message),
            409 => new Conflict(message),
            429 or >= 500 => new Unavailable(message),
            _ => new Internal(message),
        };
    }

    private static string Describe(HttpRequestMessage request) =>
        $"OCI {request.Method.Method} {request.RequestUri?.GetLeftPart(UriPartial.Path)}";
}
