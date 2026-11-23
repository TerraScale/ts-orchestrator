using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Oci;

internal sealed record class OciPayload(string Body);

internal sealed record class OciHttpRejected(HttpStatusCode Status, string Message);

internal sealed record class OciConnectionLost(Uri? Endpoint, string Message);

internal sealed record class OciResponseTimedOut(Uri? Endpoint);

internal readonly union OciHttpExchange(OciPayload, OciHttpRejected, OciConnectionLost, OciResponseTimedOut);

internal static class OciHttp
{
    private const int MaxErrorBodyChars = 512;
    private static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(30);

    public static async Task<OciHttpExchange> SendAsync(HttpClient httpClient, HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(OperationTimeout);
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            var body = await response.Content.ReadAsStringAsync(deadline.Token);
            if (response.IsSuccessStatusCode)
            {
                return new OciPayload(body);
            }

            var detail = body.Length > MaxErrorBodyChars ? body[..MaxErrorBodyChars] : body;
            return new OciHttpRejected(response.StatusCode, $"OCI {request.Method.Method} {request.RequestUri?.GetLeftPart(UriPartial.Path)} returned status {response.StatusCode}: {detail}");
        }
        catch (HttpRequestException exception)
        {
            return new OciConnectionLost(request.RequestUri, exception.Message);
        }
        catch (IOException exception)
        {
            return new OciConnectionLost(request.RequestUri, exception.Message);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new OciResponseTimedOut(request.RequestUri);
        }
    }

    public static T? Decode<T>(string body, JsonTypeInfo<T> typeInfo, out string? error) where T : class
    {
        try
        {
            var document = JsonSerializer.Deserialize(body, typeInfo);
            error = document is null ? "OCI returned an empty JSON document." : null;
            return document;
        }
        catch (JsonException exception)
        {
            error = exception.Message;
            return null;
        }
    }
}
