using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Oci;

internal sealed record class OciPayload(string Body);

internal sealed record class OciHttpRejected(HttpStatusCode Status, string Message);

internal sealed record class OciConnectionLost(Uri? Endpoint, string Message);

internal sealed record class OciResponseTimedOut(Uri? Endpoint);

internal sealed record class OciResponseTooLarge(int Limit)
{
    public string Message => string.Create(CultureInfo.InvariantCulture, $"OCI response exceeds {Limit} bytes.");
}

internal readonly union OciHttpExchange(OciPayload, OciHttpRejected, OciConnectionLost, OciResponseTimedOut, OciResponseTooLarge);

internal static class OciHttp
{
    private const int MaxErrorBodyBytes = 512;
    private const int MaxResponseBodyBytes = 1024 * 1024;
    private static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(30);
    private static readonly HttpClient CloudClient = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseProxy = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(10),
    });

    public static async Task<OciHttpExchange> SendAsync(
        HttpClient mockClient,
        OciEnvironment environment,
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var client = environment is OciCloud ? CloudClient : mockClient;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(OperationTimeout);
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if (!response.IsSuccessStatusCode)
            {
                await using var input = await response.Content.ReadAsStreamAsync(deadline.Token);
                var prefix = new byte[MaxErrorBodyBytes];
                var count = await input.ReadAtLeastAsync(prefix, prefix.Length, false, deadline.Token);
                var detail = Encoding.UTF8.GetString(prefix.AsSpan(0, count));
                return new OciHttpRejected(response.StatusCode, $"OCI {request.Method.Method} {request.RequestUri?.GetLeftPart(UriPartial.Path)} returned status {response.StatusCode}: {detail}");
            }

            if (response.Content.Headers.ContentLength > MaxResponseBodyBytes)
            {
                return new OciResponseTooLarge(MaxResponseBodyBytes);
            }

            return await ReadPayloadAsync(response.Content, deadline.Token);
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

    private static async Task<OciHttpExchange> ReadPayloadAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await using var input = await content.ReadAsStreamAsync(cancellationToken);
        using var body = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        while ((read = await input.ReadAsync(buffer, cancellationToken)) != 0)
        {
            if (body.Length + read > MaxResponseBodyBytes)
            {
                return new OciResponseTooLarge(MaxResponseBodyBytes);
            }

            body.Write(buffer.AsSpan(0, read));
        }

        return new OciPayload(Encoding.UTF8.GetString(body.GetBuffer().AsSpan(0, (int)body.Length)));
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
