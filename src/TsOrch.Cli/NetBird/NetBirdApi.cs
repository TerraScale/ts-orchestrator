using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TsOrch.Cli;

internal closed record class NetBirdApiProblem;

internal sealed record class NetBirdRequestRejected(string Operation, HttpStatusCode Status) : NetBirdApiProblem;

internal sealed record class NetBirdApiUnavailable(string Operation) : NetBirdApiProblem;

internal sealed record class NetBirdResponseInvalid(string Operation) : NetBirdApiProblem;

internal sealed record class NetBirdInstance(bool SetupRequired);

internal readonly union NetBirdRequest(JsonElement, NetBirdApiProblem);

internal readonly union NetBirdInstanceLookup(NetBirdInstance, NetBirdApiProblem);

internal sealed class NetBirdApi(Uri baseUrl, TimeProvider timeProvider) : IDisposable
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(15);
    private readonly HttpClient _http = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
    })
    {
        Timeout = Timeout.InfiniteTimeSpan,
    };

    public NetBirdCredential? Token { private get; set; }

    public void Dispose() => _http.Dispose();

    public async Task<NetBirdInstanceLookup> GetInstanceAsync(CancellationToken cancellationToken)
    {
        var outcome = await SendAsync(HttpMethod.Get, "/api/instance", null, cancellationToken);
        return outcome switch
        {
            JsonElement document => NetBirdJson.Boolean(document, "setup_required") is { } required
                ? new NetBirdInstance(required)
                : (NetBirdInstanceLookup)new NetBirdResponseInvalid("GET /api/instance"),
            NetBirdApiProblem problem => problem,
        };
    }

    public async Task<NetBirdRequest> SendAsync(HttpMethod method, string path, JsonObject? body, CancellationToken cancellationToken)
    {
        var operation = $"{method} {path}";
        using var request = new HttpRequestMessage(method, new Uri(baseUrl, path));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (Token is { } token)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Token", token.Value);
        }

        if (body is not null)
        {
            request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        }

        using var deadline = new CancellationTokenSource(RequestTimeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token);
            if (response.IsSuccessStatusCode is false)
            {
                return new NetBirdRequestRejected(operation, response.StatusCode);
            }

            if (method == HttpMethod.Delete)
            {
                return default(JsonElement);
            }

            await using var content = await response.Content.ReadAsStreamAsync(linked.Token);
            using var document = await JsonDocument.ParseAsync(content, cancellationToken: linked.Token);
            return document.RootElement.Clone();
        }
        catch (HttpRequestException)
        {
            return new NetBirdApiUnavailable(operation);
        }
        catch (IOException)
        {
            return new NetBirdApiUnavailable(operation);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested is false)
        {
            return new NetBirdApiUnavailable(operation);
        }
        catch (JsonException)
        {
            return new NetBirdResponseInvalid(operation);
        }
    }

    public static CliDiagnostic Describe(NetBirdApiProblem problem) => problem switch
    {
        NetBirdRequestRejected { Status: HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden } rejected => CliDiagnostic.Permission(
            string.Create(CultureInfo.InvariantCulture, $"NetBird {rejected.Operation} returned HTTP {(int)rejected.Status}.")),
        NetBirdRequestRejected rejected => CliDiagnostic.Unavailable(
            string.Create(CultureInfo.InvariantCulture, $"NetBird {rejected.Operation} returned HTTP {(int)rejected.Status}.")),
        NetBirdApiUnavailable failure => CliDiagnostic.Unavailable($"NetBird {failure.Operation} is unavailable."),
        NetBirdResponseInvalid invalid => CliDiagnostic.Unavailable($"NetBird {invalid.Operation} returned an invalid response."),
    };

    public static Uri? ParseUrl(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var url)
        && (url.Scheme == "https" || (url.Scheme == "http" && url.IsLoopback))
        && url.UserInfo.Length == 0 && url.AbsolutePath == "/" && url.Query.Length == 0 && url.Fragment.Length == 0
            ? url
            : null;
}

internal static class NetBirdJson
{
    public static JsonElement Property(JsonElement owner, string name) =>
        owner.ValueKind == JsonValueKind.Object && owner.TryGetProperty(name, out var value) ? value : default;

    public static string? Text(JsonElement owner, string name) => Text(Property(owner, name));

    public static string? Text(JsonElement value) =>
        value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 } text ? text : null;

    public static bool? Boolean(JsonElement owner, string name) => Property(owner, name).ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => null,
    };

    public static int? Number(JsonElement owner, string name) =>
        Property(owner, name) is { ValueKind: JsonValueKind.Number } value && value.TryGetInt32(out var number) ? number : null;

    public static IReadOnlyList<JsonElement> Items(JsonElement array) =>
        array.ValueKind == JsonValueKind.Array ? [.. array.EnumerateArray()] : [];

    public static IReadOnlyList<JsonElement> Items(JsonElement owner, string name) => Items(Property(owner, name));

    public static JsonArray Strings(IEnumerable<string> values)
    {
        var array = new JsonArray();
        foreach (var value in values)
        {
            array.Add(value);
        }

        return array;
    }
}
