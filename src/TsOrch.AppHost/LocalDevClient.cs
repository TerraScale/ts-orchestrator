using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.AppHost;

internal sealed record class WorkerFailure(string Message);

internal readonly union WorkerReply(string, WorkerFailure);

internal sealed class LocalDevClient(HttpClient httpClient, TimeProvider timeProvider)
{
    private const string SessionCookie = "ts_orch_session=";
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

    public static HttpClient CreateHttpClient() =>
        new(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false }) { Timeout = TimeSpan.FromSeconds(30) };

    public async Task<WorkerReply> WaitForLocalWorkerAsync(Uri workerUrl, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = timeProvider.GetUtcNow() + timeout;
        var me = new Uri(workerUrl, "/api/me");
        while (true)
        {
            var reply = await SendAsync(new HttpRequestMessage(HttpMethod.Get, me), cancellationToken);
            var ready = reply switch
            {
                string body => LocalDevReady(body),
                WorkerFailure failure => failure,
            };
            var settled = ready switch
            {
                string => true,
                WorkerFailure => timeProvider.GetUtcNow() >= deadline,
            };
            if (settled)
            {
                return ready;
            }

            await Task.Delay(PollInterval, timeProvider, cancellationToken);
        }
    }

    public async Task<WorkerReply> DevLoginAsync(Uri workerUrl, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(workerUrl, "/auth/dev-login"));
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode is not (HttpStatusCode.Found or HttpStatusCode.SeeOther))
            {
                return new WorkerFailure($"GET /auth/dev-login returned {(int)response.StatusCode}; the worker must run with LOCAL_DEV=true on loopback.");
            }

            var cookies = response.Headers.TryGetValues("Set-Cookie", out var values) ? values : [];
            foreach (var cookie in cookies)
            {
                if (cookie.StartsWith(SessionCookie, StringComparison.Ordinal))
                {
                    var end = cookie.IndexOf(';', StringComparison.Ordinal);
                    return end < 0 ? cookie : cookie[..end];
                }
            }

            return new WorkerFailure("GET /auth/dev-login did not set the ts_orch_session cookie.");
        }
        catch (HttpRequestException exception)
        {
            return new WorkerFailure($"GET /auth/dev-login failed: {exception.Message}");
        }
    }

    public Task<WorkerReply> PostJsonAsync<T>(Uri url, T body, JsonTypeInfo<T> typeInfo, string? sessionCookie, CancellationToken cancellationToken) =>
        PostAsync(url, JsonSerializer.Serialize(body, typeInfo), sessionCookie, cancellationToken);

    public Task<WorkerReply> PostAsync(Uri url, string json, string? sessionCookie, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(json, Encoding.UTF8, new MediaTypeHeaderValue("application/json")),
        };
        if (sessionCookie is not null)
        {
            request.Headers.Add("Cookie", sessionCookie);
        }

        return SendAsync(request, cancellationToken);
    }

    private static WorkerReply LocalDevReady(string body)
    {
        try
        {
            return JsonSerializer.Deserialize(body, AppHostJsonContext.Default.MeDocument) switch
            {
                { LocalDev: true } => body,
                { LocalDev: false } => new WorkerFailure("The worker answered /api/me without localDev; start wrangler with LOCAL_DEV=true on 127.0.0.1."),
                null => new WorkerFailure("The worker answered /api/me with JSON null."),
            };
        }
        catch (JsonException exception)
        {
            return new WorkerFailure($"The worker answered /api/me with malformed JSON: {exception.Message}");
        }
    }

    private async Task<WorkerReply> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using (request)
        {
            try
            {
                using var response = await httpClient.SendAsync(request, cancellationToken);
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    return body;
                }

                return new WorkerFailure($"{request.Method.Method} {request.RequestUri?.AbsolutePath} returned {(int)response.StatusCode}: {body}");
            }
            catch (HttpRequestException exception)
            {
                return new WorkerFailure($"{request.Method.Method} {request.RequestUri?.AbsolutePath} failed: {exception.Message}");
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new WorkerFailure($"{request.Method.Method} {request.RequestUri?.AbsolutePath} timed out.");
            }
        }
    }
}
