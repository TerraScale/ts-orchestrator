using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.AppHost;

internal readonly record struct LocalWorkerReady;

internal sealed record class LocalWorkerStartupTimedOut(string Message);

internal sealed record class LocalDevNotEnabled(string Message);

internal sealed record class LocalDevProbeInvalid(string Message);

internal sealed record class LocalWorkerRequestRejected(string Message);

internal sealed record class LocalWorkerAccessDenied(string Message);

internal sealed record class LocalWorkerUnavailable(string Message);

internal readonly union LocalWorkerStartup(LocalWorkerReady, LocalWorkerStartupTimedOut);

internal readonly union LocalDevLogin(string, LocalDevNotEnabled, LocalWorkerUnavailable);

internal readonly union LocalWorkerExchange(string, LocalWorkerRequestRejected, LocalWorkerAccessDenied, LocalWorkerUnavailable);

internal readonly union LocalDevProbe(LocalWorkerReady, LocalDevNotEnabled, LocalDevProbeInvalid);

internal sealed class LocalDevClient(HttpClient httpClient, TimeProvider timeProvider)
{
    private const string SessionCookie = "ts_orch_session=";
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

    public static HttpClient CreateHttpClient() =>
        new(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false }) { Timeout = TimeSpan.FromSeconds(30) };

    public async Task<LocalWorkerStartup> WaitForLocalWorkerAsync(Uri workerUrl, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = timeProvider.GetUtcNow() + timeout;
        var me = new Uri(workerUrl, "/api/me");
        while (true)
        {
            var outcome = await SendAsync(new HttpRequestMessage(HttpMethod.Get, me), cancellationToken);
            var failure = outcome switch
            {
                string body => LocalDevReady(body) switch
                {
                    LocalWorkerReady => null,
                    LocalDevNotEnabled notLocal => notLocal.Message,
                    LocalDevProbeInvalid malformed => malformed.Message,
                },
                LocalWorkerRequestRejected rejected => rejected.Message,
                LocalWorkerAccessDenied denied => denied.Message,
                LocalWorkerUnavailable unavailable => unavailable.Message,
            };
            if (failure is null)
            {
                return new LocalWorkerReady();
            }

            if (timeProvider.GetUtcNow() >= deadline)
            {
                return new LocalWorkerStartupTimedOut(string.Create(
                    CultureInfo.InvariantCulture,
                    $"The local worker at {me} was not ready within {timeout.TotalSeconds:F0}s: {failure}"));
            }

            await Task.Delay(PollInterval, timeProvider, cancellationToken);
        }
    }

    public async Task<LocalDevLogin> DevLoginAsync(Uri workerUrl, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(workerUrl, "/auth/dev-login"));
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode is not (HttpStatusCode.Found or HttpStatusCode.SeeOther))
            {
                return new LocalDevNotEnabled($"GET /auth/dev-login returned {(int)response.StatusCode}; the worker must run with LOCAL_DEV=true on loopback.");
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

            return new LocalDevNotEnabled("GET /auth/dev-login did not set the ts_orch_session cookie.");
        }
        catch (HttpRequestException exception)
        {
            return new LocalWorkerUnavailable($"GET /auth/dev-login failed: {exception.Message}");
        }
    }

    public Task<LocalWorkerExchange> PostJsonAsync<T>(Uri url, T body, JsonTypeInfo<T> typeInfo, string? sessionCookie, CancellationToken cancellationToken) =>
        PostAsync(url, JsonSerializer.Serialize(body, typeInfo), sessionCookie, cancellationToken);

    public Task<LocalWorkerExchange> PostAsync(Uri url, string json, string? sessionCookie, CancellationToken cancellationToken)
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

    private static LocalDevProbe LocalDevReady(string body)
    {
        try
        {
            return JsonSerializer.Deserialize(body, AppHostJsonContext.Default.MeDocument) switch
            {
                { LocalDev: true } => new LocalWorkerReady(),
                { LocalDev: false } => new LocalDevNotEnabled("The worker answered /api/me without localDev; start wrangler with LOCAL_DEV=true on 127.0.0.1."),
                null => new LocalDevProbeInvalid("The worker answered /api/me with JSON null."),
            };
        }
        catch (JsonException exception)
        {
            return new LocalDevProbeInvalid($"The worker answered /api/me with malformed JSON: {exception.Message}");
        }
    }

    private async Task<LocalWorkerExchange> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using (request)
        {
            var target = $"{request.Method.Method} {request.RequestUri?.AbsolutePath}";
            try
            {
                using var response = await httpClient.SendAsync(request, cancellationToken);
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    return body;
                }

                var message = $"{target} returned {(int)response.StatusCode}: {body}";
                if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                {
                    return new LocalWorkerAccessDenied(message);
                }

                if (response.StatusCode is HttpStatusCode.TooManyRequests or >= HttpStatusCode.InternalServerError)
                {
                    return new LocalWorkerUnavailable(message);
                }

                return new LocalWorkerRequestRejected(message);
            }
            catch (HttpRequestException exception)
            {
                return new LocalWorkerUnavailable($"{target} failed: {exception.Message}");
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new LocalWorkerUnavailable($"{target} timed out.");
            }
        }
    }
}
