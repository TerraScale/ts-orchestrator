using System.Net;
using System.Text.Json;

namespace TsOrch.Oci;

public sealed record class DockerRegistryAuth(string HeaderValue);

public sealed record class RegistryAuthDenied(string Host, HttpStatusCode Status, string Message);

public sealed record class RegistryAuthUnavailable(string Host, string Message);

public sealed record class RegistryAuthInvalid(string Host, string Message);

public readonly union RegistryAuthLookup(
    DockerRegistryAuth, RegistryAuthDenied, RegistryAuthUnavailable, RegistryAuthInvalid,
    ImdsRequestRejected, ImdsUnavailable, ImdsDocumentInvalid,
    InvalidFederationCredentials, FederationRejected, FederationUnavailable, FederationTokenInvalid);

public sealed class OciRegistryAuthClient(
    HttpClient httpClient,
    OciEnvironment environment,
    OciInstancePrincipal principal,
    TimeProvider timeProvider) : IDisposable
{
    private const string OciRegistrySuffix = ".ocir.io";
    private const string BearerUsername = "BEARER_TOKEN";
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(1);
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromMinutes(5);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, CachedRegistryAuth> _cache = [with(StringComparer.OrdinalIgnoreCase)];

    public static string? ExtractOciRegistryHost(string image)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(image);
        var slash = image.IndexOf('/');
        if (slash <= 0)
        {
            return null;
        }

        var host = image[..slash];
        if (!host.EndsWith(OciRegistrySuffix, StringComparison.OrdinalIgnoreCase) || host.Length <= OciRegistrySuffix.Length)
        {
            return null;
        }

        var region = host[..^OciRegistrySuffix.Length];
        return IsRegionToken(region) ? host.ToLowerInvariant() : null;
    }

    public static string? RewriteForRegion(string image, string ociRegion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(image);
        if (!IsRegionToken(ociRegion) || !image.Contains("@sha256:", StringComparison.Ordinal))
        {
            return null;
        }

        if (ExtractOciRegistryHost(image) is not { } currentHost)
        {
            return null;
        }

        var targetHost = $"{ociRegion.ToLowerInvariant()}{OciRegistrySuffix}";
        if (string.Equals(currentHost, targetHost, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var slash = image.IndexOf('/');
        return $"{targetHost}{image[slash..]}";
    }

    public async Task<RegistryAuthLookup> GetDockerAuthHeaderAsync(string host, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_cache.TryGetValue(host, out var cached) && cached.RefreshAt > timeProvider.GetUtcNow())
            {
                return new DockerRegistryAuth(cached.HeaderValue);
            }

            var fetched = await FetchTokenAsync(host, cancellationToken);
            if (fetched is CachedRegistryAuth fresh)
            {
                _cache[host] = fresh;
                return new DockerRegistryAuth(fresh.HeaderValue);
            }

            return fetched switch
            {
                RegistryAuthDenied denied => denied,
                RegistryAuthUnavailable unavailable => unavailable,
                RegistryAuthInvalid invalid => invalid,
                ImdsRequestRejected rejected => rejected,
                ImdsUnavailable unavailable => unavailable,
                ImdsDocumentInvalid invalid => invalid,
                InvalidFederationCredentials invalid => invalid,
                FederationRejected rejected => rejected,
                FederationUnavailable unavailable => unavailable,
                FederationTokenInvalid invalid => invalid,
                _ => new RegistryAuthUnavailable(host, "Unexpected OCIR token lookup state."),
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task InvalidateHostAsync(string host, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            _cache.Remove(host);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();

    private async Task<TokenFetchOutcome> FetchTokenAsync(string host, CancellationToken cancellationToken)
    {
        var uri = environment switch
        {
            OciMock mock => new Uri(mock.BaseUrl, "20180419/docker/token"),
            OciCloud => new Uri($"https://{host}/20180419/docker/token"),
        };

        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            var authorization = await principal.AuthorizeAsync(request, cancellationToken);
            if (authorization is not OciRequestSigned)
            {
                return authorization switch
                {
                    ImdsRequestRejected rejected => rejected,
                    ImdsUnavailable unavailable => unavailable,
                    ImdsDocumentInvalid invalid => invalid,
                    InvalidFederationCredentials invalid => invalid,
                    FederationRejected rejected => rejected,
                    FederationUnavailable unavailable => unavailable,
                    FederationTokenInvalid invalid => invalid,
                    _ => new RegistryAuthUnavailable(host, "Unexpected OCI authorization state."),
                };
            }

            var response = await OciHttp.SendAsync(httpClient, request, cancellationToken);
            if (response is OciHttpRejected { Status: HttpStatusCode.Unauthorized } && attempt == 0)
            {
                await principal.InvalidateSessionAsync(cancellationToken);
                continue;
            }

            return response switch
            {
                OciPayload payload => Decode(payload.Body, host),
                OciHttpRejected { Status: HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden } rejected => new RegistryAuthDenied(host, rejected.Status, rejected.Message),
                OciHttpRejected { Status: HttpStatusCode.TooManyRequests or >= HttpStatusCode.InternalServerError } rejected => new RegistryAuthUnavailable(host, rejected.Message),
                OciHttpRejected rejected => new RegistryAuthInvalid(host, rejected.Message),
                OciConnectionLost lost => new RegistryAuthUnavailable(host, lost.Message),
                OciResponseTimedOut => new RegistryAuthUnavailable(host, $"OCIR token request to {host} timed out."),
            };
        }

        return new RegistryAuthUnavailable(host, $"OCIR token request to {host} exhausted retries.");
    }

    private TokenFetchOutcome Decode(string payload, string host)
    {
        var document = OciHttp.Decode(payload, OciJsonContext.Default.OciDockerTokenDocument, out var error);
        if (document is null || string.IsNullOrWhiteSpace(document.Token))
        {
            return new RegistryAuthInvalid(host, error ?? $"OCIR token response from {host} returned no token.");
        }

        var authJson = JsonSerializer.SerializeToUtf8Bytes(
            new DockerRegistryAuthDocument(BearerUsername, document.Token),
            OciJsonContext.Default.DockerRegistryAuthDocument);
        var lifetime = document.ExpiresIn is { } seconds
            ? TimeSpan.FromSeconds(Math.Clamp(seconds, 60, 3600))
            : DefaultLifetime;
        var margin = lifetime > TimeSpan.FromMinutes(10) ? RefreshMargin : TimeSpan.FromTicks(lifetime.Ticks / 4);
        return new CachedRegistryAuth(Convert.ToBase64String(authJson), timeProvider.GetUtcNow() + lifetime - margin);
    }

    private static bool IsRegionToken(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value[0] == '-' || value[^1] == '-')
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (!char.IsAsciiLetterOrDigit(ch) && ch != '-')
            {
                return false;
            }
        }

        return true;
    }

    private sealed record class CachedRegistryAuth(string HeaderValue, DateTimeOffset RefreshAt);

    private readonly union TokenFetchOutcome(
        CachedRegistryAuth, RegistryAuthDenied, RegistryAuthUnavailable, RegistryAuthInvalid,
        ImdsRequestRejected, ImdsUnavailable, ImdsDocumentInvalid,
        InvalidFederationCredentials, FederationRejected, FederationUnavailable, FederationTokenInvalid);
}
