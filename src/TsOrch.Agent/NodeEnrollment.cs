using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace TsOrch.Agent;

public sealed record class NodeSession(HostIdentity Identity, string NodeId, string Token, Uri WebSocketUrl)
{
    public override string ToString() => $"{nameof(NodeSession)} {{ NodeId = {NodeId}, WebSocketUrl = {WebSocketUrl} }}";
}

public sealed class NodeEnrollment(
    IHostIdentityProvider identityProvider,
    ISecretProvider secretProvider,
    IHttpClientFactory httpClientFactory,
    IOptions<AgentOptions> options,
    ILogger<NodeEnrollment> logger)
{
    public const string BackplaneClientName = "ts-orch-backplane";

    private readonly AgentOptions _options = options.Value;

    public async Task<OrchResult<NodeSession>> EnsureEnrolledAsync(CancellationToken cancellationToken)
    {
        var resolved = await identityProvider.ResolveIdentityAsync(cancellationToken);
        if (!resolved.TryGetValue(out var discovered, out var identityError))
        {
            return identityError;
        }

        var identity = discovered with
        {
            InstanceId = _options.NodeIdOverride ?? discovered.InstanceId,
            Region = _options.RegionOverride ?? discovered.Region,
            PoolKind = _options.PoolKindOverride ?? discovered.PoolKind,
            VcnIp = _options.VcnIpOverride ?? discovered.VcnIp,
        };
        if (await LoadAsync(identity, cancellationToken) is { } stored)
        {
            logger.EnrollmentLoaded(stored.NodeId);
            return stored;
        }

        return await EnrollAsync(identity, cancellationToken);
    }

    public void Forget()
    {
        File.Delete(_options.NodeTokenFile);
        File.Delete(_options.NodeStateFile);
        logger.CredentialsForgotten();
    }

    private async Task<NodeSession?> LoadAsync(HostIdentity identity, CancellationToken cancellationToken)
    {
        if (!File.Exists(_options.NodeTokenFile) || !File.Exists(_options.NodeStateFile))
        {
            return null;
        }

        var token = (await File.ReadAllTextAsync(_options.NodeTokenFile, cancellationToken)).Trim();
        try
        {
            await using var stream = File.OpenRead(_options.NodeStateFile);
            var registration = await JsonSerializer.DeserializeAsync(stream, AgentJsonContext.Default.NodeRegistration, cancellationToken);
            if (token.Length == 0 || registration is null)
            {
                logger.EnrollmentStateCorrupt($"{_options.NodeTokenFile} or {_options.NodeStateFile} is empty.");
                return null;
            }

            return new NodeSession(identity, registration.NodeId, token, ResolveWebSocketUrl(registration.WsUrl));
        }
        catch (JsonException exception)
        {
            logger.EnrollmentStateCorrupt(exception.Message);
            return null;
        }
    }

    private async Task<OrchResult<NodeSession>> EnrollAsync(HostIdentity identity, CancellationToken cancellationToken)
    {
        var secretResult = await ResolveEnrollSecretAsync(cancellationToken);
        if (!secretResult.TryGetValue(out var enrollSecret, out var secretError))
        {
            return secretError;
        }

        var request = new NodeEnrollRequest(enrollSecret, identity.InstanceId, identity.Region, identity.PoolKind, identity.VcnIp);
        var endpoint = new Uri(BackplaneUrl, "/api/nodes/enroll");
        using var client = httpClientFactory.CreateClient(BackplaneClientName);
        NodeEnrollResponse? enrolled;
        try
        {
            using var response = await client.PostAsJsonAsync(endpoint, request, ApiJsonContext.Default.NodeEnrollRequest, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return await MapFailureAsync(response, cancellationToken);
            }

            enrolled = await response.Content.ReadFromJsonAsync(ApiJsonContext.Default.NodeEnrollResponse, cancellationToken);
        }
        catch (HttpRequestException exception)
        {
            return new Unavailable($"Backplane enrollment at {endpoint} is unreachable: {exception.Message}");
        }
        catch (JsonException exception)
        {
            return new Internal($"Backplane enrollment response was malformed: {exception.Message}");
        }

        if (enrolled is null || string.IsNullOrWhiteSpace(enrolled.Token) || string.IsNullOrWhiteSpace(enrolled.NodeId))
        {
            return new Internal("Backplane enrollment response was empty.");
        }

        UnixFiles.CreatePrivateDirectory(_options.StateDirectory);
        await UnixFiles.WriteAtomicAsync(_options.NodeTokenFile, Encoding.UTF8.GetBytes(enrolled.Token), UnixFiles.OwnerReadWrite, cancellationToken);
        await UnixFiles.WriteAtomicAsync(
            _options.NodeStateFile,
            JsonSerializer.SerializeToUtf8Bytes(new NodeRegistration(enrolled.NodeId, enrolled.WsUrl), AgentJsonContext.Default.NodeRegistration),
            UnixFiles.OwnerReadWrite,
            cancellationToken);
        logger.Enrolled(enrolled.NodeId);
        return new NodeSession(identity, enrolled.NodeId, enrolled.Token, ResolveWebSocketUrl(enrolled.WsUrl));
    }

    private async Task<OrchResult<string>> ResolveEnrollSecretAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(_options.EnrollSecret))
        {
            return _options.EnrollSecret;
        }

        var vault = _options.EnrollSecretVault ?? throw new InvalidOperationException($"{nameof(AgentOptions.EnrollSecretVault)} is required when {nameof(AgentOptions.EnrollSecret)} is not set.");
        var name = _options.EnrollSecretName ?? throw new InvalidOperationException($"{nameof(AgentOptions.EnrollSecretName)} is required when {nameof(AgentOptions.EnrollSecret)} is not set.");
        var fetched = await secretProvider.GetSecretAsync(new SecretRef(vault, name), cancellationToken);
        return fetched switch
        {
            ResolvedSecret secret => secret.Value,
            OrchError error => error,
        };
    }

    private Uri BackplaneUrl => _options.BackplaneUrl ?? throw new InvalidOperationException($"{nameof(AgentOptions.BackplaneUrl)} is required.");

    private Uri ResolveWebSocketUrl(string wsUrl)
    {
        if (Uri.TryCreate(wsUrl, UriKind.Absolute, out var explicitUrl) && (explicitUrl.Scheme == Uri.UriSchemeWss || explicitUrl.Scheme == Uri.UriSchemeWs))
        {
            return explicitUrl;
        }

        var builder = new UriBuilder(BackplaneUrl)
        {
            Scheme = BackplaneUrl.Scheme == Uri.UriSchemeHttps ? Uri.UriSchemeWss : Uri.UriSchemeWs,
            Path = "/ws/node",
            Query = string.Empty,
        };
        return builder.Uri;
    }

    private static async Task<OrchError> MapFailureAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var message = string.Create(CultureInfo.InvariantCulture, $"Backplane enrollment returned {(int)response.StatusCode}");
        try
        {
            if (await response.Content.ReadFromJsonAsync(ApiJsonContext.Default.ErrorResponse, cancellationToken) is { } body)
            {
                message = $"{message}: {body.Error.Message}";
            }
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException)
        {
            message = $"{message}.";
        }

        return response.StatusCode switch
        {
            HttpStatusCode.Unauthorized => new Unauthorized(message),
            HttpStatusCode.Forbidden => new Forbidden(message),
            HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => new Validation(message),
            HttpStatusCode.Conflict => new Conflict(message),
            >= HttpStatusCode.InternalServerError => new Unavailable(message),
            _ => new Internal(message),
        };
    }
}
