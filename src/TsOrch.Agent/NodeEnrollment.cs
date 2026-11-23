using System.Collections.Frozen;
using System.Globalization;
using System.Text;
using System.Text.Json;
using TsOrch.Oci;

namespace TsOrch.Agent;

public sealed record class HostIdentity(
    string InstanceId,
    string Region,
    PoolKind PoolKind,
    string VcnIp,
    string Shape,
    string FaultDomain,
    IReadOnlyDictionary<string, string> Labels,
    SecretRef? EnrollSecret);

public sealed record class NodeSession(HostIdentity Identity, string NodeId, string Token, Uri WebSocketUrl)
{
    public override string ToString() => $"{nameof(NodeSession)} {{ NodeId = {NodeId}, WebSocketUrl = {WebSocketUrl} }}";
}

public sealed class NodeEnrollment(
    OciImdsClient imds,
    OciVaultClient vault,
    OciEnvironment ociEnvironment,
    IHttpClientFactory httpClientFactory,
    AgentOptions options,
    ILogger<NodeEnrollment> logger)
{
    public const string BackplaneClientName = "ts-orch-backplane";
    public const string StandaloneShape = "standalone";
    public const string StandaloneFaultDomain = "standalone";

    private static readonly FrozenDictionary<string, string> Labels = [];

    public async Task<Result<NodeSession, Validation, Conflict, Unauthorized, Forbidden, Unavailable, InternalFailure>> EnsureEnrolledAsync(CancellationToken cancellationToken) =>
        await ResolveIdentityAsync(cancellationToken) switch
        {
            HostIdentity identity => await LoadAsync(identity, cancellationToken) switch
            {
                NodeSession stored => Loaded(stored),
                NotFound => await EnrollAsync(identity, cancellationToken),
            },
            Validation failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    public void Forget()
    {
        File.Delete(options.NodeTokenFile);
        File.Delete(options.NodeStateFile);
        AgentLog.CredentialsForgotten(logger);
    }

    private NodeSession Loaded(NodeSession stored)
    {
        AgentLog.EnrollmentLoaded(logger, stored.NodeId);
        return stored;
    }

    private async Task<Result<HostIdentity, Validation, Unavailable, InternalFailure>> ResolveIdentityAsync(CancellationToken cancellationToken)
    {
        var standalone = ociEnvironment switch
        {
            OciCloud => options is { NodeIdOverride: not null, RegionOverride: not null, VcnIpOverride: not null },
            OciMock => false,
        };
        if (standalone)
        {
            return options is { NodeIdOverride: { } nodeId, RegionOverride: { } region, VcnIpOverride: { } vcnIp, PoolKindOverride: { } poolKind }
                ? new HostIdentity(nodeId, region, poolKind, vcnIp, StandaloneShape, StandaloneFaultDomain, Labels, ConfiguredEnrollSecret())
                : new Validation($"{nameof(AgentOptions.PoolKindOverride)} is required when the node identity is set without OCI instance metadata.");
        }

        return await imds.GetIdentityAsync(cancellationToken) switch
        {
            OciInstanceIdentity instance => FromMetadata(instance),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    private Result<HostIdentity, Validation, Unavailable, InternalFailure> FromMetadata(OciInstanceIdentity instance)
    {
        if ((options.RegionOverride ?? instance.Node.Region) is not { } region)
        {
            return new Validation($"OCI instance metadata carries no ts_region and {nameof(AgentOptions.RegionOverride)} is not set.");
        }

        if ((options.PoolKindOverride ?? instance.Node.Pool) is not { } poolKind)
        {
            return new Validation($"OCI instance metadata carries no ts_pool and {nameof(AgentOptions.PoolKindOverride)} is not set.");
        }

        var enrollSecret = ConfiguredEnrollSecret()
            ?? (instance.Node is { EnrollVault: { } metadataVault, EnrollSecretName: { } metadataName } ? new SecretRef(metadataVault, metadataName) : null);
        return new HostIdentity(
            options.NodeIdOverride ?? instance.InstanceId,
            region,
            poolKind,
            options.VcnIpOverride ?? instance.VcnIp,
            instance.Shape,
            instance.FaultDomain,
            Labels,
            enrollSecret);
    }

    private SecretRef? ConfiguredEnrollSecret() =>
        options is { EnrollSecretVault: { } vaultId, EnrollSecretName: { } secretName } ? new SecretRef(vaultId, secretName) : null;

    private async Task<Result<NodeSession, NotFound>> LoadAsync(HostIdentity identity, CancellationToken cancellationToken)
    {
        if (!File.Exists(options.NodeTokenFile) || !File.Exists(options.NodeStateFile))
        {
            return new NotFound("No stored enrollment.");
        }

        try
        {
            var token = (await File.ReadAllTextAsync(options.NodeTokenFile, cancellationToken)).Trim();
            await using var stream = File.OpenRead(options.NodeStateFile);
            var registration = await JsonSerializer.DeserializeAsync(stream, AgentJsonContext.Default.NodeRegistration, cancellationToken);
            if (token.Length == 0 || registration is null)
            {
                return Corrupt($"{options.NodeTokenFile} or {options.NodeStateFile} is empty.");
            }

            return new NodeSession(identity, registration.NodeId, token, ResolveWebSocketUrl(registration.WsUrl));
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            return Corrupt(exception.Message);
        }
    }

    private NotFound Corrupt(string reason)
    {
        AgentLog.EnrollmentStateCorrupt(logger, reason);
        return new NotFound(reason);
    }

    private async Task<Result<NodeSession, Validation, Conflict, Unauthorized, Forbidden, Unavailable, InternalFailure>> EnrollAsync(
        HostIdentity identity,
        CancellationToken cancellationToken) =>
        await ResolveEnrollSecretAsync(identity, cancellationToken) switch
        {
            string enrollSecret => await PostEnrollmentAsync(identity, enrollSecret, cancellationToken) switch
            {
                NodeEnrollResponse enrolled => await StoreAsync(identity, enrolled, cancellationToken),
                Validation failure => failure,
                Conflict failure => failure,
                Unauthorized failure => failure,
                Unavailable failure => failure,
                InternalFailure failure => failure,
            },
            Validation failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    private async Task<Result<string, Validation, Forbidden, Unavailable, InternalFailure>> ResolveEnrollSecretAsync(
        HostIdentity identity,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(options.EnrollSecret))
        {
            return options.EnrollSecret;
        }

        if (identity.EnrollSecret is not { } reference)
        {
            return new Validation($"No enrollment secret: set {nameof(AgentOptions.EnrollSecret)}, {nameof(AgentOptions.EnrollSecretVault)} and {nameof(AgentOptions.EnrollSecretName)}, or the ts_enroll_vault and ts_enroll_secret instance metadata.");
        }

        return await vault.GetSecretAsync(reference.Vault, reference.Name, cancellationToken) switch
        {
            VaultSecretBundle bundle => bundle.Value,
            Validation failure => failure,
            NotFound failure => new Validation($"Enrollment secret {reference.Name} is missing from vault {reference.Vault}: {failure.Message}"),
            Forbidden failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    private async Task<Result<NodeEnrollResponse, Validation, Conflict, Unauthorized, Unavailable, InternalFailure>> PostEnrollmentAsync(
        HostIdentity identity,
        string enrollSecret,
        CancellationToken cancellationToken)
    {
        var request = new NodeEnrollRequest(enrollSecret, identity.InstanceId, identity.Region, identity.PoolKind, identity.VcnIp);
        var endpoint = new Uri(options.BackplaneUrl, "/api/nodes/enroll");
        using var client = httpClientFactory.CreateClient(BackplaneClientName);
        try
        {
            using var response = await client.PostAsJsonAsync(endpoint, request, ApiJsonContext.Default.NodeEnrollRequest, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return await FailureAsync(response, cancellationToken);
            }

            return await response.Content.ReadFromJsonAsync(ApiJsonContext.Default.NodeEnrollResponse, cancellationToken) is { } enrolled
                && !string.IsNullOrWhiteSpace(enrolled.Token)
                && !string.IsNullOrWhiteSpace(enrolled.NodeId)
                ? enrolled
                : new InternalFailure("Backplane enrollment response was empty.");
        }
        catch (HttpRequestException exception)
        {
            return new Unavailable($"Backplane enrollment at {endpoint} is unreachable: {exception.Message}");
        }
        catch (JsonException exception)
        {
            return new InternalFailure($"Backplane enrollment response was malformed: {exception.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new Unavailable($"Backplane enrollment at {endpoint} timed out.");
        }
    }

    private async Task<Result<NodeSession, Validation, Conflict, Unauthorized, Forbidden, Unavailable, InternalFailure>> StoreAsync(
        HostIdentity identity,
        NodeEnrollResponse enrolled,
        CancellationToken cancellationToken)
    {
        var written = await UnixFiles.WriteAtomicAsync(
            [options.StateDirectory],
            [
                new AtomicWrite(options.NodeTokenFile, Encoding.UTF8.GetBytes(enrolled.Token), UnixFiles.OwnerReadWrite),
                new AtomicWrite(
                    options.NodeStateFile,
                    JsonSerializer.SerializeToUtf8Bytes(new NodeRegistration(enrolled.NodeId, enrolled.WsUrl), AgentJsonContext.Default.NodeRegistration),
                    UnixFiles.OwnerReadWrite),
            ],
            cancellationToken);
        return written switch
        {
            Done => Enrolled(new NodeSession(identity, enrolled.NodeId, enrolled.Token, ResolveWebSocketUrl(enrolled.WsUrl))),
            InternalFailure failure => failure,
        };
    }

    private NodeSession Enrolled(NodeSession session)
    {
        AgentLog.Enrolled(logger, session.NodeId);
        return session;
    }

    private Uri ResolveWebSocketUrl(string wsUrl)
    {
        if (Uri.TryCreate(wsUrl, UriKind.Absolute, out var explicitUrl) && (explicitUrl.Scheme == Uri.UriSchemeWss || explicitUrl.Scheme == Uri.UriSchemeWs))
        {
            return explicitUrl;
        }

        var builder = new UriBuilder(options.BackplaneUrl)
        {
            Scheme = options.BackplaneUrl.Scheme == Uri.UriSchemeHttps ? Uri.UriSchemeWss : Uri.UriSchemeWs,
            Path = "/ws/node",
            Query = string.Empty,
        };
        return builder.Uri;
    }

    private static async Task<Result<NodeEnrollResponse, Validation, Conflict, Unauthorized, Unavailable, InternalFailure>> FailureAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var status = (int)response.StatusCode;
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var message = string.Create(CultureInfo.InvariantCulture, $"Backplane enrollment returned {status}: {ErrorMessage(body)}");
        return status switch
        {
            401 => new Unauthorized(message),
            400 or 422 => new Validation(message),
            409 => new Conflict(message),
            429 or >= 500 => new Unavailable(message),
            _ => new InternalFailure(message),
        };
    }

    private static string ErrorMessage(string body)
    {
        try
        {
            return JsonSerializer.Deserialize(body, ApiJsonContext.Default.ErrorResponse) is { Error: { } error } ? error.Message : body;
        }
        catch (JsonException)
        {
            return body;
        }
    }
}
