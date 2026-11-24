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

public sealed record class NodeIdentityIncomplete(string Message);

public sealed record class EnrollmentMetadataUnreadable(string Message);

public sealed record class EnrollmentSecretUnconfigured(string Message);

public sealed record class EnrollmentSecretUnreadable(string Message);

public sealed record class NodeRegistrationRejected(int Status, string Message);

public sealed record class EnrollmentBackplaneUnavailable(string Message);

public sealed record class EnrollmentResponseInvalid(string Message);

public sealed record class EnrollmentStateWriteFailed(string Path, string Message);

public readonly union NodeEnrollmentOutcome(
    NodeSession, NodeIdentityIncomplete, EnrollmentMetadataUnreadable, EnrollmentSecretUnconfigured, EnrollmentSecretUnreadable,
    NodeRegistrationRejected, EnrollmentBackplaneUnavailable, EnrollmentResponseInvalid, EnrollmentStateWriteFailed);

internal readonly union NodeIdentity(HostIdentity, NodeIdentityIncomplete, EnrollmentMetadataUnreadable);

internal readonly union EnrollmentSecret(string, EnrollmentSecretUnconfigured, EnrollmentSecretUnreadable);

internal readonly union NodeRegistrationResponse(NodeEnrollResponse, NodeRegistrationRejected, EnrollmentBackplaneUnavailable, EnrollmentResponseInvalid);

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

    public async Task<NodeEnrollmentOutcome> EnsureEnrolledAsync(CancellationToken cancellationToken)
    {
        var identity = await ResolveIdentityAsync(cancellationToken);
        return identity switch
        {
            HostIdentity host => await ResumeOrEnrollAsync(host, cancellationToken),
            NodeIdentityIncomplete incomplete => incomplete,
            EnrollmentMetadataUnreadable unreadable => unreadable,
        };
    }

    private async Task<NodeEnrollmentOutcome> ResumeOrEnrollAsync(HostIdentity identity, CancellationToken cancellationToken) =>
        await LoadAsync(identity, cancellationToken) is { } session ? Loaded(session) : await EnrollAsync(identity, cancellationToken);

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

    private async Task<NodeIdentity> ResolveIdentityAsync(CancellationToken cancellationToken)
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
                : new NodeIdentityIncomplete($"{nameof(AgentOptions.PoolKindOverride)} is required when the node identity is set without OCI instance metadata.");
        }

        var read = await imds.GetIdentityAsync(cancellationToken);
        return read switch
        {
            OciInstanceIdentity instance => FromMetadata(instance),
            ImdsRequestRejected failure => new EnrollmentMetadataUnreadable(failure.Message),
            ImdsUnavailable failure => new EnrollmentMetadataUnreadable(failure.Message),
            ImdsDocumentInvalid failure => new EnrollmentMetadataUnreadable(failure.Message),
        };
    }

    private NodeIdentity FromMetadata(OciInstanceIdentity instance)
    {
        if ((options.RegionOverride ?? instance.Node.Region) is not { } region)
        {
            return new NodeIdentityIncomplete($"OCI instance metadata carries no ts_region and {nameof(AgentOptions.RegionOverride)} is not set.");
        }

        if ((options.PoolKindOverride ?? instance.Node.Pool) is not { } poolKind)
        {
            return new NodeIdentityIncomplete($"OCI instance metadata carries no ts_pool and {nameof(AgentOptions.PoolKindOverride)} is not set.");
        }

        var enrollSecret = ConfiguredEnrollSecret()
            ?? (instance.Node is { EnrollVault: { } metadataVault, EnrollSecretName: { } metadataName } ? new SecretRef(metadataVault, metadataName) : null);
        Dictionary<string, string> labels = [with(StringComparer.Ordinal)];
        if (instance.Node.DataVolumeId is { } volumeId)
        {
            labels["oci.data-volume-id"] = volumeId;
        }

        if (instance.Node.InstancePoolId is { } poolId)
        {
            labels["oci.instance-pool-id"] = poolId;
        }

        if (instance.Node.StatefulIndex is { } statefulIndex)
        {
            labels["oci.stateful-index"] = statefulIndex;
        }

        return new HostIdentity(
            options.NodeIdOverride ?? instance.InstanceId,
            region,
            poolKind,
            options.VcnIpOverride ?? instance.VcnIp,
            instance.Shape,
            instance.FaultDomain,
            labels,
            enrollSecret);
    }

    private SecretRef? ConfiguredEnrollSecret() =>
        options is { EnrollSecretVault: { } vaultId, EnrollSecretName: { } secretName } ? new SecretRef(vaultId, secretName) : null;

    private async Task<NodeSession?> LoadAsync(HostIdentity identity, CancellationToken cancellationToken)
    {
        if (!File.Exists(options.NodeTokenFile) || !File.Exists(options.NodeStateFile))
        {
            return null;
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

    private NodeSession? Corrupt(string reason)
    {
        AgentLog.EnrollmentStateCorrupt(logger, reason);
        return null;
    }

    private async Task<NodeEnrollmentOutcome> EnrollAsync(HostIdentity identity, CancellationToken cancellationToken)
    {
        var secret = await ResolveEnrollSecretAsync(identity, cancellationToken);
        return secret switch
        {
            string value => await RegisterAsync(identity, value, cancellationToken),
            EnrollmentSecretUnconfigured unconfigured => unconfigured,
            EnrollmentSecretUnreadable unreadable => unreadable,
        };
    }

    private async Task<NodeEnrollmentOutcome> RegisterAsync(HostIdentity identity, string secret, CancellationToken cancellationToken)
    {
        var registered = await PostEnrollmentAsync(identity, secret, cancellationToken);
        return registered switch
        {
            NodeEnrollResponse enrolled => await StoreAsync(identity, enrolled, cancellationToken),
            NodeRegistrationRejected rejected => rejected,
            EnrollmentBackplaneUnavailable unavailable => unavailable,
            EnrollmentResponseInvalid invalid => invalid,
        };
    }

    private async Task<EnrollmentSecret> ResolveEnrollSecretAsync(
        HostIdentity identity,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(options.EnrollSecret))
        {
            return options.EnrollSecret;
        }

        if (identity.EnrollSecret is not { } reference)
        {
            return new EnrollmentSecretUnconfigured($"No enrollment secret: set {nameof(AgentOptions.EnrollSecret)}, {nameof(AgentOptions.EnrollSecretVault)} and {nameof(AgentOptions.EnrollSecretName)}, or the ts_enroll_vault and ts_enroll_secret instance metadata.");
        }

        var read = await vault.GetSecretAsync(reference.Vault, reference.Name, cancellationToken);
        return read switch
        {
            VaultSecretBundle bundle => bundle.Value,
            VaultRegionMissing failure => new EnrollmentSecretUnreadable(failure.Message),
            VaultSecretMissing failure => new EnrollmentSecretUnreadable(failure.Message),
            VaultAccessDenied failure => new EnrollmentSecretUnreadable(failure.Message),
            VaultUnavailable failure => new EnrollmentSecretUnreadable(failure.Message),
            VaultBundleInvalid failure => new EnrollmentSecretUnreadable(failure.Message),
            ImdsRequestRejected failure => new EnrollmentSecretUnreadable(failure.Message),
            ImdsUnavailable failure => new EnrollmentSecretUnreadable(failure.Message),
            ImdsDocumentInvalid failure => new EnrollmentSecretUnreadable(failure.Message),
            InvalidFederationCredentials failure => new EnrollmentSecretUnreadable(failure.Message),
            FederationRejected failure => new EnrollmentSecretUnreadable(failure.Message),
            FederationUnavailable failure => new EnrollmentSecretUnreadable(failure.Message),
            FederationTokenInvalid failure => new EnrollmentSecretUnreadable(failure.Message),
        };
    }

    private async Task<NodeRegistrationResponse> PostEnrollmentAsync(
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
                : new EnrollmentResponseInvalid("Backplane enrollment response was empty.");
        }
        catch (HttpRequestException exception)
        {
            return new EnrollmentBackplaneUnavailable($"Backplane enrollment at {endpoint} is unreachable: {exception.Message}");
        }
        catch (JsonException exception)
        {
            return new EnrollmentResponseInvalid($"Backplane enrollment response was malformed: {exception.Message}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new EnrollmentBackplaneUnavailable($"Backplane enrollment at {endpoint} timed out.");
        }
    }

    private async Task<NodeEnrollmentOutcome> StoreAsync(
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
            AtomicWriteCompleted => Enrolled(new NodeSession(identity, enrolled.NodeId, enrolled.Token, ResolveWebSocketUrl(enrolled.WsUrl))),
            AtomicWriteFailed failure => new EnrollmentStateWriteFailed(failure.Path, failure.Message),
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

    private static async Task<NodeRegistrationResponse> FailureAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var status = (int)response.StatusCode;
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var message = string.Create(CultureInfo.InvariantCulture, $"Backplane enrollment returned {status}: {ErrorMessage(body)}");
        return status is 429 or >= 500
            ? new EnrollmentBackplaneUnavailable(message)
            : new NodeRegistrationRejected(status, message);
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
