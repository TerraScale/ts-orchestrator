using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace TsOrch.Oci;

internal sealed record class OciFederationMaterial(
    string LeafCertificatePem,
    string LeafPrivateKeyPem,
    string IntermediateCertificatePem);

public sealed record class ImdsRequestRejected(string Path, HttpStatusCode Status, string Message);

public sealed record class ImdsUnavailable(string Path, string Message);

public sealed record class ImdsDocumentInvalid(string Path, string Message);

public readonly union ImdsIdentity(OciInstanceIdentity, ImdsRequestRejected, ImdsUnavailable, ImdsDocumentInvalid);

internal readonly union ImdsFederationMaterial(OciFederationMaterial, ImdsRequestRejected, ImdsUnavailable);

internal readonly union ImdsRead(OciPayload, ImdsRequestRejected, ImdsUnavailable);

public sealed class OciImdsClient(HttpClient httpClient, OciEnvironment environment)
{
    private const string RegionKey = "ts_region";
    private const string PoolKey = "ts_pool";
    private const string EnrollVaultKey = "ts_enroll_vault";
    private const string EnrollSecretKey = "ts_enroll_secret";
    private const string NetBirdUrlKey = "ts_netbird_url";
    private const string NetBirdSetupKeySecretKey = "ts_netbird_setup_key_secret";
    private const string DataVolumeIdKey = "ts_data_volume_id";
    private const string InstancePoolIdKey = "ts_instance_pool_id";
    private const string StatefulIndexKey = "ts_stateful_index";
    private const string InstancePath = "instance/";
    private const string VnicsPath = "vnics/";

    private static readonly Uri CloudBaseUrl = new("http://169.254.169.254/opc/v2/");
    private static readonly AuthenticationHeaderValue ImdsAuthorization = new("Bearer", "Oracle");

    private OciInstanceIdentity? _identity;

    public Uri BaseUrl { get; } = environment switch
    {
        OciCloud => CloudBaseUrl,
        OciMock mock => new Uri(mock.BaseUrl, "opc/v2/"),
    };

    public async Task<ImdsIdentity> GetIdentityAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _identity) is { } cached)
        {
            return cached;
        }

        var read = await ReadAsync(InstancePath, cancellationToken);
        return read switch
        {
            OciPayload payload => await ReadVnicsAsync(payload.Body, cancellationToken),
            ImdsRequestRejected rejected => rejected,
            ImdsUnavailable unavailable => unavailable,
        };
    }

    internal async Task<ImdsFederationMaterial> GetFederationMaterialAsync(CancellationToken cancellationToken)
    {
        var certificate = await ReadAsync("identity/cert.pem", cancellationToken);
        return certificate switch
        {
            OciPayload leaf => await ReadKeyAsync(leaf.Body, cancellationToken),
            ImdsRequestRejected rejected => rejected,
            ImdsUnavailable unavailable => unavailable,
        };
    }

    private async Task<ImdsFederationMaterial> ReadKeyAsync(string certificate, CancellationToken cancellationToken)
    {
        var key = await ReadAsync("identity/key.pem", cancellationToken);
        return key switch
        {
            OciPayload payload => await ReadIntermediateAsync(certificate, payload.Body, cancellationToken),
            ImdsRequestRejected rejected => rejected,
            ImdsUnavailable unavailable => unavailable,
        };
    }

    private async Task<ImdsFederationMaterial> ReadIntermediateAsync(string certificate, string key, CancellationToken cancellationToken)
    {
        var intermediate = await ReadAsync("identity/intermediate.pem", cancellationToken);
        return intermediate switch
        {
            OciPayload payload => new OciFederationMaterial(certificate, key, payload.Body),
            ImdsRequestRejected rejected => rejected,
            ImdsUnavailable unavailable => unavailable,
        };
    }

    private async Task<ImdsIdentity> ReadVnicsAsync(string body, CancellationToken cancellationToken)
    {
        var instance = OciHttp.Decode(body, OciJsonContext.Default.ImdsInstanceDocument, out var error);
        if (instance is null)
        {
            return new ImdsDocumentInvalid(InstancePath, error ?? "Instance document is missing.");
        }

        var read = await ReadAsync(VnicsPath, cancellationToken);
        return read switch
        {
            OciPayload payload => Identify(instance, payload.Body),
            ImdsRequestRejected rejected => rejected,
            ImdsUnavailable unavailable => unavailable,
        };
    }

    private ImdsIdentity Identify(ImdsInstanceDocument instance, string body)
    {
        var vnics = OciHttp.Decode(body, OciJsonContext.Default.IReadOnlyListImdsVnicDocument, out var error);
        if (vnics is not [var primary, ..])
        {
            return new ImdsDocumentInvalid(VnicsPath, error ?? "OCI instance metadata lists no VNICs for this instance.");
        }

        var metadata = instance.Metadata;
        var poolText = NonEmpty(metadata, PoolKey);
        var pool = poolText is null ? null : ParsePool(poolText);
        if (poolText is not null && pool is null)
        {
            return new ImdsDocumentInvalid(InstancePath, $"OCI instance metadata {PoolKey} '{poolText}' is neither 'stateful' nor 'worker'.");
        }

        var identity = new OciInstanceIdentity(
            instance.Id,
            instance.CanonicalRegionName,
            instance.CompartmentId,
            instance.FaultDomain,
            instance.Shape,
            primary.PrivateIp,
            instance.RegionInfo.RealmDomainComponent,
            new OciNodeMetadata(
                NonEmpty(metadata, RegionKey),
                pool,
                NonEmpty(metadata, EnrollVaultKey),
                NonEmpty(metadata, EnrollSecretKey),
                NonEmpty(metadata, NetBirdUrlKey),
                NonEmpty(metadata, NetBirdSetupKeySecretKey),
                NonEmpty(metadata, DataVolumeIdKey),
                NonEmpty(metadata, InstancePoolIdKey),
                NonEmpty(metadata, StatefulIndexKey)));
        Volatile.Write(ref _identity, identity);
        return identity;
    }

    private static PoolKind? ParsePool(string text) => text switch
    {
        "stateful" => PoolKind.Stateful,
        "worker" => PoolKind.Worker,
        _ => null,
    };

    private static string? NonEmpty(IReadOnlyDictionary<string, JsonElement>? metadata, string key) =>
        metadata?.GetValueOrDefault(key) is { ValueKind: JsonValueKind.String } value && value.GetString() is { Length: > 0 } text ? text : null;

    private async Task<ImdsRead> ReadAsync(string path, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(BaseUrl, path));
        request.Headers.Authorization = ImdsAuthorization;
        var outcome = await OciHttp.SendAsync(httpClient, environment, request, cancellationToken);
        return outcome switch
        {
            OciPayload payload => payload,
            OciHttpRejected rejected => new ImdsRequestRejected(path, rejected.Status, rejected.Message),
            OciConnectionLost lost => new ImdsUnavailable(path, lost.Message),
            OciResponseTooLarge failure => new ImdsUnavailable(path, failure.Message),
            OciResponseTimedOut => new ImdsUnavailable(path, $"OCI instance metadata {path} timed out."),
        };
    }
}
