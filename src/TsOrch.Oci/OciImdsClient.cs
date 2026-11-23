using System.Net.Http.Headers;
using System.Text.Json.Serialization.Metadata;

namespace TsOrch.Oci;

internal sealed record class OciFederationMaterial(
    string LeafCertificatePem,
    string LeafPrivateKeyPem,
    string IntermediateCertificatePem);

public sealed class OciImdsClient(HttpClient httpClient, OciEnvironment environment)
{
    private const string RegionKey = "ts_region";
    private const string PoolKey = "ts_pool";
    private const string EnrollVaultKey = "ts_enroll_vault";
    private const string EnrollSecretKey = "ts_enroll_secret";

    private static readonly Uri CloudBaseUrl = new("http://169.254.169.254/opc/v2/");
    private static readonly AuthenticationHeaderValue ImdsAuthorization = new("Bearer", "Oracle");

    private OciInstanceIdentity? _identity;

    public Uri BaseUrl { get; } = environment switch
    {
        OciCloud => CloudBaseUrl,
        OciMock mock => new Uri(mock.BaseUrl, "opc/v2/"),
    };

    public async Task<Result<OciInstanceIdentity, Unavailable, InternalFailure>> GetIdentityAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _identity) is { } cached)
        {
            return cached;
        }

        return await GetJsonAsync("instance/", OciJsonContext.Default.ImdsInstanceDocument, cancellationToken) switch
        {
            ImdsInstanceDocument instance => await WithVnicsAsync(instance, cancellationToken),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    internal async Task<Result<OciFederationMaterial, Unavailable, InternalFailure>> GetFederationMaterialAsync(CancellationToken cancellationToken) =>
        await GetTextAsync("identity/cert.pem", cancellationToken) switch
        {
            string leafCertificate => await GetTextAsync("identity/key.pem", cancellationToken) switch
            {
                string leafKey => await GetTextAsync("identity/intermediate.pem", cancellationToken) switch
                {
                    string intermediate => new OciFederationMaterial(leafCertificate, leafKey, intermediate),
                    Unavailable failure => failure,
                    InternalFailure failure => failure,
                },
                Unavailable failure => failure,
                InternalFailure failure => failure,
            },
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    private async Task<Result<OciInstanceIdentity, Unavailable, InternalFailure>> WithVnicsAsync(ImdsInstanceDocument instance, CancellationToken cancellationToken) =>
        await GetJsonAsync("vnics/", OciJsonContext.Default.IReadOnlyListImdsVnicDocument, cancellationToken) switch
        {
            IReadOnlyList<ImdsVnicDocument> vnics => Identify(instance, vnics),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    private Result<OciInstanceIdentity, Unavailable, InternalFailure> Identify(ImdsInstanceDocument instance, IReadOnlyList<ImdsVnicDocument> vnics)
    {
        if (vnics is not [var primary, ..])
        {
            return new InternalFailure("OCI instance metadata lists no VNICs for this instance.");
        }

        var metadata = instance.Metadata ?? new Dictionary<string, string>();
        var poolText = NonEmpty(metadata, PoolKey);
        var pool = poolText is null ? null : ParsePool(poolText);
        if (poolText is not null && pool is null)
        {
            return new InternalFailure($"OCI instance metadata {PoolKey} '{poolText}' is neither 'stateful' nor 'worker'.");
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
                NonEmpty(metadata, EnrollSecretKey)));
        Volatile.Write(ref _identity, identity);
        return identity;
    }

    private static PoolKind? ParsePool(string text) => text switch
    {
        "stateful" => PoolKind.Stateful,
        "worker" => PoolKind.Worker,
        _ => null,
    };

    private static string? NonEmpty(IReadOnlyDictionary<string, string> metadata, string key) =>
        metadata.GetValueOrDefault(key) is { Length: > 0 } value ? value : null;

    private async Task<Result<T, Unavailable, InternalFailure>> GetJsonAsync<T>(string path, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
        where T : notnull
    {
        using var request = CreateRequest(path);
        return await OciHttp.SendJsonAsync(httpClient, request, typeInfo, cancellationToken) switch
        {
            T document => document,
            NotFound failure => new InternalFailure(failure.Message),
            Forbidden failure => new InternalFailure(failure.Message),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    private async Task<Result<string, Unavailable, InternalFailure>> GetTextAsync(string path, CancellationToken cancellationToken)
    {
        using var request = CreateRequest(path);
        return await OciHttp.SendTextAsync(httpClient, request, cancellationToken) switch
        {
            string text => text,
            NotFound failure => new InternalFailure(failure.Message),
            Forbidden failure => new InternalFailure(failure.Message),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    private HttpRequestMessage CreateRequest(string path)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri(BaseUrl, path));
        request.Headers.Authorization = ImdsAuthorization;
        return request;
    }
}
