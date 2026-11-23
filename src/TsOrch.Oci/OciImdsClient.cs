using System.Net.Http.Headers;
using System.Text.Json.Serialization.Metadata;
using TsOrch.Protocol;

namespace TsOrch.Oci;

internal sealed record class OciFederationMaterial(
    string LeafCertificatePem,
    string LeafPrivateKeyPem,
    string IntermediateCertificatePem);

public sealed class OciImdsClient(HttpClient httpClient, OciEnvironment environment)
{
    private static readonly Uri CloudBaseUrl = new("http://169.254.169.254/opc/v2/");
    private static readonly AuthenticationHeaderValue ImdsAuthorization = new("Bearer", "Oracle");

    private OciInstanceIdentity? _identity;

    public Uri BaseUrl { get; } = environment switch
    {
        OciCloud => CloudBaseUrl,
        OciMock mock => new Uri(mock.BaseUrl, "opc/v2/"),
    };

    public async Task<OrchResult<OciInstanceIdentity>> GetIdentityAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _identity) is { } cached)
        {
            return cached;
        }

        var instanceResult = await GetJsonAsync("instance/", OciJsonContext.Default.ImdsInstanceDocument, cancellationToken);
        if (!instanceResult.TryGetValue(out var instance, out var instanceError))
        {
            return instanceError;
        }

        var vnicsResult = await GetJsonAsync("vnics/", OciJsonContext.Default.IReadOnlyListImdsVnicDocument, cancellationToken);
        if (!vnicsResult.TryGetValue(out var vnics, out var vnicsError))
        {
            return vnicsError;
        }

        if (vnics.Count == 0)
        {
            return new Internal("OCI instance metadata lists no VNICs for this instance.");
        }

        var identity = new OciInstanceIdentity(
            instance.Id,
            instance.CanonicalRegionName,
            instance.CompartmentId,
            instance.FaultDomain,
            instance.Shape,
            vnics[0].PrivateIp,
            instance.RegionInfo.RealmDomainComponent);
        Volatile.Write(ref _identity, identity);
        return identity;
    }

    internal async Task<OrchResult<OciFederationMaterial>> GetFederationMaterialAsync(CancellationToken cancellationToken)
    {
        var leafCertificateResult = await GetTextAsync("identity/cert.pem", cancellationToken);
        if (!leafCertificateResult.TryGetValue(out var leafCertificate, out var leafCertificateError))
        {
            return leafCertificateError;
        }

        var leafKeyResult = await GetTextAsync("identity/key.pem", cancellationToken);
        if (!leafKeyResult.TryGetValue(out var leafKey, out var leafKeyError))
        {
            return leafKeyError;
        }

        var intermediateResult = await GetTextAsync("identity/intermediate.pem", cancellationToken);
        if (!intermediateResult.TryGetValue(out var intermediate, out var intermediateError))
        {
            return intermediateError;
        }

        return new OciFederationMaterial(leafCertificate, leafKey, intermediate);
    }

    private async Task<OrchResult<T>> GetJsonAsync<T>(string path, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
    {
        using var request = CreateRequest(path);
        return await OciHttp.SendJsonAsync(httpClient, request, typeInfo, cancellationToken);
    }

    private async Task<OrchResult<string>> GetTextAsync(string path, CancellationToken cancellationToken)
    {
        using var request = CreateRequest(path);
        return await OciHttp.SendTextAsync(httpClient, request, cancellationToken);
    }

    private HttpRequestMessage CreateRequest(string path)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri(BaseUrl, path));
        request.Headers.Authorization = ImdsAuthorization;
        return request;
    }
}
