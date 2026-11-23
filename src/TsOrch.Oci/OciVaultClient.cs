using System.Buffers.Text;
using System.Net;
using System.Text;

namespace TsOrch.Oci;

public sealed record class VaultRegionMissing(string VaultId)
{
    public string Message => $"Vault id '{VaultId}' does not carry a region segment.";
}

public sealed record class VaultSecretMissing(string VaultId, string SecretName, string Message);

public sealed record class VaultAccessDenied(string VaultId, HttpStatusCode Status, string Message);

public sealed record class VaultUnavailable(string VaultId, string Message);

public sealed record class VaultBundleInvalid(string SecretName, string Message);

public readonly union VaultSecretLookup(
    VaultSecretBundle, VaultRegionMissing, VaultSecretMissing, VaultAccessDenied, VaultUnavailable,
    VaultBundleInvalid, ImdsRequestRejected, ImdsUnavailable, ImdsDocumentInvalid,
    InvalidFederationCredentials, FederationRejected, FederationUnavailable, FederationTokenInvalid);

public sealed class OciVaultClient(
    HttpClient httpClient,
    OciEnvironment environment,
    OciImdsClient imds,
    OciInstancePrincipal principal)
{
    private const string Base64ContentType = "BASE64";

    public async Task<VaultSecretLookup> GetSecretAsync(string vaultId, string secretName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultId);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
        return environment switch
        {
            OciMock mock => await FetchBundleAsync(mock.BaseUrl, vaultId, secretName, cancellationToken),
            OciCloud => await FetchCloudBundleAsync(vaultId, secretName, cancellationToken),
        };
    }

    private async Task<VaultSecretLookup> FetchCloudBundleAsync(string vaultId, string secretName, CancellationToken cancellationToken)
    {
        if (VaultRegion(vaultId) is not { } region)
        {
            return new VaultRegionMissing(vaultId);
        }

        var read = await imds.GetIdentityAsync(cancellationToken);
        return read switch
        {
            OciInstanceIdentity identity => await FetchBundleAsync(new Uri($"https://secrets.vaults.{region}.oci.{identity.RealmDomain}/"), vaultId, secretName, cancellationToken),
            ImdsRequestRejected rejected => rejected,
            ImdsUnavailable unavailable => unavailable,
            ImdsDocumentInvalid invalid => invalid,
        };
    }

    private async Task<VaultSecretLookup> FetchBundleAsync(Uri baseUrl, string vaultId, string secretName, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(baseUrl, $"20190301/secretbundles/actions/getByName?secretName={Uri.EscapeDataString(secretName)}&vaultId={Uri.EscapeDataString(vaultId)}"));
        var authorization = await principal.AuthorizeAsync(request, cancellationToken);
        return authorization switch
        {
            OciRequestSigned => await ReadBundleAsync(request, vaultId, secretName, cancellationToken),
            ImdsRequestRejected rejected => rejected,
            ImdsUnavailable unavailable => unavailable,
            ImdsDocumentInvalid invalid => invalid,
            InvalidFederationCredentials invalid => invalid,
            FederationRejected rejected => rejected,
            FederationUnavailable unavailable => unavailable,
            FederationTokenInvalid invalid => invalid,
        };
    }

    private async Task<VaultSecretLookup> ReadBundleAsync(HttpRequestMessage request, string vaultId, string secretName, CancellationToken cancellationToken)
    {
        var response = await OciHttp.SendAsync(httpClient, request, cancellationToken);
        return response switch
        {
            OciPayload payload => Decode(payload.Body, secretName),
            OciHttpRejected { Status: HttpStatusCode.NotFound } rejected => new VaultSecretMissing(vaultId, secretName, rejected.Message),
            OciHttpRejected { Status: HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden } rejected => new VaultAccessDenied(vaultId, rejected.Status, rejected.Message),
            OciHttpRejected { Status: HttpStatusCode.TooManyRequests or >= HttpStatusCode.InternalServerError } rejected => new VaultUnavailable(vaultId, rejected.Message),
            OciHttpRejected rejected => new VaultBundleInvalid(secretName, rejected.Message),
            OciConnectionLost lost => new VaultUnavailable(vaultId, lost.Message),
            OciResponseTimedOut => new VaultUnavailable(vaultId, "OCI Vault response timed out."),
        };
    }

    private static VaultSecretLookup Decode(string payload, string secretName)
    {
        var bundle = OciHttp.Decode(payload, OciJsonContext.Default.SecretBundleDocument, out var error);
        if (bundle?.SecretBundleContent is not { } content)
        {
            return new VaultBundleInvalid(secretName, error ?? $"OCI Vault secret '{secretName}' returned no content.");
        }

        if (!string.Equals(content.ContentType, Base64ContentType, StringComparison.Ordinal) || !Base64.IsValid(content.Content))
        {
            return new VaultBundleInvalid(secretName, $"OCI Vault secret '{secretName}' content is not base64 ({content.ContentType}).");
        }

        return new VaultSecretBundle(bundle.SecretId, Encoding.UTF8.GetString(Convert.FromBase64String(content.Content)), bundle.VersionNumber);
    }

    private static string? VaultRegion(string vaultId)
    {
        var segments = vaultId.Split('.');
        return segments is ["ocid1", "vault", _, { Length: > 0 } region, ..] ? region : null;
    }
}
