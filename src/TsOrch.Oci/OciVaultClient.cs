using System.Buffers.Text;
using System.Text;

namespace TsOrch.Oci;

public sealed class OciVaultClient(
    HttpClient httpClient,
    OciEnvironment environment,
    OciImdsClient imds,
    OciInstancePrincipal principal)
{
    private const string Base64ContentType = "BASE64";

    public async Task<Result<VaultSecretBundle, Validation, NotFound, Forbidden, Unavailable, InternalFailure>> GetSecretAsync(
        string vaultId,
        string secretName,
        CancellationToken cancellationToken) =>
        await GetBundleAsync(vaultId, secretName, cancellationToken) switch
        {
            SecretBundleDocument bundle => Decode(bundle, secretName),
            Validation failure => failure,
            NotFound failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    public async Task<Result<long, Validation, NotFound, Forbidden, Unavailable, InternalFailure>> GetSecretVersionAsync(
        string vaultId,
        string secretName,
        CancellationToken cancellationToken) =>
        await GetBundleAsync(vaultId, secretName, cancellationToken) switch
        {
            SecretBundleDocument bundle => bundle.VersionNumber,
            Validation failure => failure,
            NotFound failure => failure,
            Forbidden failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };

    private static Result<VaultSecretBundle, Validation, NotFound, Forbidden, Unavailable, InternalFailure> Decode(SecretBundleDocument bundle, string secretName)
    {
        if (bundle.SecretBundleContent is not { } content)
        {
            return new InternalFailure($"OCI Vault secret '{secretName}' returned no content.");
        }

        if (!string.Equals(content.ContentType, Base64ContentType, StringComparison.Ordinal) || !Base64.IsValid(content.Content))
        {
            return new InternalFailure($"OCI Vault secret '{secretName}' content is not base64 ({content.ContentType}).");
        }

        return new VaultSecretBundle(bundle.SecretId, Encoding.UTF8.GetString(Convert.FromBase64String(content.Content)), bundle.VersionNumber);
    }

    private async Task<Result<SecretBundleDocument, Validation, NotFound, Forbidden, Unavailable, InternalFailure>> GetBundleAsync(
        string vaultId,
        string secretName,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultId);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
        return await SecretsBaseUrlAsync(vaultId, cancellationToken) switch
        {
            Uri baseUrl => await FetchBundleAsync(baseUrl, vaultId, secretName, cancellationToken),
            Validation failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    private async Task<Result<SecretBundleDocument, Validation, NotFound, Forbidden, Unavailable, InternalFailure>> FetchBundleAsync(
        Uri baseUrl,
        string vaultId,
        string secretName,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(
                baseUrl,
                $"20190301/secretbundles/actions/getByName?secretName={Uri.EscapeDataString(secretName)}&vaultId={Uri.EscapeDataString(vaultId)}"));
        return await principal.AuthorizeAsync(request, cancellationToken) switch
        {
            Done => await OciHttp.SendJsonAsync(httpClient, request, OciJsonContext.Default.SecretBundleDocument, cancellationToken) switch
            {
                SecretBundleDocument bundle => bundle,
                NotFound failure => failure,
                Forbidden failure => failure,
                Unavailable failure => failure,
                InternalFailure failure => failure,
            },
            Forbidden failure => failure,
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    private async Task<Result<Uri, Validation, Unavailable, InternalFailure>> SecretsBaseUrlAsync(string vaultId, CancellationToken cancellationToken) =>
        environment switch
        {
            OciMock mock => mock.BaseUrl,
            OciCloud => await CloudSecretsBaseUrlAsync(vaultId, cancellationToken),
        };

    private async Task<Result<Uri, Validation, Unavailable, InternalFailure>> CloudSecretsBaseUrlAsync(string vaultId, CancellationToken cancellationToken)
    {
        if (VaultRegion(vaultId) is not { } region)
        {
            return new Validation($"Vault id '{vaultId}' does not carry a region segment.");
        }

        return await imds.GetIdentityAsync(cancellationToken) switch
        {
            OciInstanceIdentity identity => new Uri($"https://secrets.vaults.{region}.oci.{identity.RealmDomain}/"),
            Unavailable failure => failure,
            InternalFailure failure => failure,
        };
    }

    private static string? VaultRegion(string vaultId)
    {
        var segments = vaultId.Split('.');
        return segments is ["ocid1", "vault", _, { Length: > 0 } region, ..] ? region : null;
    }
}
