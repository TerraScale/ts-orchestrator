using System.Buffers.Text;
using System.Text;
using TsOrch.Protocol;

namespace TsOrch.Oci;

public sealed class OciVaultClient(
    HttpClient httpClient,
    OciEnvironment environment,
    OciImdsClient imds,
    OciInstancePrincipal principal)
{
    private const string Base64ContentType = "BASE64";

    public async Task<OrchResult<VaultSecretBundle>> GetSecretAsync(string vaultId, string secretName, CancellationToken cancellationToken)
    {
        var bundleResult = await GetBundleAsync(vaultId, secretName, cancellationToken);
        if (!bundleResult.TryGetValue(out var bundle, out var error))
        {
            return error;
        }

        if (bundle.SecretBundleContent is not { } content)
        {
            return new Internal($"OCI Vault secret '{secretName}' returned no content.");
        }

        if (!string.Equals(content.ContentType, Base64ContentType, StringComparison.Ordinal) || !Base64.IsValid(content.Content))
        {
            return new Internal($"OCI Vault secret '{secretName}' content is not base64 ({content.ContentType}).");
        }

        return new VaultSecretBundle(bundle.SecretId, Encoding.UTF8.GetString(Convert.FromBase64String(content.Content)), bundle.VersionNumber);
    }

    public async Task<OrchResult<long>> GetSecretVersionAsync(string vaultId, string secretName, CancellationToken cancellationToken)
    {
        var bundleResult = await GetBundleAsync(vaultId, secretName, cancellationToken);
        if (!bundleResult.TryGetValue(out var bundle, out var error))
        {
            return error;
        }

        return bundle.VersionNumber;
    }

    private async Task<OrchResult<SecretBundleDocument>> GetBundleAsync(string vaultId, string secretName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultId);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretName);

        var baseUrlResult = await SecretsBaseUrlAsync(vaultId, cancellationToken);
        if (!baseUrlResult.TryGetValue(out var baseUrl, out var baseUrlError))
        {
            return baseUrlError;
        }

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(
                baseUrl,
                $"20190301/secretbundles/actions/getByName?secretName={Uri.EscapeDataString(secretName)}&vaultId={Uri.EscapeDataString(vaultId)}"));
        var authorization = await principal.AuthorizeAsync(request, cancellationToken);
        if (authorization is OrchError authorizationError)
        {
            return authorizationError;
        }

        return await OciHttp.SendJsonAsync(httpClient, request, OciJsonContext.Default.SecretBundleDocument, cancellationToken);
    }

    private async Task<OrchResult<Uri>> SecretsBaseUrlAsync(string vaultId, CancellationToken cancellationToken) =>
        environment switch
        {
            OciMock mock => mock.BaseUrl,
            OciCloud => await CloudSecretsBaseUrlAsync(vaultId, cancellationToken),
        };

    private async Task<OrchResult<Uri>> CloudSecretsBaseUrlAsync(string vaultId, CancellationToken cancellationToken)
    {
        if (VaultRegion(vaultId) is not { } region)
        {
            return new Validation($"Vault id '{vaultId}' does not carry a region segment.");
        }

        var identityResult = await imds.GetIdentityAsync(cancellationToken);
        if (!identityResult.TryGetValue(out var identity, out var identityError))
        {
            return identityError;
        }

        return new Uri($"https://secrets.vaults.{region}.oci.{identity.RealmDomain}/");
    }

    private static string? VaultRegion(string vaultId)
    {
        var segments = vaultId.Split('.');
        return segments is ["ocid1", "vault", _, { Length: > 0 } region, ..] ? region : null;
    }
}
