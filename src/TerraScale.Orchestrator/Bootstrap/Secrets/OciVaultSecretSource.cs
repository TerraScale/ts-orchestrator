using Oci.Common;
using Oci.Common.Auth;
using Oci.SecretsService;
using Oci.SecretsService.Models;
using Oci.SecretsService.Requests;
using Oci.SecretsService.Responses;
using System.Security.Cryptography;
using TerraScale.Orchestrator.Nodes;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.Bootstrap.Secrets;

internal interface IOciVaultSecretSource : IDisposable
{
    Task<byte[]> ReadAsync(OciSecretFile file, CancellationToken cancellationToken);
}

/// <summary>Instance Principal only; the endpoint and version are never chosen by a remote response.</summary>
internal sealed class OciVaultSecretSource(
    Func<GetSecretBundleRequest, CancellationToken, Task<GetSecretBundleResponse>> getBundle,
    Action? dispose = null) : IOciVaultSecretSource
{
    internal static OciVaultSecretSource Create(string region)
    {
        if (!TerraScaleRegion.IsValid(region))
            throw new InvalidDataException("The OCI Vault region is unsupported.");
        var endpoint = $"https://secrets.vaults.{TerraScaleRegion.OciName(region)}.oci.oraclecloud.com";
        var client = OciSdkEndpoint.Pin(new SecretsClient(new InstancePrincipalsAuthenticationDetailsProvider(),
            new ClientConfiguration { TimeoutMillis = 30_000 }, endpoint));
        return new((request, token) => client.GetSecretBundle(request, cancellationToken: token), client.Dispose);
    }

    public async Task<byte[]> ReadAsync(OciSecretFile file, CancellationToken cancellationToken)
    {
        var response = await getBundle(new GetSecretBundleRequest
        {
            SecretId = file.SecretId,
            VersionNumber = file.Version
        }, cancellationToken).ConfigureAwait(false);
        var bundle = response.SecretBundle;
        if (bundle is null || bundle.SecretId != file.SecretId || bundle.VersionNumber != file.Version ||
            bundle.SecretBundleContent is not Base64SecretBundleContentDetails { Content: { } content } ||
            content.Length is < 1 or > 87384)
            throw new InvalidDataException("OCI Vault did not return the pinned secret version.");
        try
        {
            var bytes = Convert.FromBase64String(content);
            if (bytes.Length is < 1 or > OciSecretManifest.MaximumSecretBytes)
            {
                CryptographicOperations.ZeroMemory(bytes);
                throw new InvalidDataException("OCI Vault returned an out-of-bounds secret.");
            }
            return bytes;
        }
        catch (FormatException)
        {
            throw new InvalidDataException("OCI Vault returned invalid secret encoding.");
        }
    }

    public void Dispose() => dispose?.Invoke();
}
