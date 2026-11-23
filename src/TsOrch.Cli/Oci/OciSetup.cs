using TsOrch.Oci;

namespace TsOrch.Cli;

internal sealed record class OciClients(OciEnvironment Environment, OciImdsClient Imds, OciInstancePrincipal Principal, OciVaultClient Vault) : IDisposable
{
    public void Dispose() => Principal.Dispose();
}

internal static class OciSetup
{
    public static OciClients Create(HttpClient httpClient, OciEnvironment environment, TimeProvider timeProvider)
    {
        var imds = new OciImdsClient(httpClient, environment);
        var principal = new OciInstancePrincipal(httpClient, environment, imds, new OciRequestSigner(timeProvider), timeProvider);
        return new OciClients(environment, imds, principal, new OciVaultClient(httpClient, environment, imds, principal));
    }
}
